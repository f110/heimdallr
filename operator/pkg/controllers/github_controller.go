package controllers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-github/github"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/controllers/controllerbase"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1alpha2"
)

const (
	githubControllerFinalizerName = "github-controller.heimdallr.f110.dev/finalizer"
)

type GitHubController struct {
	*controllerbase.Controller

	proxyLister         proxyListers.ProxyLister
	proxyListerSynced   cache.InformerSynced
	backendInformer     cache.SharedIndexInformer
	backendLister       proxyListers.BackendLister
	backendListerSynced cache.InformerSynced
	secretLister        listers.SecretLister
	secretListerSynced  cache.InformerSynced

	client     clientset.Interface
	coreClient kubernetes.Interface

	transport http.RoundTripper
}

func NewGitHubController(
	sharedInformerFactory informers.SharedInformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	coreClient kubernetes.Interface,
	client clientset.Interface,
	transport http.RoundTripper,
) (*GitHubController, error) {
	backendInformer := sharedInformerFactory.Proxy().V1alpha2().Backends()
	proxyInformer := sharedInformerFactory.Proxy().V1alpha2().Proxies()

	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()

	c := &GitHubController{
		client:              client,
		proxyLister:         proxyInformer.Lister(),
		proxyListerSynced:   proxyInformer.Informer().HasSynced,
		backendInformer:     backendInformer.Informer(),
		backendLister:       backendInformer.Lister(),
		backendListerSynced: backendInformer.Informer().HasSynced,
		secretLister:        secretInformer.Lister(),
		secretListerSynced:  secretInformer.Informer().HasSynced,
		transport:           transport,
	}

	c.Controller = controllerbase.NewController(c, coreClient)
	return c, nil
}

func (c *GitHubController) Name() string {
	return "github-controller"
}

func (c *GitHubController) Finalizers() []string {
	return []string{githubControllerFinalizerName}
}

func (c *GitHubController) ListerSynced() []cache.InformerSynced {
	return []cache.InformerSynced{
		c.proxyListerSynced,
		c.backendListerSynced,
		c.secretListerSynced,
	}
}

func (c *GitHubController) EventSources() []cache.SharedIndexInformer {
	return []cache.SharedIndexInformer{
		c.backendInformer,
	}
}

func (c *GitHubController) ConvertToKeys() controllerbase.ObjectToKeyConverter {
	return func(obj interface{}) (keys []string, err error) {
		switch obj.(type) {
		case *proxyv1alpha2.Backend:
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				return nil, err
			}
			return []string{key}, nil
		default:
			c.Log().Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (c *GitHubController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	backend, err := c.backendLister.Backends(namespace).Get(name)
	if err != nil && apierrors.IsNotFound(err) {
		c.Log().Debug("Backend is not found", zap.String("key", key))
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	var webhookConf *proxyv1alpha2.WebhookConfiguration
	for _, v := range backend.Spec.Permissions {
		if v.Webhook == "github" {
			webhookConf = v.WebhookConfiguration
			break
		}
	}
	if webhookConf == nil {
		c.Log().Debug("Not set webhook or webhook is not github", zap.String("backend.name", backend.Name))
		return nil, nil
	}

	return backend, nil
}

func (c *GitHubController) UpdateObject(ctx context.Context, obj interface{}) error {
	backend, ok := obj.(*proxyv1alpha2.Backend)
	if !ok {
		return nil
	}

	_, err := c.client.ProxyV1alpha2().Backends(backend.Namespace).Update(ctx, backend, metav1.UpdateOptions{})
	return err
}

func (c *GitHubController) Reconcile(ctx context.Context, obj interface{}) error {
	c.Log().Debug("syncBackend")
	backend := obj.(*proxyv1alpha2.Backend)

	for _, s := range backend.Spec.Permissions {
		if s.Webhook != "github" {
			continue
		}
		if s.WebhookConfiguration == nil {
			continue
		}
		if s.WebhookConfiguration.GitHub == nil {
			continue
		}

		ghClient, err := c.newGithubClient(s.WebhookConfiguration, backend.Namespace)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		updatedB := backend.DeepCopy()
		for _, ownerAndRepo := range s.WebhookConfiguration.GitHub.Repositories {
			if backend.Status.IsConfigured(ownerAndRepo) {
				continue
			}

			s := strings.Split(ownerAndRepo, "/")
			if len(s) != 2 {
				continue
			}
			owner, repo := s[0], s[1]

			found, err := c.checkConfigured(ctx, ghClient, updatedB, owner, repo)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if found {
				continue
			}

			if err := c.setWebHook(ctx, ghClient, updatedB, owner, repo); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}

		if !reflect.DeepEqual(backend.Status, updatedB.Status) {
			err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				backend, err := c.backendLister.Backends(updatedB.Namespace).Get(updatedB.Name)
				if err != nil {
					return err
				}

				backend.Status = updatedB.Status
				_, err = c.client.ProxyV1alpha2().Backends(backend.Namespace).UpdateStatus(ctx, backend, metav1.UpdateOptions{})
				if err != nil {
					c.Log().Debug("Failed update backend", zap.Error(err))
					return err
				}
				return nil
			})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *GitHubController) Finalize(ctx context.Context, obj interface{}) error {
	backend := obj.(*proxyv1alpha2.Backend)

	if len(backend.Status.WebhookConfigurations) == 0 {
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			backend, err := c.backendLister.Backends(backend.Namespace).Get(backend.Name)
			if err != nil {
				return err
			}

			updatedB := backend.DeepCopy()
			controllerbase.RemoveFinalizer(&updatedB.ObjectMeta, githubControllerFinalizerName)
			if !reflect.DeepEqual(updatedB.Finalizers, backend.Finalizers) {
				_, err = c.client.ProxyV1alpha2().Backends(updatedB.Namespace).Update(ctx, updatedB, metav1.UpdateOptions{})
				return err
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		return nil
	}

	webhookConfigurationStatus := make(map[string]*proxyv1alpha2.WebhookConfigurationStatus)
	for _, v := range backend.Status.WebhookConfigurations {
		webhookConfigurationStatus[v.Repository] = v
	}

	for _, p := range backend.Spec.Permissions {
		if p.Webhook != "github" {
			continue
		}
		if p.WebhookConfiguration == nil || p.WebhookConfiguration.GitHub == nil {
			continue
		}

		ghClient, err := c.newGithubClient(p.WebhookConfiguration, backend.Namespace)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		for _, v := range p.WebhookConfiguration.GitHub.Repositories {
			status, ok := webhookConfigurationStatus[v]
			if !ok {
				continue
			}
			s := strings.SplitN(v, "/", 2)
			owner, repo := s[0], s[1]

			c.Log().Debug("Delete hook", zap.String("repo", owner+"/"+repo), zap.Int64("id", status.Id))
			_, err := ghClient.Repositories.DeleteHook(ctx, owner, repo, status.Id)
			if err != nil {
				c.Log().Debug("Failed delete hook", zap.Error(err))
			} else {
				c.Log().Info("Delete webhook", zap.Int64("id", status.Id), zap.String("repo", v))
				delete(webhookConfigurationStatus, v)
			}
		}
	}

	webhookConfigurations := make([]*proxyv1alpha2.WebhookConfigurationStatus, 0)
	for _, v := range webhookConfigurationStatus {
		webhookConfigurations = append(webhookConfigurations, v)
	}
	sort.Slice(webhookConfigurations, func(i, j int) bool {
		return webhookConfigurations[i].Id < webhookConfigurations[j].Id
	})

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		backend, err := c.backendLister.Backends(backend.Namespace).Get(backend.Name)
		if err != nil {
			return err
		}

		updatedB := backend.DeepCopy()
		updatedB.Status.WebhookConfigurations = webhookConfigurations
		if len(updatedB.Status.WebhookConfigurations) == 0 {
			controllerbase.RemoveFinalizer(&updatedB.ObjectMeta, githubControllerFinalizerName)
		}
		if !reflect.DeepEqual(updatedB.Status, backend.Status) {
			c.Log().Debug("Update Backend Status", zap.String("name", updatedB.Name))
			_, err = c.client.ProxyV1alpha2().Backends(updatedB.Namespace).UpdateStatus(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		if !reflect.DeepEqual(updatedB.Finalizers, backend.Finalizers) {
			c.Log().Debug("Update Backend", zap.String("name", updatedB.Name))
			_, err = c.client.ProxyV1alpha2().Backends(updatedB.Namespace).Update(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *GitHubController) checkConfigured(ctx context.Context, client *github.Client, backend *proxyv1alpha2.Backend, owner, repo string) (bool, error) {
	hooks, _, err := client.Repositories.ListHooks(ctx, owner, repo, &github.ListOptions{})
	if err != nil {
		return false, xerrors.Errorf(": %w", err)
	}

	for _, h := range hooks {
		u, err := url.Parse(h.GetURL())
		if err != nil {
			c.Log().Debug("Failed parse url", zap.Error(err), zap.String("url", h.GetURL()))
			continue
		}
		if backend.Spec.FQDN != "" && u.Host == backend.Spec.FQDN {
			return true, nil
		} else if strings.HasPrefix(u.Host, fmt.Sprintf("%s.%s", backend.Name, backend.Spec.Layer)) {
			return true, nil
		}
	}

	return false, nil
}

func (c *GitHubController) setWebHook(ctx context.Context, client *github.Client, backend *proxyv1alpha2.Backend, owner, repo string) error {
	for _, v := range backend.Status.DeployedBy {
		u, err := url.Parse(v.Url)
		if err != nil {
			c.Log().Debug("Failed parse url", zap.Error(err), zap.String("url", v.Url))
			continue
		}

		for _, p := range backend.Spec.Permissions {
			if p.Webhook != "github" {
				continue
			}
			if p.WebhookConfiguration == nil || p.WebhookConfiguration.GitHub == nil {
				continue
			}

			u.Path = p.WebhookConfiguration.GitHub.Path
			proxy, err := c.proxyLister.Proxies(v.Namespace).Get(v.Name)
			if err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}

				c.Log().Info("Fetch error", zap.Error(err), zap.String("namespace", v.Namespace), zap.String("name", v.Name))
				continue
			}
			if proxy.Status.GithubWebhookSecretName == "" {
				c.Log().Debug("Is not ready", zap.String("name", proxy.Name))
				continue
			}
			secret, err := c.secretLister.Secrets(proxy.Namespace).Get(proxy.Status.GithubWebhookSecretName)
			if err != nil {
				if apierrors.IsNotFound(err) {
					c.Log().Error("Is not found", zap.String("namespace", proxy.Namespace), zap.String("name", proxy.Status.GithubWebhookSecretName))
				}

				continue
			}

			newHook := &github.Hook{
				Events: p.WebhookConfiguration.GitHub.Events,
				Config: map[string]interface{}{
					"url":          u.String(),
					"content_type": p.WebhookConfiguration.GitHub.ContentType,
					"secret":       string(secret.Data[githubWebhookSecretFilename]),
				},
			}
			c.Log().Debug("Create new hook", zap.String("repo", owner+"/"+repo))
			newHook, _, err = client.Repositories.CreateHook(ctx, owner, repo, newHook)
			if err != nil {
				c.Log().Info("Failed create hook", zap.Error(err))
				continue
			}

			backend.Status.WebhookConfigurations = append(backend.Status.WebhookConfigurations,
				&proxyv1alpha2.WebhookConfigurationStatus{Id: newHook.GetID(), Repository: fmt.Sprintf("%s/%s", owner, repo), UpdateTime: metav1.Now()},
			)
		}
	}

	return nil
}

func (c *GitHubController) newGithubClient(conf *proxyv1alpha2.WebhookConfiguration, namespace string) (*github.Client, error) {
	secretNamespace := conf.GitHub.CredentialSecretNamespace
	if secretNamespace == "" {
		secretNamespace = namespace
	}
	secret, err := c.secretLister.Secrets(secretNamespace).Get(conf.GitHub.CredentialSecretName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, xerrors.Errorf(": %w", err)
		}

		return nil, xerrors.Errorf(": %w", err)
	}
	appId, err := strconv.ParseInt(string(secret.Data[conf.GitHub.AppIdKey]), 10, 64)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	installationId, err := strconv.ParseInt(string(secret.Data[conf.GitHub.InstallationIdKey]), 10, 64)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	rt, err := ghinstallation.New(c.transport, appId, installationId, secret.Data[conf.GitHub.PrivateKeyKey])
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return github.NewClient(&http.Client{Transport: rt}), nil
}
