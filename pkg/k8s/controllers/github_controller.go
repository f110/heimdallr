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
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v41/github"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
)

const (
	githubControllerFinalizerName = "github-controller.heimdallr.f110.dev/finalizer"
)

type GitHubController struct {
	*controllerbase.Controller

	proxyLister         *client.ProxyV1alpha2ProxyLister
	proxyListerSynced   cache.InformerSynced
	backendInformer     cache.SharedIndexInformer
	backendLister       *client.ProxyV1alpha2BackendLister
	backendListerSynced cache.InformerSynced
	secretLister        listers.SecretLister
	secretListerSynced  cache.InformerSynced

	client     *client.ProxyV1alpha2
	coreClient kubernetes.Interface

	transport http.RoundTripper
}

func NewGitHubController(
	sharedInformerFactory *client.InformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	coreClient kubernetes.Interface,
	proxyClient *client.ProxyV1alpha2,
	transport http.RoundTripper,
) (*GitHubController, error) {
	proxyInformers := client.NewProxyV1alpha2Informer(sharedInformerFactory.Cache(), proxyClient, metav1.NamespaceAll, 30*time.Second)
	backendInformer := proxyInformers.BackendInformer()
	proxyInformer := proxyInformers.ProxyInformer()

	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()

	c := &GitHubController{
		client:              proxyClient,
		proxyLister:         proxyInformers.ProxyLister(),
		proxyListerSynced:   proxyInformer.HasSynced,
		backendInformer:     backendInformer,
		backendLister:       proxyInformers.BackendLister(),
		backendListerSynced: backendInformer.HasSynced,
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
			c.Log(nil).Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (c *GitHubController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	backend, err := c.backendLister.Get(namespace, name)
	if err != nil && apierrors.IsNotFound(err) {
		c.Log(nil).Debug("Backend is not found", zap.String("key", key))
		return nil, nil
	} else if err != nil {
		return nil, xerrors.WithStack(err)
	}

	var webhookConf *proxyv1alpha2.WebhookConfiguration
	for _, v := range backend.Spec.Permissions {
		if v.Webhook == "github" {
			webhookConf = v.WebhookConfiguration
			break
		}
	}
	if webhookConf == nil {
		c.Log(nil).Debug("Not set webhook or webhook is not github", zap.String("backend.name", backend.Name))
		return nil, nil
	}

	return backend, nil
}

func (c *GitHubController) UpdateObject(ctx context.Context, obj interface{}) error {
	backend, ok := obj.(*proxyv1alpha2.Backend)
	if !ok {
		return nil
	}

	_, err := c.client.UpdateBackend(ctx, backend, metav1.UpdateOptions{})
	return err
}

func (c *GitHubController) Reconcile(ctx context.Context, obj interface{}) error {
	backend := obj.(*proxyv1alpha2.Backend)
	c.Log(ctx).Debug("syncBackend", zap.String("namespace", backend.Namespace), zap.String("name", backend.Name))

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
			return err
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
				return err
			}
			if found {
				continue
			}

			if err := c.setWebHook(ctx, ghClient, updatedB, owner, repo); err != nil {
				return err
			}
		}

		if !reflect.DeepEqual(backend.Status, updatedB.Status) {
			err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				backend, err := c.backendLister.Get(updatedB.Namespace, updatedB.Name)
				if err != nil {
					return err
				}

				backend.Status = updatedB.Status
				_, err = c.client.UpdateStatusBackend(ctx, backend, metav1.UpdateOptions{})
				if err != nil {
					c.Log(ctx).Debug("Failed update backend", zap.Error(err))
					return err
				}
				return nil
			})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	return nil
}

func (c *GitHubController) Finalize(ctx context.Context, obj interface{}) error {
	backend := obj.(*proxyv1alpha2.Backend)

	if len(backend.Status.WebhookConfiguration) == 0 {
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			backend, err := c.backendLister.Get(backend.Namespace, backend.Name)
			if err != nil {
				return err
			}

			updatedB := backend.DeepCopy()
			controllerbase.RemoveFinalizer(&updatedB.ObjectMeta, githubControllerFinalizerName)
			if !reflect.DeepEqual(updatedB.Finalizers, backend.Finalizers) {
				_, err = c.client.UpdateBackend(ctx, updatedB, metav1.UpdateOptions{})
				return err
			}
			return nil
		})
		if err != nil {
			return xerrors.WithStack(err)
		}
		return nil
	}

	webhookConfigurationStatus := make(map[string]proxyv1alpha2.WebhookConfigurationStatus)
	for _, v := range backend.Status.WebhookConfiguration {
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
			return err
		}

		for _, v := range p.WebhookConfiguration.GitHub.Repositories {
			status, ok := webhookConfigurationStatus[v]
			if !ok {
				continue
			}
			s := strings.SplitN(v, "/", 2)
			owner, repo := s[0], s[1]

			c.Log(ctx).Debug("Delete hook", zap.String("repo", owner+"/"+repo), zap.Int64("id", status.Id))
			_, err := ghClient.Repositories.DeleteHook(ctx, owner, repo, status.Id)
			if err != nil {
				c.Log(ctx).Debug("Failed delete hook", zap.Error(err))
				ghErr := err.(*github.ErrorResponse)
				if ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound {
					delete(webhookConfigurationStatus, v)
				}
			} else {
				c.Log(ctx).Info("Delete webhook", zap.Int64("id", status.Id), zap.String("repo", v))
				delete(webhookConfigurationStatus, v)
			}
		}
	}

	webhookConfigurations := make([]proxyv1alpha2.WebhookConfigurationStatus, 0)
	for _, v := range webhookConfigurationStatus {
		webhookConfigurations = append(webhookConfigurations, v)
	}
	sort.Slice(webhookConfigurations, func(i, j int) bool {
		return webhookConfigurations[i].Id < webhookConfigurations[j].Id
	})

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		backend, err := c.backendLister.Get(backend.Namespace, backend.Name)
		if err != nil {
			return err
		}

		updatedB := backend.DeepCopy()
		updatedB.Status.WebhookConfiguration = webhookConfigurations
		if len(updatedB.Status.WebhookConfiguration) == 0 {
			controllerbase.RemoveFinalizer(&updatedB.ObjectMeta, githubControllerFinalizerName)
		}
		if !reflect.DeepEqual(updatedB.Status, backend.Status) {
			c.Log(ctx).Debug("Update Backend Status", zap.String("name", updatedB.Name))
			_, err = c.client.UpdateStatusBackend(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		if !reflect.DeepEqual(updatedB.Finalizers, backend.Finalizers) {
			c.Log(ctx).Debug("Update Backend", zap.String("name", updatedB.Name))
			_, err = c.client.UpdateBackend(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *GitHubController) checkConfigured(ctx context.Context, client *github.Client, backend *proxyv1alpha2.Backend, owner, repo string) (bool, error) {
	hooks, _, err := client.Repositories.ListHooks(ctx, owner, repo, &github.ListOptions{})
	if err != nil {
		return false, xerrors.WithStack(err)
	}

	for _, h := range hooks {
		u, err := url.Parse(h.GetURL())
		if err != nil {
			c.Log(ctx).Debug("Failed parse url", zap.Error(err), zap.String("url", h.GetURL()))
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
			c.Log(ctx).Debug("Failed parse url", zap.Error(err), zap.String("url", v.Url))
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
			proxy, err := c.proxyLister.Get(v.Namespace, v.Name)
			if err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}

				c.Log(ctx).Info("Fetch error", zap.Error(err), zap.String("namespace", v.Namespace), zap.String("name", v.Name))
				continue
			}
			if proxy.Status.GithubWebhookSecretName == "" {
				c.Log(ctx).Debug("Is not ready", zap.String("name", proxy.Name))
				continue
			}
			secret, err := c.secretLister.Secrets(proxy.Namespace).Get(proxy.Status.GithubWebhookSecretName)
			if err != nil {
				if apierrors.IsNotFound(err) {
					c.Log(ctx).Error("Is not found", zap.String("namespace", proxy.Namespace), zap.String("name", proxy.Status.GithubWebhookSecretName))
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
			c.Log(ctx).Debug("Create new hook", zap.String("repo", owner+"/"+repo))
			newHook, _, err = client.Repositories.CreateHook(ctx, owner, repo, newHook)
			if err != nil {
				c.Log(ctx).Info("Failed create hook", zap.Error(err))
				continue
			}

			now := metav1.Now()
			backend.Status.WebhookConfiguration = append(backend.Status.WebhookConfiguration,
				proxyv1alpha2.WebhookConfigurationStatus{
					Id:         newHook.GetID(),
					Repository: fmt.Sprintf("%s/%s", owner, repo),
					UpdateTime: &now,
				},
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
			return nil, xerrors.WithStack(err)
		}

		return nil, xerrors.WithStack(err)
	}
	appId, err := strconv.ParseInt(string(secret.Data[conf.GitHub.AppIdKey]), 10, 64)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	installationId, err := strconv.ParseInt(string(secret.Data[conf.GitHub.InstallationIdKey]), 10, 64)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	rt, err := ghinstallation.New(c.transport, appId, installationId, secret.Data[conf.GitHub.PrivateKeyKey])
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return github.NewClient(&http.Client{Transport: rt}), nil
}
