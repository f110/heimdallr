package controllers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-github/github"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1alpha1"
)

const (
	githubControllerFinalizerName = "github-controller.heimdallr.f110.dev/finalizer"
)

type GitHubController struct {
	schema.GroupVersionKind

	proxyLister         proxyListers.ProxyLister
	proxyListerSynced   cache.InformerSynced
	backendLister       proxyListers.BackendLister
	backendListerSynced cache.InformerSynced
	secretLister        listers.SecretLister
	secretListerSynced  cache.InformerSynced

	client     clientset.Interface
	coreClient kubernetes.Interface

	queue    workqueue.RateLimitingInterface
	recorder record.EventRecorder

	transport http.RoundTripper
}

func NewGitHubController(
	sharedInformerFactory informers.SharedInformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	coreClient kubernetes.Interface,
	client clientset.Interface,
	transport http.RoundTripper,
) (*GitHubController, error) {
	backendInformer := sharedInformerFactory.Proxy().V1alpha1().Backends()
	proxyInformer := sharedInformerFactory.Proxy().V1alpha1().Proxies()

	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: coreClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "github-controller"})

	c := &GitHubController{
		client:              client,
		proxyLister:         proxyInformer.Lister(),
		proxyListerSynced:   proxyInformer.Informer().HasSynced,
		backendLister:       backendInformer.Lister(),
		backendListerSynced: backendInformer.Informer().HasSynced,
		secretLister:        secretInformer.Lister(),
		secretListerSynced:  secretInformer.Informer().HasSynced,
		queue:               workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "backend"),
		recorder:            recorder,
		transport:           transport,
	}

	backendInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addBackend,
		UpdateFunc: c.updateBackend,
		DeleteFunc: c.deleteBackend,
	})

	return c, nil
}

func (c *GitHubController) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()

	if !cache.WaitForNamedCacheSync(
		c.Kind, ctx.Done(),
		c.proxyListerSynced,
		c.backendListerSynced,
		c.secretListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, ctx.Done())
	}

	<-ctx.Done()
}

func (c *GitHubController) syncBackend(key string) error {
	klog.V(4).Info("syncBackend")
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	backend, err := c.backendLister.Backends(namespace).Get(name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if backend.Spec.Webhook != "github" {
		klog.V(4).Infof("%s is not set Webhook or Webhook is not github", backend.Name)
		return nil
	}
	if backend.Spec.WebhookConfiguration == nil {
		klog.V(4).Infof("not set WebhookConfiguration")
		return nil
	}

	if backend.DeletionTimestamp.IsZero() {
		if !containsString(backend.Finalizers, githubControllerFinalizerName) {
			backend.ObjectMeta.Finalizers = append(backend.ObjectMeta.Finalizers, githubControllerFinalizerName)
			_, err = c.client.ProxyV1alpha1().Backends(backend.Namespace).Update(context.TODO(), backend, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
	}

	// Object has been deleted
	if !backend.DeletionTimestamp.IsZero() {
		return c.finalizeBackend(backend)
	}

	ghClient, err := c.newGithubClient(backend)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	updatedB := backend.DeepCopy()
	for _, ownerAndRepo := range backend.Spec.WebhookConfiguration.Repositories {
		if backend.Status.IsConfigured(ownerAndRepo) {
			continue
		}

		s := strings.Split(ownerAndRepo, "/")
		if len(s) != 2 {
			continue
		}
		owner, repo := s[0], s[1]

		found, err := c.checkConfigured(ghClient, updatedB, owner, repo)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if found {
			continue
		}

		if err := c.setWebHook(ghClient, updatedB, owner, repo); err != nil {
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
			_, err = c.client.ProxyV1alpha1().Backends(backend.Namespace).UpdateStatus(context.TODO(), backend, metav1.UpdateOptions{})
			if err != nil {
				klog.Infof("Failed update backend: %v", err)
				return err
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *GitHubController) finalizeBackend(backend *proxyv1alpha1.Backend) error {
	if len(backend.Status.WebhookConfigurations) == 0 {
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			backend, err := c.backendLister.Backends(backend.Namespace).Get(backend.Name)
			if err != nil {
				return err
			}

			updatedB := backend.DeepCopy()
			updatedB.Finalizers = removeString(updatedB.Finalizers, githubControllerFinalizerName)
			if !reflect.DeepEqual(updatedB.Finalizers, backend.Finalizers) {
				_, err = c.client.ProxyV1alpha1().Backends(updatedB.Namespace).Update(context.TODO(), updatedB, metav1.UpdateOptions{})
				return err
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		return nil
	}

	ghClient, err := c.newGithubClient(backend)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	webhookConfigurations := make([]*proxyv1alpha1.WebhookConfigurationStatus, 0)
	for _, v := range backend.Status.WebhookConfigurations {
		if v.Id == 0 {
			continue
		}
		s := strings.SplitN(v.Repository, "/", 2)
		owner, repo := s[0], s[1]

		klog.V(4).Infof("Delete hook: %s/%s/%d", owner, repo, v.Id)
		_, err := ghClient.Repositories.DeleteHook(context.Background(), owner, repo, v.Id)
		if err != nil {
			log.Print(err)
			klog.V(4).Infof("Failed delete hook: %v", err)
			webhookConfigurations = append(webhookConfigurations, v)
		}
	}

	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		backend, err = c.backendLister.Backends(backend.Namespace).Get(backend.Name)
		if err != nil {
			return err
		}

		updatedB := backend.DeepCopy()
		updatedB.Status.WebhookConfigurations = webhookConfigurations
		if len(updatedB.Status.WebhookConfigurations) == 0 {
			updatedB.Finalizers = removeString(updatedB.Finalizers, githubControllerFinalizerName)
		}
		if !reflect.DeepEqual(updatedB.Status, backend.Status) || !reflect.DeepEqual(updatedB.Finalizers, backend.Finalizers) {
			_, err = c.client.ProxyV1alpha1().Backends(updatedB.Namespace).Update(context.TODO(), updatedB, metav1.UpdateOptions{})
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (c *GitHubController) checkConfigured(client *github.Client, backend *proxyv1alpha1.Backend, owner, repo string) (bool, error) {
	hooks, _, err := client.Repositories.ListHooks(context.Background(), owner, repo, &github.ListOptions{})
	if err != nil {
		return false, xerrors.Errorf(": %w", err)
	}

	for _, h := range hooks {
		u, err := url.Parse(h.GetURL())
		if err != nil {
			klog.Infof("Failed parse url: %s", h.GetURL())
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

func (c *GitHubController) setWebHook(client *github.Client, backend *proxyv1alpha1.Backend, owner, repo string) error {
	for _, v := range backend.Status.DeployedBy {
		u, err := url.Parse(v.Url)
		if err != nil {
			klog.Infof("Failure parse url: %s", v.Url)
			continue
		}
		u.Path = backend.Spec.WebhookConfiguration.Path
		proxy, err := c.proxyLister.Proxies(v.Namespace).Get(v.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}

			klog.Infof("fetch %s/%s error: %v", v.Namespace, v.Name, err)
			continue
		}
		if proxy.Status.GithubWebhookSecretName == "" {
			klog.V(4).Infof("%s is not ready", proxy.Name)
			continue
		}
		secret, err := c.secretLister.Secrets(proxy.Namespace).Get(proxy.Status.GithubWebhookSecretName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Errorf("%s/%s is not found. This is a suspicious error.", proxy.Namespace, proxy.Status.GithubWebhookSecretName)
			}

			klog.Infof("fetch %s/%s error: %v", proxy.Namespace, proxy.Name, proxy.Status.GithubWebhookSecretName)
			continue
		}

		newHook := &github.Hook{
			Events: backend.Spec.WebhookConfiguration.Events,
			Config: map[string]interface{}{
				"url":          u.String(),
				"content_type": backend.Spec.WebhookConfiguration.ContentType,
				"secret":       string(secret.Data[githubWebhookSecretFilename]),
			},
		}
		klog.V(4).Infof("Create new hook: %s/%s", owner, repo)
		newHook, _, err = client.Repositories.CreateHook(context.Background(), owner, repo, newHook)
		if err != nil {
			klog.Infof("Failed create hook: %v", err)
			continue
		}

		backend.Status.WebhookConfigurations = append(backend.Status.WebhookConfigurations,
			&proxyv1alpha1.WebhookConfigurationStatus{Id: newHook.GetID(), Repository: fmt.Sprintf("%s/%s", owner, repo), UpdateTime: metav1.Now()},
		)
	}

	return nil
}

func (c *GitHubController) newGithubClient(backend *proxyv1alpha1.Backend) (*github.Client, error) {
	secretNamespace := backend.Spec.WebhookConfiguration.CredentialSecretNamespace
	if secretNamespace == "" {
		secretNamespace = backend.Namespace
	}
	secret, err := c.secretLister.Secrets(secretNamespace).Get(backend.Spec.WebhookConfiguration.CredentialSecretName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, xerrors.Errorf(": %w", err)
		}

		return nil, xerrors.Errorf(": %w", err)
	}
	appId, err := strconv.ParseInt(string(secret.Data[backend.Spec.WebhookConfiguration.AppIdKey]), 10, 64)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	installationId, err := strconv.ParseInt(string(secret.Data[backend.Spec.WebhookConfiguration.InstallationIdKey]), 10, 64)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	rt, err := ghinstallation.New(c.transport, appId, installationId, secret.Data[backend.Spec.WebhookConfiguration.PrivateKeyKey])
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return github.NewClient(&http.Client{Transport: rt}), nil
}

func (c *GitHubController) worker() {
	klog.V(4).Info("Start worker")
	for c.processNextItem() {
	}
}

func (c *GitHubController) processNextItem() bool {
	defer klog.V(4).Info("Finish processNextItem")

	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	klog.V(4).Infof("Get next queue: %s", obj)

	err := func(obj interface{}) error {
		defer c.queue.Done(obj)

		err := c.syncBackend(obj.(string))
		if err != nil {
			if errors.Is(err, &RetryError{}) {
				klog.V(4).Infof("Retrying %v", err)
				c.queue.AddRateLimited(obj)
				return nil
			}

			return err
		}

		c.queue.Forget(obj)
		return nil
	}(obj)
	if err != nil {
		klog.Infof("%+v", err)
		return true
	}

	return true
}

func (c *GitHubController) addBackend(obj interface{}) {
	backend := obj.(*proxyv1alpha1.Backend)

	c.enqueue(backend)
}

func (c *GitHubController) updateBackend(old, cur interface{}) {
	oldBackend := old.(*proxyv1alpha1.Backend)
	curBackend := cur.(*proxyv1alpha1.Backend)

	if oldBackend.UID != curBackend.UID {
		if key, err := cache.MetaNamespaceKeyFunc(oldBackend); err != nil {
			return
		} else {
			c.deleteBackend(cache.DeletedFinalStateUnknown{Key: key, Obj: oldBackend})
		}
	}

	c.enqueue(curBackend)
}

func (c *GitHubController) deleteBackend(obj interface{}) {
	backend, ok := obj.(*proxyv1alpha1.Backend)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		backend, ok = tombstone.Obj.(*proxyv1alpha1.Backend)
		if !ok {
			return
		}
	}

	c.enqueue(backend)
}

func (c *GitHubController) enqueue(backend *proxyv1alpha1.Backend) {
	if key, err := cache.MetaNamespaceKeyFunc(backend); err != nil {
		klog.Info(err)
		return
	} else {
		klog.V(4).Infof("Enqueue: %s", key)
		c.queue.Add(key)
	}
}

func containsString(v []string, s string) bool {
	for _, item := range v {
		if item == s {
			return true
		}
	}

	return false
}

func removeString(v []string, s string) []string {
	result := make([]string, 0, len(v))
	for _, item := range v {
		if item == s {
			continue
		}

		result = append(result, item)
	}

	return result
}
