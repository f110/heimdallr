package controllers

import (
	"context"
	"errors"
	"fmt"
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
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	proxyv1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1"
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
	backendInformer := sharedInformerFactory.Proxy().V1().Backends()
	proxyInformer := sharedInformerFactory.Proxy().V1().Proxies()

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
	secretNamespace := backend.Spec.WebhookConfiguration.CredentialSecretNamespace
	if secretNamespace == "" {
		secretNamespace = backend.Namespace
	}
	secret, err := c.secretLister.Secrets(secretNamespace).Get(backend.Spec.WebhookConfiguration.CredentialSecretName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("%s is not found", backend.Spec.WebhookConfiguration.CredentialSecretName)
			return nil
		}

		return xerrors.Errorf(": %w", err)
	}
	appId, err := strconv.ParseInt(string(secret.Data[backend.Spec.WebhookConfiguration.AppIdKey]), 10, 64)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	installationId, err := strconv.ParseInt(string(secret.Data[backend.Spec.WebhookConfiguration.InstallationIdKey]), 10, 64)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	rt, err := ghinstallation.New(c.transport, appId, installationId, secret.Data[backend.Spec.WebhookConfiguration.PrivateKeyKey])
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	ghClient := github.NewClient(&http.Client{Transport: rt})
	originalBackend := backend.DeepCopy()

Spec:
	for _, ownerAndRepo := range backend.Spec.WebhookConfiguration.Repositories {
		for _, v := range backend.Status.WebhookConfigurations {
			if v.Repository == ownerAndRepo {
				continue Spec
			}
		}

		s := strings.Split(ownerAndRepo, "/")
		if len(s) != 2 {
			continue
		}
		owner, repo := s[0], s[1]
		hooks, _, err := ghClient.Repositories.ListHooks(context.Background(), owner, repo, &github.ListOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		found := false
		for _, h := range hooks {
			u, err := url.Parse(h.GetURL())
			if err != nil {
				klog.Infof("Failed parse url: %s", h.GetURL())
				continue
			}
			if backend.Spec.FQDN != "" && u.Host == backend.Spec.FQDN {
				found = true
				break
			} else if strings.HasPrefix(u.Host, fmt.Sprintf("%s.%s", backend.Name, backend.Spec.Layer)) {
				found = true
				break
			}
		}

		if !found {
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
				_, _, err = ghClient.Repositories.CreateHook(context.Background(), owner, repo, newHook)
				if err != nil {
					klog.Infof("Failed create hook: %v", err)
					continue
				}

				backend.Status.WebhookConfigurations = append(backend.Status.WebhookConfigurations,
					&proxyv1.WebhookConfigurationStatus{Repository: ownerAndRepo, UpdateTime: metav1.Now()},
				)
			}
		}
	}

	if !reflect.DeepEqual(backend.Status, originalBackend.Status) {
		_, err = c.client.ProxyV1().Backends(backend.Namespace).UpdateStatus(backend)
		if err != nil {
			klog.Infof("Failed update backend: %v", err)
		}
	}

	return nil
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
	backend := obj.(*proxyv1.Backend)

	c.enqueue(backend)
}

func (c *GitHubController) updateBackend(old, cur interface{}) {
	oldBackend := old.(*proxyv1.Backend)
	curBackend := cur.(*proxyv1.Backend)

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
	backend, ok := obj.(*proxyv1.Backend)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		backend, ok = tombstone.Obj.(*proxyv1.Backend)
		if !ok {
			return
		}
	}

	c.enqueue(backend)
}

func (c *GitHubController) enqueue(backend *proxyv1.Backend) {
	if key, err := cache.MetaNamespaceKeyFunc(backend); err != nil {
		klog.Info(err)
		return
	} else {
		klog.V(4).Infof("Enqueue: %s", key)
		c.queue.Add(key)
	}
}
