package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreInformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	coreListers "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"

	"go.f110.dev/heimdallr/operator/pkg/api/proxy"
	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1alpha1"
	"go.f110.dev/heimdallr/pkg/logger"
)

const (
	ingressClassControllerName     = "heimdallr.f110.dev/ingress-controller"
	ingressControllerFinalizerName = "ingress-controller.heimdallr.f110.dev/finalizer"
)

type IngressController struct {
	ingressLister            networkinglisters.IngressLister
	ingressListerSynced      cache.InformerSynced
	ingressClassLister       networkinglisters.IngressClassLister
	ingressClassListerSynced cache.InformerSynced
	serviceLister            coreListers.ServiceLister
	serviceListerSynced      cache.InformerSynced

	backendLister       proxyListers.BackendLister
	backendListerSynced cache.InformerSynced

	client     clientset.Interface
	coreClient kubernetes.Interface

	queue    workqueue.RateLimitingInterface
	recorder record.EventRecorder
	log      *zap.Logger
}

func NewIngressController(
	coreSharedInformerFactory coreInformers.SharedInformerFactory,
	sharedInformerFactory informers.SharedInformerFactory,
	coreClient kubernetes.Interface,
	client clientset.Interface,
) *IngressController {
	ingressInformer := coreSharedInformerFactory.Networking().V1().Ingresses()
	ingressClassInformer := coreSharedInformerFactory.Networking().V1().IngressClasses()
	serviceInformer := coreSharedInformerFactory.Core().V1().Services()
	backendInformer := sharedInformerFactory.Proxy().V1alpha1().Backends()

	log := logger.Log.Named("ingress-controller")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(func(format string, args ...interface{}) {
		log.Info(fmt.Sprintf(format, args...))
	})
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: coreClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "github-controller"})

	ic := &IngressController{
		ingressLister:            ingressInformer.Lister(),
		ingressListerSynced:      ingressInformer.Informer().HasSynced,
		ingressClassLister:       ingressClassInformer.Lister(),
		ingressClassListerSynced: ingressInformer.Informer().HasSynced,
		serviceLister:            serviceInformer.Lister(),
		serviceListerSynced:      serviceInformer.Informer().HasSynced,
		backendLister:            backendInformer.Lister(),
		backendListerSynced:      backendInformer.Informer().HasSynced,
		coreClient:               coreClient,
		client:                   client,
		queue:                    workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ingress"),
		log:                      log,
		recorder:                 recorder,
	}

	ingressInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ic.addIngress,
		UpdateFunc: ic.updateIngress,
		DeleteFunc: ic.deleteIngress,
	})
	return ic
}

func (ic *IngressController) Run(ctx context.Context, workers int) {
	defer ic.queue.ShutDown()

	if !cache.WaitForCacheSync(ctx.Done(),
		ic.ingressListerSynced,
		ic.ingressClassListerSynced,
		ic.backendListerSynced,
		ic.serviceListerSynced,
	) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(ic.worker, time.Second, ctx.Done())
	}

	<-ctx.Done()
}

func (ic *IngressController) syncIngress(ctx context.Context, key string) error {
	ic.log.Debug("syncIngress")
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	ingress, err := ic.ingressLister.Ingresses(namespace).Get(name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if ingress.Spec.IngressClassName == nil {
		return nil
	}

	ingClass, err := ic.ingressClassLister.Get(*ingress.Spec.IngressClassName)
	if err != nil {
		ic.log.Debug("Failure or not found IngressClass", zap.Error(err), zap.String("name", *ingress.Spec.IngressClassName))
		return nil
	}
	if ingClass.Spec.Controller != ingressClassControllerName {
		ic.log.Debug("Skip Ingress", zap.String("name", ingress.Name))
		return nil
	}

	if ingress.DeletionTimestamp.IsZero() {
		if !containsString(ingress.Finalizers, ingressControllerFinalizerName) {
			ingress.ObjectMeta.Finalizers = append(ingress.ObjectMeta.Finalizers, ingressControllerFinalizerName)
			_, err = ic.coreClient.NetworkingV1().Ingresses(ingress.Namespace).Update(ctx, ingress, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	if !ingress.DeletionTimestamp.IsZero() {
		return ic.finalizeIngress(ctx, ingress)
	}

	backends := make([]*proxyv1alpha1.Backend, 0)
	for _, rule := range ingress.Spec.Rules {
		if len(rule.HTTP.Paths) != 1 {
			ic.log.Info("Not support multiple paths", zap.String("ingress.name", ingress.Name))
			continue
		}

		p := rule.HTTP.Paths[0]
		backends = append(backends,
			&proxyv1alpha1.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ingress.Name,
					Namespace: ingress.Namespace,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(ingress, networkingv1.SchemeGroupVersion.WithKind("Ingress")),
					},
					Annotations: map[string]string{
						proxy.AnnotationKeyIngressName: key,
					},
					Labels: ingClass.Labels,
				},
				Spec: proxyv1alpha1.BackendSpec{
					FQDN:         rule.Host,
					DisableAuthn: true,
					ServiceSelector: proxyv1alpha1.ServiceSelector{
						Name:      p.Backend.Service.Name,
						Namespace: ingress.Namespace,
						Port:      p.Backend.Service.Port.Name,
					},
				},
			},
		)
	}

	for _, b := range backends {
		backend, err := ic.backendLister.Backends(b.Namespace).Get(b.Name)
		if err != nil && apierrors.IsNotFound(err) {
			_, err = ic.client.ProxyV1alpha1().Backends(b.Namespace).Create(ctx, b, metav1.CreateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			continue
		} else if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		updatedB := backend.DeepCopy()
		updatedB.Spec = b.Spec
		if !reflect.DeepEqual(updatedB, backend) {
			_, err = ic.client.ProxyV1alpha1().Backends(backend.Namespace).Update(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (ic *IngressController) finalizeIngress(ctx context.Context, ingress *networkingv1.Ingress) error {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		ig, err := ic.ingressLister.Ingresses(ingress.Namespace).Get(ingress.Name)
		if err != nil {
			return err
		}

		updatedI := ig.DeepCopy()
		updatedI.Finalizers = removeString(updatedI.Finalizers, ingressControllerFinalizerName)
		if !reflect.DeepEqual(updatedI.Finalizers, ig.Finalizers) {
			_, err = ic.coreClient.NetworkingV1().Ingresses(updatedI.Namespace).Update(ctx, updatedI, metav1.UpdateOptions{})
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

func (ic *IngressController) worker() {
	ic.log.Debug("Start worker")
	for ic.processNextItem() {
	}
}

func (ic *IngressController) processNextItem() bool {
	defer ic.log.Debug("Finish processNextItem")

	obj, shutdown := ic.queue.Get()
	if shutdown {
		return false
	}
	ic.log.Debug("Get next queue", zap.Any("key", obj))

	err := func(obj interface{}) error {
		defer ic.queue.Done(obj)

		ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelFunc()

		err := ic.syncIngress(ctx, obj.(string))
		if err != nil {
			if errors.Is(err, &RetryError{}) {
				ic.log.Debug("Retrying", zap.Error(err))
				ic.queue.AddRateLimited(obj)
				return nil
			}

			return err
		}

		ic.queue.Forget(obj)
		return nil
	}(obj)
	if err != nil {
		ic.log.Info("Failed sync", zap.Error(err))
		return true
	}

	return true
}

func (ic *IngressController) enqueue(ingress *networkingv1.Ingress) {
	if key, err := cache.MetaNamespaceKeyFunc(ingress); err != nil {
		return
	} else {
		ic.log.Debug("Enqueue", zap.String("key", key))
		ic.queue.Add(key)
	}
}

func (ic *IngressController) addIngress(obj interface{}) {
	ingress := obj.(*networkingv1.Ingress)

	ic.enqueue(ingress)
}

func (ic *IngressController) updateIngress(old, cur interface{}) {
	oldIngress := old.(*networkingv1.Ingress)
	curIngress := cur.(*networkingv1.Ingress)

	if oldIngress.UID != curIngress.UID {
		if key, err := cache.MetaNamespaceKeyFunc(oldIngress); err != nil {
			return
		} else {
			ic.deleteIngress(cache.DeletedFinalStateUnknown{Key: key, Obj: oldIngress})
		}
	}

	ic.enqueue(curIngress)
}

func (ic *IngressController) deleteIngress(obj interface{}) {
	ingress, ok := obj.(*networkingv1.Ingress)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		ingress, ok = tombstone.Obj.(*networkingv1.Ingress)
		if !ok {
			return
		}
	}

	ic.enqueue(ingress)
}
