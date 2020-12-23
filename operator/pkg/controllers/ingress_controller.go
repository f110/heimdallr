package controllers

import (
	"context"
	"fmt"
	"reflect"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreInformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	coreListers "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	"go.f110.dev/heimdallr/operator/pkg/api/proxy"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/controllers/controllerbase"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1alpha2"
)

const (
	ingressClassControllerName     = "heimdallr.f110.dev/ingress-controller"
	ingressControllerFinalizerName = "ingress-controller.heimdallr.f110.dev/finalizer"
)

type IngressController struct {
	*controllerbase.Controller

	ingressInformer          cache.SharedIndexInformer
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
	backendInformer := sharedInformerFactory.Proxy().V1alpha2().Backends()

	ic := &IngressController{
		ingressInformer:          ingressInformer.Informer(),
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
	}

	ic.Controller = controllerbase.NewController(ic, coreClient)
	return ic
}

func (ic *IngressController) Name() string {
	return "ingress-controller"
}

func (ic *IngressController) Finalizers() []string {
	return []string{ingressControllerFinalizerName}
}

func (ic *IngressController) ListerSynced() []cache.InformerSynced {
	return []cache.InformerSynced{
		ic.ingressListerSynced,
		ic.ingressClassListerSynced,
		ic.backendListerSynced,
		ic.serviceListerSynced,
	}
}

func (ic *IngressController) EventSources() []cache.SharedIndexInformer {
	return []cache.SharedIndexInformer{
		ic.ingressInformer,
	}
}

func (ic *IngressController) ConvertToKeys() controllerbase.ObjectToKeyConverter {
	return func(obj interface{}) (keys []string, err error) {
		switch obj.(type) {
		case *networkingv1.Ingress:
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				return nil, err
			}
			return []string{key}, nil
		default:
			ic.Log().Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (ic *IngressController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	ingress, err := ic.ingressLister.Ingresses(namespace).Get(name)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if ingress.Spec.IngressClassName == nil {
		return nil, nil
	}

	ingClass, err := ic.ingressClassLister.Get(*ingress.Spec.IngressClassName)
	if err != nil {
		ic.Log().Debug("Failure or not found IngressClass", zap.Error(err), zap.String("name", *ingress.Spec.IngressClassName))
		return nil, nil
	}
	if ingClass.Spec.Controller != ingressClassControllerName {
		ic.Log().Debug("Skip Ingress", zap.String("name", ingress.Name))
		return nil, nil
	}

	return ingress, nil
}

func (ic *IngressController) UpdateObject(ctx context.Context, obj interface{}) error {
	ingress, ok := obj.(*networkingv1.Ingress)
	if !ok {
		return nil
	}

	_, err := ic.coreClient.NetworkingV1().Ingresses(ingress.Namespace).Update(ctx, ingress, metav1.UpdateOptions{})
	return err
}

func (ic *IngressController) Reconcile(ctx context.Context, obj interface{}) error {
	ic.Log().Debug("syncIngress")
	ingress := obj.(*networkingv1.Ingress)
	ingClass, err := ic.coreClient.NetworkingV1().IngressClasses().Get(ctx, *ingress.Spec.IngressClassName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	backends := make([]*proxyv1alpha2.Backend, 0)
	for _, rule := range ingress.Spec.Rules {
		httpRouting := make([]*proxyv1alpha2.BackendHTTPRoutingSpec, 0)
		for _, v := range rule.HTTP.Paths {
			httpRouting = append(httpRouting, &proxyv1alpha2.BackendHTTPRoutingSpec{
				Path: v.Path,
				ServiceSelector: &proxyv1alpha2.ServiceSelector{
					Name:      v.Backend.Service.Name,
					Namespace: ingress.Namespace,
					Port:      v.Backend.Service.Port.Name,
				},
			})
		}

		backends = append(backends,
			&proxyv1alpha2.Backend{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ingress.Name,
					Namespace: ingress.Namespace,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(ingress, networkingv1.SchemeGroupVersion.WithKind("Ingress")),
					},
					Annotations: map[string]string{
						proxy.AnnotationKeyIngressName: fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name),
					},
					Labels: ingClass.Labels,
				},
				Spec: proxyv1alpha2.BackendSpec{
					FQDN:         rule.Host,
					DisableAuthn: true,
					HTTPRouting:  httpRouting,
				},
			},
		)
	}

	for _, b := range backends {
		backend, err := ic.backendLister.Backends(b.Namespace).Get(b.Name)
		if err != nil && apierrors.IsNotFound(err) {
			_, err = ic.client.ProxyV1alpha2().Backends(b.Namespace).Create(ctx, b, metav1.CreateOptions{})
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
			_, err = ic.client.ProxyV1alpha2().Backends(backend.Namespace).Update(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (ic *IngressController) Finalize(ctx context.Context, obj interface{}) error {
	ingress := obj.(*networkingv1.Ingress)

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		ig, err := ic.ingressLister.Ingresses(ingress.Namespace).Get(ingress.Name)
		if err != nil {
			return err
		}

		updatedI := ig.DeepCopy()
		controllerbase.RemoveFinalizer(&updatedI.ObjectMeta, ingressControllerFinalizerName)
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
