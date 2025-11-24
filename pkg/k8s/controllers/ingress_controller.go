package controllers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/apis/networkingv1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

const (
	ingressClassControllerName     = "heimdallr.f110.dev/ingress-controller"
	ingressControllerFinalizerName = "ingress-controller.heimdallr.f110.dev/finalizer"
)

type IngressController struct {
	*controllerbase.Controller

	ingressInformer          cache.SharedIndexInformer
	ingressLister            *k8sclient.NetworkingK8sIoV1IngressLister
	ingressListerSynced      cache.InformerSynced
	ingressClassLister       *k8sclient.NetworkingK8sIoV1IngressClassLister
	ingressClassListerSynced cache.InformerSynced
	serviceLister            *k8sclient.CoreV1ServiceLister
	serviceListerSynced      cache.InformerSynced

	backendLister       *client.ProxyV1alpha2BackendLister
	backendListerSynced cache.InformerSynced

	proxyClient *client.ProxyV1alpha2
	coreClient  *k8sclient.Set
}

func NewIngressController(
	coreSharedInformerFactory *k8sclient.InformerFactory,
	sharedInformerFactory *client.InformerFactory,
	coreClient *k8sclient.Set,
	proxyClient *client.ProxyV1alpha2,
	k8sClient kubernetes.Interface,
) *IngressController {
	corev1Informer := k8sclient.NewCoreV1Informer(coreSharedInformerFactory.Cache(), coreClient.CoreV1, metav1.NamespaceAll, 30*time.Second)
	networkingv1Informer := k8sclient.NewNetworkingK8sIoV1Informer(coreSharedInformerFactory.Cache(), coreClient.NetworkingK8sIoV1, metav1.NamespaceAll, 30*time.Second)
	backendInformer := client.NewProxyV1alpha2Informer(sharedInformerFactory.Cache(), proxyClient, metav1.NamespaceAll, 30*time.Second)

	ic := &IngressController{
		ingressInformer:          networkingv1Informer.IngressInformer(),
		ingressLister:            networkingv1Informer.IngressLister(),
		ingressListerSynced:      networkingv1Informer.IngressInformer().HasSynced,
		ingressClassLister:       networkingv1Informer.IngressClassLister(),
		ingressClassListerSynced: networkingv1Informer.IngressClassInformer().HasSynced,
		serviceLister:            corev1Informer.ServiceLister(),
		serviceListerSynced:      corev1Informer.ServiceInformer().HasSynced,
		backendLister:            backendInformer.BackendLister(),
		backendListerSynced:      backendInformer.BackendInformer().HasSynced,
		coreClient:               coreClient,
		proxyClient:              proxyClient,
	}

	ic.Controller = controllerbase.NewController(ic, k8sClient)
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
			ic.Log(nil).Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (ic *IngressController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	ingress, err := ic.ingressLister.Get(namespace, name)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	if ingress.Spec.IngressClassName == "" {
		return nil, nil
	}

	ingClass, err := ic.ingressClassLister.Get(ingress.Spec.IngressClassName)
	if err != nil {
		ic.Log(nil).Debug("Failure or not found IngressClass", zap.Error(err), zap.String("name", ingress.Spec.IngressClassName))
		return nil, nil
	}
	if ingClass.Spec.Controller != ingressClassControllerName {
		ic.Log(nil).Debug("Skip Ingress", zap.String("name", ingress.Name))
		return nil, nil
	}

	return ingress, nil
}

func (ic *IngressController) UpdateObject(ctx context.Context, obj interface{}) error {
	ingress, ok := obj.(*networkingv1.Ingress)
	if !ok {
		return nil
	}

	_, err := ic.coreClient.NetworkingK8sIoV1.UpdateIngress(ctx, ingress, metav1.UpdateOptions{})
	return err
}

func (ic *IngressController) Reconcile(ctx context.Context, obj interface{}) error {
	ingress := obj.(*networkingv1.Ingress)
	ic.Log(ctx).Debug("syncIngress", zap.String("namespace", ingress.Namespace), zap.String("name", ingress.Name))

	ingClass, err := ic.coreClient.NetworkingK8sIoV1.GetIngressClass(ctx, ingress.Spec.IngressClassName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	backends := make([]*proxyv1alpha2.Backend, 0)
	for _, rule := range ingress.Spec.Rules {
		httpRouting := make([]proxyv1alpha2.BackendHTTPSpec, 0)
		for _, v := range rule.HTTP.Paths {
			httpRouting = append(httpRouting, proxyv1alpha2.BackendHTTPSpec{
				Path: v.Path,
				ServiceSelector: &proxyv1alpha2.ServiceSelector{
					Name:      v.Backend.Service.Name,
					Namespace: ingress.Namespace,
					Port:      v.Backend.Service.Port.Name,
				},
			})
		}

		backends = append(backends,
			proxy.BackendFactory(nil,
				k8sfactory.Name(ingress.Name),
				k8sfactory.Namespace(ingress.Namespace),
				k8sfactory.Annotation(proxy.AnnotationKeyIngressName, fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Name)),
				k8sfactory.Labels(ingClass.Labels),
				proxy.FQDN(rule.Host),
				proxy.DisableAuthn,
				proxy.HTTP(httpRouting),
			),
		)
	}

	for _, b := range backends {
		backend, err := ic.backendLister.Get(b.Namespace, b.Name)
		if err != nil && apierrors.IsNotFound(err) {
			_, err = ic.proxyClient.CreateBackend(ctx, b, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
			continue
		} else if err != nil {
			return xerrors.WithStack(err)
		}

		updatedB := backend.DeepCopy()
		updatedB.Spec = b.Spec
		if !reflect.DeepEqual(updatedB, backend) {
			_, err = ic.proxyClient.UpdateBackend(ctx, updatedB, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	return nil
}

func (ic *IngressController) Finalize(ctx context.Context, obj interface{}) error {
	ingress := obj.(*networkingv1.Ingress)

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		ig, err := ic.ingressLister.Get(ingress.Namespace, ingress.Name)
		if err != nil {
			return err
		}

		updatedI := ig.DeepCopy()
		controllerbase.RemoveFinalizer(&updatedI.ObjectMeta, ingressControllerFinalizerName)
		if !reflect.DeepEqual(updatedI.Finalizers, ig.Finalizers) {
			_, err = ic.coreClient.NetworkingK8sIoV1.UpdateIngress(ctx, updatedI, metav1.UpdateOptions{})
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
