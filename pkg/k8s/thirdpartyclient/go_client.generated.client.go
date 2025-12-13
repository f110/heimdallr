package thirdpartyclient

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"go.f110.dev/kubeproto/go/apis/metav1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/cert-manager/certmanagerv1"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/prometheus-operator/monitoringv1"
)

var (
	Scheme         = runtime.NewScheme()
	ParameterCodec = runtime.NewParameterCodec(Scheme)
	Codecs         = serializer.NewCodecFactory(Scheme)
	AddToScheme    = localSchemeBuilder.AddToScheme
)

var localSchemeBuilder = runtime.SchemeBuilder{
	monitoringv1.AddToScheme,
	certmanagerv1.AddToScheme,
}

func init() {
	for _, v := range []func(*runtime.Scheme) error{
		monitoringv1.AddToScheme,
		certmanagerv1.AddToScheme,
	} {
		if err := v(Scheme); err != nil {
			panic(err)
		}
	}
}

type Backend interface {
	Get(ctx context.Context, resourceName, namespace, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error)
	List(ctx context.Context, resourceName, namespace string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error)
	Create(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error)
	Update(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	UpdateStatus(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	Delete(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string, opts metav1.DeleteOptions) error
	Watch(ctx context.Context, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) (watch.Interface, error)
	GetClusterScoped(ctx context.Context, resourceName, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error)
	ListClusterScoped(ctx context.Context, resourceName string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error)
	CreateClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error)
	UpdateClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	UpdateStatusClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	DeleteClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, name string, opts metav1.DeleteOptions) error
	WatchClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error)

	RESTClient() *rest.RESTClient
}

type Set struct {
	CoreV1        *CoreV1
	CertManagerV1 *CertManagerV1
}

func NewSet(cfg *rest.Config) (*Set, error) {
	s := &Set{}
	{
		conf := *cfg
		conf.GroupVersion = &monitoringv1.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.CoreV1 = NewCoreV1Client(&restBackend{client: c}, &conf)
	}
	{
		conf := *cfg
		conf.GroupVersion = &certmanagerv1.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.CertManagerV1 = NewCertManagerV1Client(&restBackend{client: c}, &conf)
	}

	return s, nil
}

type restBackend struct {
	client *rest.RESTClient
}

func (r *restBackend) Get(ctx context.Context, resourceName, namespace, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error) {
	return result, r.client.Get().
		Namespace(namespace).
		Resource(resourceName).
		Name(name).
		VersionedParams(&opts, ParameterCodec).
		Do(ctx).
		Into(result)
}

func (r *restBackend) List(ctx context.Context, resourceName, namespace string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds > 0 {
		timeout = time.Duration(opts.TimeoutSeconds) * time.Second
	}
	return result, r.client.Get().
		Namespace(namespace).
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
}

func (r *restBackend) Create(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	meta := m.GetObjectMeta()
	return result, r.client.Post().
		Namespace(meta.Namespace).
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) Update(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	meta := m.GetObjectMeta()
	return result, r.client.Put().
		Namespace(meta.Namespace).
		Resource(resourceName).
		Name(meta.Name).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) UpdateStatus(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	meta := m.GetObjectMeta()
	return result, r.client.Put().
		Namespace(meta.Namespace).
		Resource(resourceName).
		Name(meta.Name).
		SubResource("status").
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) Delete(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string, opts metav1.DeleteOptions) error {
	return r.client.Delete().
		Namespace(namespace).
		Resource(gvr.Resource).
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

func (r *restBackend) Watch(ctx context.Context, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds > 0 {
		timeout = time.Duration(opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return r.client.Get().
		Namespace(namespace).
		Resource(gvr.Resource).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

func (r *restBackend) GetClusterScoped(ctx context.Context, resourceName, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error) {
	return result, r.client.Get().
		Resource(resourceName).
		Name(name).
		VersionedParams(&opts, ParameterCodec).
		Do(ctx).
		Into(result)
}

func (r *restBackend) ListClusterScoped(ctx context.Context, resourceName string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds > 0 {
		timeout = time.Duration(opts.TimeoutSeconds) * time.Second
	}
	return result, r.client.Get().
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
}

func (r *restBackend) CreateClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error) {
	return result, r.client.Post().
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) UpdateClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	meta := m.GetObjectMeta()
	return result, r.client.Put().
		Resource(resourceName).
		Name(meta.Name).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) UpdateStatusClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	meta := m.GetObjectMeta()
	return result, r.client.Put().
		Resource(resourceName).
		Name(meta.Name).
		SubResource("status").
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) DeleteClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, name string, opts metav1.DeleteOptions) error {
	return r.client.Delete().
		Resource(gvr.Resource).
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

func (r *restBackend) WatchClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds > 0 {
		timeout = time.Duration(opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return r.client.Get().
		Resource(gvr.Resource).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

func (r *restBackend) RESTClient() *rest.RESTClient {
	return r.client
}

type CoreV1 struct {
	backend Backend
	config  *rest.Config
}

func NewCoreV1Client(b Backend, config *rest.Config) *CoreV1 {
	return &CoreV1{backend: b, config: config}
}

func (c *CoreV1) GetAlertmanager(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.Get(ctx, "alertmanagers", namespace, name, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreV1) CreateAlertmanager(ctx context.Context, v *monitoringv1.Alertmanager, opts metav1.CreateOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.Create(ctx, "alertmanagers", v, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreV1) UpdateAlertmanager(ctx context.Context, v *monitoringv1.Alertmanager, opts metav1.UpdateOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.Update(ctx, "alertmanagers", v, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreV1) UpdateStatusAlertmanager(ctx context.Context, v *monitoringv1.Alertmanager, opts metav1.UpdateOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.UpdateStatus(ctx, "alertmanagers", v, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreV1) DeleteAlertmanager(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "alertmanagers"}, namespace, name, opts)
}

func (c *CoreV1) ListAlertmanager(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.AlertmanagerList, error) {
	result, err := c.backend.List(ctx, "alertmanagers", namespace, opts, &monitoringv1.AlertmanagerList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.AlertmanagerList), nil
}

func (c *CoreV1) WatchAlertmanager(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "alertmanagers"}, namespace, opts)
}

func (c *CoreV1) GetPodMonitor(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.PodMonitor, error) {
	result, err := c.backend.Get(ctx, "podmonitors", namespace, name, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitor), nil
}

func (c *CoreV1) CreatePodMonitor(ctx context.Context, v *monitoringv1.PodMonitor, opts metav1.CreateOptions) (*monitoringv1.PodMonitor, error) {
	result, err := c.backend.Create(ctx, "podmonitors", v, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitor), nil
}

func (c *CoreV1) UpdatePodMonitor(ctx context.Context, v *monitoringv1.PodMonitor, opts metav1.UpdateOptions) (*monitoringv1.PodMonitor, error) {
	result, err := c.backend.Update(ctx, "podmonitors", v, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitor), nil
}

func (c *CoreV1) DeletePodMonitor(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "podmonitors"}, namespace, name, opts)
}

func (c *CoreV1) ListPodMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.PodMonitorList, error) {
	result, err := c.backend.List(ctx, "podmonitors", namespace, opts, &monitoringv1.PodMonitorList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitorList), nil
}

func (c *CoreV1) WatchPodMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "podmonitors"}, namespace, opts)
}

func (c *CoreV1) GetProbe(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.Probe, error) {
	result, err := c.backend.Get(ctx, "probes", namespace, name, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Probe), nil
}

func (c *CoreV1) CreateProbe(ctx context.Context, v *monitoringv1.Probe, opts metav1.CreateOptions) (*monitoringv1.Probe, error) {
	result, err := c.backend.Create(ctx, "probes", v, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Probe), nil
}

func (c *CoreV1) UpdateProbe(ctx context.Context, v *monitoringv1.Probe, opts metav1.UpdateOptions) (*monitoringv1.Probe, error) {
	result, err := c.backend.Update(ctx, "probes", v, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Probe), nil
}

func (c *CoreV1) DeleteProbe(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "probes"}, namespace, name, opts)
}

func (c *CoreV1) ListProbe(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.ProbeList, error) {
	result, err := c.backend.List(ctx, "probes", namespace, opts, &monitoringv1.ProbeList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ProbeList), nil
}

func (c *CoreV1) WatchProbe(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "probes"}, namespace, opts)
}

func (c *CoreV1) GetPrometheus(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.Get(ctx, "prometheuses", namespace, name, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreV1) CreatePrometheus(ctx context.Context, v *monitoringv1.Prometheus, opts metav1.CreateOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.Create(ctx, "prometheuses", v, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreV1) UpdatePrometheus(ctx context.Context, v *monitoringv1.Prometheus, opts metav1.UpdateOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.Update(ctx, "prometheuses", v, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreV1) UpdateStatusPrometheus(ctx context.Context, v *monitoringv1.Prometheus, opts metav1.UpdateOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.UpdateStatus(ctx, "prometheuses", v, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreV1) DeletePrometheus(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "prometheuses"}, namespace, name, opts)
}

func (c *CoreV1) ListPrometheus(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.PrometheusList, error) {
	result, err := c.backend.List(ctx, "prometheuses", namespace, opts, &monitoringv1.PrometheusList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusList), nil
}

func (c *CoreV1) WatchPrometheus(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "prometheuses"}, namespace, opts)
}

func (c *CoreV1) GetPrometheusRule(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.PrometheusRule, error) {
	result, err := c.backend.Get(ctx, "prometheusrules", namespace, name, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRule), nil
}

func (c *CoreV1) CreatePrometheusRule(ctx context.Context, v *monitoringv1.PrometheusRule, opts metav1.CreateOptions) (*monitoringv1.PrometheusRule, error) {
	result, err := c.backend.Create(ctx, "prometheusrules", v, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRule), nil
}

func (c *CoreV1) UpdatePrometheusRule(ctx context.Context, v *monitoringv1.PrometheusRule, opts metav1.UpdateOptions) (*monitoringv1.PrometheusRule, error) {
	result, err := c.backend.Update(ctx, "prometheusrules", v, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRule), nil
}

func (c *CoreV1) DeletePrometheusRule(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}, namespace, name, opts)
}

func (c *CoreV1) ListPrometheusRule(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.PrometheusRuleList, error) {
	result, err := c.backend.List(ctx, "prometheusrules", namespace, opts, &monitoringv1.PrometheusRuleList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRuleList), nil
}

func (c *CoreV1) WatchPrometheusRule(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}, namespace, opts)
}

func (c *CoreV1) GetServiceMonitor(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.ServiceMonitor, error) {
	result, err := c.backend.Get(ctx, "servicemonitors", namespace, name, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitor), nil
}

func (c *CoreV1) CreateServiceMonitor(ctx context.Context, v *monitoringv1.ServiceMonitor, opts metav1.CreateOptions) (*monitoringv1.ServiceMonitor, error) {
	result, err := c.backend.Create(ctx, "servicemonitors", v, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitor), nil
}

func (c *CoreV1) UpdateServiceMonitor(ctx context.Context, v *monitoringv1.ServiceMonitor, opts metav1.UpdateOptions) (*monitoringv1.ServiceMonitor, error) {
	result, err := c.backend.Update(ctx, "servicemonitors", v, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitor), nil
}

func (c *CoreV1) DeleteServiceMonitor(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}, namespace, name, opts)
}

func (c *CoreV1) ListServiceMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.ServiceMonitorList, error) {
	result, err := c.backend.List(ctx, "servicemonitors", namespace, opts, &monitoringv1.ServiceMonitorList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitorList), nil
}

func (c *CoreV1) WatchServiceMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}, namespace, opts)
}

func (c *CoreV1) GetThanosRuler(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.Get(ctx, "thanosrulers", namespace, name, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreV1) CreateThanosRuler(ctx context.Context, v *monitoringv1.ThanosRuler, opts metav1.CreateOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.Create(ctx, "thanosrulers", v, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreV1) UpdateThanosRuler(ctx context.Context, v *monitoringv1.ThanosRuler, opts metav1.UpdateOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.Update(ctx, "thanosrulers", v, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreV1) UpdateStatusThanosRuler(ctx context.Context, v *monitoringv1.ThanosRuler, opts metav1.UpdateOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.UpdateStatus(ctx, "thanosrulers", v, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreV1) DeleteThanosRuler(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "thanosrulers"}, namespace, name, opts)
}

func (c *CoreV1) ListThanosRuler(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.ThanosRulerList, error) {
	result, err := c.backend.List(ctx, "thanosrulers", namespace, opts, &monitoringv1.ThanosRulerList{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRulerList), nil
}

func (c *CoreV1) WatchThanosRuler(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: ".monitoring.coreos.com", Version: "v1", Resource: "thanosrulers"}, namespace, opts)
}

type CertManagerV1 struct {
	backend Backend
	config  *rest.Config
}

func NewCertManagerV1Client(b Backend, config *rest.Config) *CertManagerV1 {
	return &CertManagerV1{backend: b, config: config}
}

func (c *CertManagerV1) GetCertificate(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.Get(ctx, "certificates", namespace, name, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerV1) CreateCertificate(ctx context.Context, v *certmanagerv1.Certificate, opts metav1.CreateOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.Create(ctx, "certificates", v, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerV1) UpdateCertificate(ctx context.Context, v *certmanagerv1.Certificate, opts metav1.UpdateOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.Update(ctx, "certificates", v, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerV1) UpdateStatusCertificate(ctx context.Context, v *certmanagerv1.Certificate, opts metav1.UpdateOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.UpdateStatus(ctx, "certificates", v, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerV1) DeleteCertificate(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, namespace, name, opts)
}

func (c *CertManagerV1) ListCertificate(ctx context.Context, namespace string, opts metav1.ListOptions) (*certmanagerv1.CertificateList, error) {
	result, err := c.backend.List(ctx, "certificates", namespace, opts, &certmanagerv1.CertificateList{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateList), nil
}

func (c *CertManagerV1) WatchCertificate(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, namespace, opts)
}

func (c *CertManagerV1) GetCertificateRequest(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.Get(ctx, "certificaterequests", namespace, name, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerV1) CreateCertificateRequest(ctx context.Context, v *certmanagerv1.CertificateRequest, opts metav1.CreateOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.Create(ctx, "certificaterequests", v, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerV1) UpdateCertificateRequest(ctx context.Context, v *certmanagerv1.CertificateRequest, opts metav1.UpdateOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.Update(ctx, "certificaterequests", v, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerV1) UpdateStatusCertificateRequest(ctx context.Context, v *certmanagerv1.CertificateRequest, opts metav1.UpdateOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.UpdateStatus(ctx, "certificaterequests", v, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerV1) DeleteCertificateRequest(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}, namespace, name, opts)
}

func (c *CertManagerV1) ListCertificateRequest(ctx context.Context, namespace string, opts metav1.ListOptions) (*certmanagerv1.CertificateRequestList, error) {
	result, err := c.backend.List(ctx, "certificaterequests", namespace, opts, &certmanagerv1.CertificateRequestList{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequestList), nil
}

func (c *CertManagerV1) WatchCertificateRequest(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}, namespace, opts)
}

func (c *CertManagerV1) GetClusterIssuer(ctx context.Context, name string, opts metav1.GetOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.GetClusterScoped(ctx, "clusterissuers", name, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerV1) CreateClusterIssuer(ctx context.Context, v *certmanagerv1.ClusterIssuer, opts metav1.CreateOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.CreateClusterScoped(ctx, "clusterissuers", v, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerV1) UpdateClusterIssuer(ctx context.Context, v *certmanagerv1.ClusterIssuer, opts metav1.UpdateOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.UpdateClusterScoped(ctx, "clusterissuers", v, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerV1) UpdateStatusClusterIssuer(ctx context.Context, v *certmanagerv1.ClusterIssuer, opts metav1.UpdateOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.UpdateStatusClusterScoped(ctx, "clusterissuers", v, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerV1) DeleteClusterIssuer(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.backend.DeleteClusterScoped(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}, name, opts)
}

func (c *CertManagerV1) ListClusterIssuer(ctx context.Context, opts metav1.ListOptions) (*certmanagerv1.ClusterIssuerList, error) {
	result, err := c.backend.ListClusterScoped(ctx, "clusterissuers", opts, &certmanagerv1.ClusterIssuerList{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuerList), nil
}

func (c *CertManagerV1) WatchClusterIssuer(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.WatchClusterScoped(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}, opts)
}

func (c *CertManagerV1) GetIssuer(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.Get(ctx, "issuers", namespace, name, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerV1) CreateIssuer(ctx context.Context, v *certmanagerv1.Issuer, opts metav1.CreateOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.Create(ctx, "issuers", v, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerV1) UpdateIssuer(ctx context.Context, v *certmanagerv1.Issuer, opts metav1.UpdateOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.Update(ctx, "issuers", v, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerV1) UpdateStatusIssuer(ctx context.Context, v *certmanagerv1.Issuer, opts metav1.UpdateOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.UpdateStatus(ctx, "issuers", v, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerV1) DeleteIssuer(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}, namespace, name, opts)
}

func (c *CertManagerV1) ListIssuer(ctx context.Context, namespace string, opts metav1.ListOptions) (*certmanagerv1.IssuerList, error) {
	result, err := c.backend.List(ctx, "issuers", namespace, opts, &certmanagerv1.IssuerList{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.IssuerList), nil
}

func (c *CertManagerV1) WatchIssuer(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}, namespace, opts)
}

type InformerCache struct {
	mu        sync.Mutex
	informers map[reflect.Type]cache.SharedIndexInformer
}

func NewInformerCache() *InformerCache {
	return &InformerCache{informers: make(map[reflect.Type]cache.SharedIndexInformer)}
}

func (c *InformerCache) Write(obj runtime.Object, newFunc func() cache.SharedIndexInformer) cache.SharedIndexInformer {
	c.mu.Lock()
	defer c.mu.Unlock()

	typ := reflect.TypeOf(obj)
	if v, ok := c.informers[typ]; ok {
		return v
	}
	informer := newFunc()
	c.informers[typ] = informer

	return informer
}

func (c *InformerCache) Informers() []cache.SharedIndexInformer {
	c.mu.Lock()
	defer c.mu.Unlock()

	a := make([]cache.SharedIndexInformer, 0, len(c.informers))
	for _, v := range c.informers {
		a = append(a, v)
	}

	return a
}

type InformerFactory struct {
	set   *Set
	cache *InformerCache

	namespace    string
	resyncPeriod time.Duration
}

func NewInformerFactory(s *Set, c *InformerCache, namespace string, resyncPeriod time.Duration) *InformerFactory {
	return &InformerFactory{set: s, cache: c, namespace: namespace, resyncPeriod: resyncPeriod}
}

func (f *InformerFactory) Cache() *InformerCache {
	return f.cache
}

func (f *InformerFactory) InformerFor(obj runtime.Object) cache.SharedIndexInformer {
	switch obj.(type) {
	case *monitoringv1.Alertmanager:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).AlertmanagerInformer()
	case *monitoringv1.PodMonitor:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).PodMonitorInformer()
	case *monitoringv1.Probe:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).ProbeInformer()
	case *monitoringv1.Prometheus:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).PrometheusInformer()
	case *monitoringv1.PrometheusRule:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).PrometheusRuleInformer()
	case *monitoringv1.ServiceMonitor:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).ServiceMonitorInformer()
	case *monitoringv1.ThanosRuler:
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).ThanosRulerInformer()
	case *certmanagerv1.Certificate:
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).CertificateInformer()
	case *certmanagerv1.CertificateRequest:
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).CertificateRequestInformer()
	case *certmanagerv1.ClusterIssuer:
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).ClusterIssuerInformer()
	case *certmanagerv1.Issuer:
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).IssuerInformer()
	default:
		return nil
	}
}

func (f *InformerFactory) InformerForResource(gvr schema.GroupVersionResource) cache.SharedIndexInformer {
	switch gvr {
	case monitoringv1.SchemaGroupVersion.WithResource("alertmanagers"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).AlertmanagerInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("podmonitors"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).PodMonitorInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("probes"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).ProbeInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("prometheuses"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).PrometheusInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("prometheusrules"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).PrometheusRuleInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("servicemonitors"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).ServiceMonitorInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("thanosrulers"):
		return NewCoreV1Informer(f.cache, f.set.CoreV1, f.namespace, f.resyncPeriod).ThanosRulerInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("certificates"):
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).CertificateInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("certificaterequests"):
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).CertificateRequestInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("clusterissuers"):
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).ClusterIssuerInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("issuers"):
		return NewCertManagerV1Informer(f.cache, f.set.CertManagerV1, f.namespace, f.resyncPeriod).IssuerInformer()
	default:
		return nil
	}
}

func (f *InformerFactory) Run(ctx context.Context) {
	for _, v := range f.cache.Informers() {
		go v.Run(ctx.Done())
	}
}

type CoreV1Informer struct {
	cache        *InformerCache
	client       *CoreV1
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewCoreV1Informer(c *InformerCache, client *CoreV1, namespace string, resyncPeriod time.Duration) *CoreV1Informer {
	return &CoreV1Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *CoreV1Informer) AlertmanagerInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.Alertmanager{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListAlertmanager(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchAlertmanager(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.Alertmanager{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) AlertmanagerLister() *CoreV1AlertmanagerLister {
	return NewCoreV1AlertmanagerLister(f.AlertmanagerInformer().GetIndexer())
}

func (f *CoreV1Informer) PodMonitorInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.PodMonitor{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListPodMonitor(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchPodMonitor(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.PodMonitor{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) PodMonitorLister() *CoreV1PodMonitorLister {
	return NewCoreV1PodMonitorLister(f.PodMonitorInformer().GetIndexer())
}

func (f *CoreV1Informer) ProbeInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.Probe{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListProbe(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchProbe(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.Probe{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) ProbeLister() *CoreV1ProbeLister {
	return NewCoreV1ProbeLister(f.ProbeInformer().GetIndexer())
}

func (f *CoreV1Informer) PrometheusInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.Prometheus{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListPrometheus(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchPrometheus(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.Prometheus{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) PrometheusLister() *CoreV1PrometheusLister {
	return NewCoreV1PrometheusLister(f.PrometheusInformer().GetIndexer())
}

func (f *CoreV1Informer) PrometheusRuleInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.PrometheusRule{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListPrometheusRule(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchPrometheusRule(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.PrometheusRule{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) PrometheusRuleLister() *CoreV1PrometheusRuleLister {
	return NewCoreV1PrometheusRuleLister(f.PrometheusRuleInformer().GetIndexer())
}

func (f *CoreV1Informer) ServiceMonitorInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.ServiceMonitor{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListServiceMonitor(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchServiceMonitor(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.ServiceMonitor{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) ServiceMonitorLister() *CoreV1ServiceMonitorLister {
	return NewCoreV1ServiceMonitorLister(f.ServiceMonitorInformer().GetIndexer())
}

func (f *CoreV1Informer) ThanosRulerInformer() cache.SharedIndexInformer {
	return f.cache.Write(&monitoringv1.ThanosRuler{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListThanosRuler(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchThanosRuler(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&monitoringv1.ThanosRuler{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CoreV1Informer) ThanosRulerLister() *CoreV1ThanosRulerLister {
	return NewCoreV1ThanosRulerLister(f.ThanosRulerInformer().GetIndexer())
}

type CertManagerV1Informer struct {
	cache        *InformerCache
	client       *CertManagerV1
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewCertManagerV1Informer(c *InformerCache, client *CertManagerV1, namespace string, resyncPeriod time.Duration) *CertManagerV1Informer {
	return &CertManagerV1Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *CertManagerV1Informer) CertificateInformer() cache.SharedIndexInformer {
	return f.cache.Write(&certmanagerv1.Certificate{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListCertificate(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchCertificate(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&certmanagerv1.Certificate{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CertManagerV1Informer) CertificateLister() *CertManagerV1CertificateLister {
	return NewCertManagerV1CertificateLister(f.CertificateInformer().GetIndexer())
}

func (f *CertManagerV1Informer) CertificateRequestInformer() cache.SharedIndexInformer {
	return f.cache.Write(&certmanagerv1.CertificateRequest{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListCertificateRequest(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchCertificateRequest(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&certmanagerv1.CertificateRequest{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CertManagerV1Informer) CertificateRequestLister() *CertManagerV1CertificateRequestLister {
	return NewCertManagerV1CertificateRequestLister(f.CertificateRequestInformer().GetIndexer())
}

func (f *CertManagerV1Informer) ClusterIssuerInformer() cache.SharedIndexInformer {
	return f.cache.Write(&certmanagerv1.ClusterIssuer{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListClusterIssuer(context.TODO(), metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchClusterIssuer(context.TODO(), metav1.ListOptions{})
				},
			},
			&certmanagerv1.ClusterIssuer{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CertManagerV1Informer) ClusterIssuerLister() *CertManagerV1ClusterIssuerLister {
	return NewCertManagerV1ClusterIssuerLister(f.ClusterIssuerInformer().GetIndexer())
}

func (f *CertManagerV1Informer) IssuerInformer() cache.SharedIndexInformer {
	return f.cache.Write(&certmanagerv1.Issuer{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options k8smetav1.ListOptions) (runtime.Object, error) {
					return f.client.ListIssuer(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options k8smetav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchIssuer(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&certmanagerv1.Issuer{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *CertManagerV1Informer) IssuerLister() *CertManagerV1IssuerLister {
	return NewCertManagerV1IssuerLister(f.IssuerInformer().GetIndexer())
}

type CoreV1AlertmanagerLister struct {
	indexer cache.Indexer
}

func NewCoreV1AlertmanagerLister(indexer cache.Indexer) *CoreV1AlertmanagerLister {
	return &CoreV1AlertmanagerLister{indexer: indexer}
}

func (x *CoreV1AlertmanagerLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.Alertmanager, error) {
	var ret []*monitoringv1.Alertmanager
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.Alertmanager).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1AlertmanagerLister) Get(namespace, name string) (*monitoringv1.Alertmanager, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("alertmanager").GroupResource(), name)
	}
	return obj.(*monitoringv1.Alertmanager).DeepCopy(), nil
}

type CoreV1PodMonitorLister struct {
	indexer cache.Indexer
}

func NewCoreV1PodMonitorLister(indexer cache.Indexer) *CoreV1PodMonitorLister {
	return &CoreV1PodMonitorLister{indexer: indexer}
}

func (x *CoreV1PodMonitorLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.PodMonitor, error) {
	var ret []*monitoringv1.PodMonitor
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.PodMonitor).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1PodMonitorLister) Get(namespace, name string) (*monitoringv1.PodMonitor, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("podmonitor").GroupResource(), name)
	}
	return obj.(*monitoringv1.PodMonitor).DeepCopy(), nil
}

type CoreV1ProbeLister struct {
	indexer cache.Indexer
}

func NewCoreV1ProbeLister(indexer cache.Indexer) *CoreV1ProbeLister {
	return &CoreV1ProbeLister{indexer: indexer}
}

func (x *CoreV1ProbeLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.Probe, error) {
	var ret []*monitoringv1.Probe
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.Probe).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1ProbeLister) Get(namespace, name string) (*monitoringv1.Probe, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("probe").GroupResource(), name)
	}
	return obj.(*monitoringv1.Probe).DeepCopy(), nil
}

type CoreV1PrometheusLister struct {
	indexer cache.Indexer
}

func NewCoreV1PrometheusLister(indexer cache.Indexer) *CoreV1PrometheusLister {
	return &CoreV1PrometheusLister{indexer: indexer}
}

func (x *CoreV1PrometheusLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.Prometheus, error) {
	var ret []*monitoringv1.Prometheus
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.Prometheus).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1PrometheusLister) Get(namespace, name string) (*monitoringv1.Prometheus, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("prometheus").GroupResource(), name)
	}
	return obj.(*monitoringv1.Prometheus).DeepCopy(), nil
}

type CoreV1PrometheusRuleLister struct {
	indexer cache.Indexer
}

func NewCoreV1PrometheusRuleLister(indexer cache.Indexer) *CoreV1PrometheusRuleLister {
	return &CoreV1PrometheusRuleLister{indexer: indexer}
}

func (x *CoreV1PrometheusRuleLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.PrometheusRule, error) {
	var ret []*monitoringv1.PrometheusRule
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.PrometheusRule).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1PrometheusRuleLister) Get(namespace, name string) (*monitoringv1.PrometheusRule, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("prometheusrule").GroupResource(), name)
	}
	return obj.(*monitoringv1.PrometheusRule).DeepCopy(), nil
}

type CoreV1ServiceMonitorLister struct {
	indexer cache.Indexer
}

func NewCoreV1ServiceMonitorLister(indexer cache.Indexer) *CoreV1ServiceMonitorLister {
	return &CoreV1ServiceMonitorLister{indexer: indexer}
}

func (x *CoreV1ServiceMonitorLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.ServiceMonitor, error) {
	var ret []*monitoringv1.ServiceMonitor
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.ServiceMonitor).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1ServiceMonitorLister) Get(namespace, name string) (*monitoringv1.ServiceMonitor, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("servicemonitor").GroupResource(), name)
	}
	return obj.(*monitoringv1.ServiceMonitor).DeepCopy(), nil
}

type CoreV1ThanosRulerLister struct {
	indexer cache.Indexer
}

func NewCoreV1ThanosRulerLister(indexer cache.Indexer) *CoreV1ThanosRulerLister {
	return &CoreV1ThanosRulerLister{indexer: indexer}
}

func (x *CoreV1ThanosRulerLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.ThanosRuler, error) {
	var ret []*monitoringv1.ThanosRuler
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.ThanosRuler).DeepCopy())
	})
	return ret, err
}

func (x *CoreV1ThanosRulerLister) Get(namespace, name string) (*monitoringv1.ThanosRuler, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("thanosruler").GroupResource(), name)
	}
	return obj.(*monitoringv1.ThanosRuler).DeepCopy(), nil
}

type CertManagerV1CertificateLister struct {
	indexer cache.Indexer
}

func NewCertManagerV1CertificateLister(indexer cache.Indexer) *CertManagerV1CertificateLister {
	return &CertManagerV1CertificateLister{indexer: indexer}
}

func (x *CertManagerV1CertificateLister) List(namespace string, selector labels.Selector) ([]*certmanagerv1.Certificate, error) {
	var ret []*certmanagerv1.Certificate
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.Certificate).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerV1CertificateLister) Get(namespace, name string) (*certmanagerv1.Certificate, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("certificate").GroupResource(), name)
	}
	return obj.(*certmanagerv1.Certificate).DeepCopy(), nil
}

type CertManagerV1CertificateRequestLister struct {
	indexer cache.Indexer
}

func NewCertManagerV1CertificateRequestLister(indexer cache.Indexer) *CertManagerV1CertificateRequestLister {
	return &CertManagerV1CertificateRequestLister{indexer: indexer}
}

func (x *CertManagerV1CertificateRequestLister) List(namespace string, selector labels.Selector) ([]*certmanagerv1.CertificateRequest, error) {
	var ret []*certmanagerv1.CertificateRequest
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.CertificateRequest).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerV1CertificateRequestLister) Get(namespace, name string) (*certmanagerv1.CertificateRequest, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("certificaterequest").GroupResource(), name)
	}
	return obj.(*certmanagerv1.CertificateRequest).DeepCopy(), nil
}

type CertManagerV1ClusterIssuerLister struct {
	indexer cache.Indexer
}

func NewCertManagerV1ClusterIssuerLister(indexer cache.Indexer) *CertManagerV1ClusterIssuerLister {
	return &CertManagerV1ClusterIssuerLister{indexer: indexer}
}

func (x *CertManagerV1ClusterIssuerLister) List(selector labels.Selector) ([]*certmanagerv1.ClusterIssuer, error) {
	var ret []*certmanagerv1.ClusterIssuer
	err := cache.ListAll(x.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.ClusterIssuer).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerV1ClusterIssuerLister) Get(name string) (*certmanagerv1.ClusterIssuer, error) {
	obj, exists, err := x.indexer.GetByKey("/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("clusterissuer").GroupResource(), name)
	}
	return obj.(*certmanagerv1.ClusterIssuer).DeepCopy(), nil
}

type CertManagerV1IssuerLister struct {
	indexer cache.Indexer
}

func NewCertManagerV1IssuerLister(indexer cache.Indexer) *CertManagerV1IssuerLister {
	return &CertManagerV1IssuerLister{indexer: indexer}
}

func (x *CertManagerV1IssuerLister) List(namespace string, selector labels.Selector) ([]*certmanagerv1.Issuer, error) {
	var ret []*certmanagerv1.Issuer
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.Issuer).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerV1IssuerLister) Get(namespace, name string) (*certmanagerv1.Issuer, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("issuer").GroupResource(), name)
	}
	return obj.(*certmanagerv1.Issuer).DeepCopy(), nil
}
