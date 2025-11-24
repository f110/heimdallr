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
	certmanagerv1.AddToScheme,
	monitoringv1.AddToScheme,
}

func init() {
	for _, v := range []func(*runtime.Scheme) error{
		certmanagerv1.AddToScheme,
		monitoringv1.AddToScheme,
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
}

type Set struct {
	CertManagerIoV1 *CertManagerIoV1
	CoreosComV1     *CoreosComV1
	RESTClient      *rest.RESTClient
}

func NewSet(cfg *rest.Config) (*Set, error) {
	s := &Set{}
	{
		conf := *cfg
		conf.GroupVersion = &certmanagerv1.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.CertManagerIoV1 = NewCertManagerIoV1Client(&restBackend{client: c})
	}
	{
		conf := *cfg
		conf.GroupVersion = &monitoringv1.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.CoreosComV1 = NewCoreosComV1Client(&restBackend{client: c})
	}
	{
		conf := *cfg
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.RESTClient = c
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

type CertManagerIoV1 struct {
	backend Backend
}

func NewCertManagerIoV1Client(b Backend) *CertManagerIoV1 {
	return &CertManagerIoV1{backend: b}
}

func (c *CertManagerIoV1) GetCertificate(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.Get(ctx, "certificates", namespace, name, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerIoV1) CreateCertificate(ctx context.Context, v *certmanagerv1.Certificate, opts metav1.CreateOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.Create(ctx, "certificates", v, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerIoV1) UpdateCertificate(ctx context.Context, v *certmanagerv1.Certificate, opts metav1.UpdateOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.Update(ctx, "certificates", v, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerIoV1) UpdateStatusCertificate(ctx context.Context, v *certmanagerv1.Certificate, opts metav1.UpdateOptions) (*certmanagerv1.Certificate, error) {
	result, err := c.backend.UpdateStatus(ctx, "certificates", v, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Certificate), nil
}

func (c *CertManagerIoV1) DeleteCertificate(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "certificates"}, namespace, name, opts)
}

func (c *CertManagerIoV1) ListCertificate(ctx context.Context, namespace string, opts metav1.ListOptions) (*certmanagerv1.CertificateList, error) {
	result, err := c.backend.List(ctx, "certificates", namespace, opts, &certmanagerv1.Certificate{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateList), nil
}

func (c *CertManagerIoV1) WatchCertificate(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "certificates"}, namespace, opts)
}

func (c *CertManagerIoV1) GetCertificateRequest(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.Get(ctx, "certificaterequests", namespace, name, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerIoV1) CreateCertificateRequest(ctx context.Context, v *certmanagerv1.CertificateRequest, opts metav1.CreateOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.Create(ctx, "certificaterequests", v, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerIoV1) UpdateCertificateRequest(ctx context.Context, v *certmanagerv1.CertificateRequest, opts metav1.UpdateOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.Update(ctx, "certificaterequests", v, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerIoV1) UpdateStatusCertificateRequest(ctx context.Context, v *certmanagerv1.CertificateRequest, opts metav1.UpdateOptions) (*certmanagerv1.CertificateRequest, error) {
	result, err := c.backend.UpdateStatus(ctx, "certificaterequests", v, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequest), nil
}

func (c *CertManagerIoV1) DeleteCertificateRequest(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "certificaterequests"}, namespace, name, opts)
}

func (c *CertManagerIoV1) ListCertificateRequest(ctx context.Context, namespace string, opts metav1.ListOptions) (*certmanagerv1.CertificateRequestList, error) {
	result, err := c.backend.List(ctx, "certificaterequests", namespace, opts, &certmanagerv1.CertificateRequest{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.CertificateRequestList), nil
}

func (c *CertManagerIoV1) WatchCertificateRequest(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "certificaterequests"}, namespace, opts)
}

func (c *CertManagerIoV1) GetClusterIssuer(ctx context.Context, name string, opts metav1.GetOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.GetClusterScoped(ctx, "clusterissuers", name, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerIoV1) CreateClusterIssuer(ctx context.Context, v *certmanagerv1.ClusterIssuer, opts metav1.CreateOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.CreateClusterScoped(ctx, "clusterissuers", v, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerIoV1) UpdateClusterIssuer(ctx context.Context, v *certmanagerv1.ClusterIssuer, opts metav1.UpdateOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.UpdateClusterScoped(ctx, "clusterissuers", v, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerIoV1) UpdateStatusClusterIssuer(ctx context.Context, v *certmanagerv1.ClusterIssuer, opts metav1.UpdateOptions) (*certmanagerv1.ClusterIssuer, error) {
	result, err := c.backend.UpdateStatusClusterScoped(ctx, "clusterissuers", v, opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuer), nil
}

func (c *CertManagerIoV1) DeleteClusterIssuer(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.backend.DeleteClusterScoped(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "clusterissuers"}, name, opts)
}

func (c *CertManagerIoV1) ListClusterIssuer(ctx context.Context, opts metav1.ListOptions) (*certmanagerv1.ClusterIssuerList, error) {
	result, err := c.backend.ListClusterScoped(ctx, "clusterissuers", opts, &certmanagerv1.ClusterIssuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.ClusterIssuerList), nil
}

func (c *CertManagerIoV1) WatchClusterIssuer(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.WatchClusterScoped(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "clusterissuers"}, opts)
}

func (c *CertManagerIoV1) GetIssuer(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.Get(ctx, "issuers", namespace, name, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerIoV1) CreateIssuer(ctx context.Context, v *certmanagerv1.Issuer, opts metav1.CreateOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.Create(ctx, "issuers", v, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerIoV1) UpdateIssuer(ctx context.Context, v *certmanagerv1.Issuer, opts metav1.UpdateOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.Update(ctx, "issuers", v, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerIoV1) UpdateStatusIssuer(ctx context.Context, v *certmanagerv1.Issuer, opts metav1.UpdateOptions) (*certmanagerv1.Issuer, error) {
	result, err := c.backend.UpdateStatus(ctx, "issuers", v, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.Issuer), nil
}

func (c *CertManagerIoV1) DeleteIssuer(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "issuers"}, namespace, name, opts)
}

func (c *CertManagerIoV1) ListIssuer(ctx context.Context, namespace string, opts metav1.ListOptions) (*certmanagerv1.IssuerList, error) {
	result, err := c.backend.List(ctx, "issuers", namespace, opts, &certmanagerv1.Issuer{})
	if err != nil {
		return nil, err
	}
	return result.(*certmanagerv1.IssuerList), nil
}

func (c *CertManagerIoV1) WatchIssuer(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "cert-manager.io.", Version: "v1", Resource: "issuers"}, namespace, opts)
}

type CoreosComV1 struct {
	backend Backend
}

func NewCoreosComV1Client(b Backend) *CoreosComV1 {
	return &CoreosComV1{backend: b}
}

func (c *CoreosComV1) GetAlertmanager(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.Get(ctx, "alertmanagers", namespace, name, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreosComV1) CreateAlertmanager(ctx context.Context, v *monitoringv1.Alertmanager, opts metav1.CreateOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.Create(ctx, "alertmanagers", v, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreosComV1) UpdateAlertmanager(ctx context.Context, v *monitoringv1.Alertmanager, opts metav1.UpdateOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.Update(ctx, "alertmanagers", v, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreosComV1) UpdateStatusAlertmanager(ctx context.Context, v *monitoringv1.Alertmanager, opts metav1.UpdateOptions) (*monitoringv1.Alertmanager, error) {
	result, err := c.backend.UpdateStatus(ctx, "alertmanagers", v, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Alertmanager), nil
}

func (c *CoreosComV1) DeleteAlertmanager(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "alertmanagers"}, namespace, name, opts)
}

func (c *CoreosComV1) ListAlertmanager(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.AlertmanagerList, error) {
	result, err := c.backend.List(ctx, "alertmanagers", namespace, opts, &monitoringv1.Alertmanager{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.AlertmanagerList), nil
}

func (c *CoreosComV1) WatchAlertmanager(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "alertmanagers"}, namespace, opts)
}

func (c *CoreosComV1) GetPodMonitor(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.PodMonitor, error) {
	result, err := c.backend.Get(ctx, "podmonitors", namespace, name, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitor), nil
}

func (c *CoreosComV1) CreatePodMonitor(ctx context.Context, v *monitoringv1.PodMonitor, opts metav1.CreateOptions) (*monitoringv1.PodMonitor, error) {
	result, err := c.backend.Create(ctx, "podmonitors", v, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitor), nil
}

func (c *CoreosComV1) UpdatePodMonitor(ctx context.Context, v *monitoringv1.PodMonitor, opts metav1.UpdateOptions) (*monitoringv1.PodMonitor, error) {
	result, err := c.backend.Update(ctx, "podmonitors", v, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitor), nil
}

func (c *CoreosComV1) DeletePodMonitor(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "podmonitors"}, namespace, name, opts)
}

func (c *CoreosComV1) ListPodMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.PodMonitorList, error) {
	result, err := c.backend.List(ctx, "podmonitors", namespace, opts, &monitoringv1.PodMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PodMonitorList), nil
}

func (c *CoreosComV1) WatchPodMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "podmonitors"}, namespace, opts)
}

func (c *CoreosComV1) GetProbe(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.Probe, error) {
	result, err := c.backend.Get(ctx, "probes", namespace, name, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Probe), nil
}

func (c *CoreosComV1) CreateProbe(ctx context.Context, v *monitoringv1.Probe, opts metav1.CreateOptions) (*monitoringv1.Probe, error) {
	result, err := c.backend.Create(ctx, "probes", v, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Probe), nil
}

func (c *CoreosComV1) UpdateProbe(ctx context.Context, v *monitoringv1.Probe, opts metav1.UpdateOptions) (*monitoringv1.Probe, error) {
	result, err := c.backend.Update(ctx, "probes", v, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Probe), nil
}

func (c *CoreosComV1) DeleteProbe(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "probes"}, namespace, name, opts)
}

func (c *CoreosComV1) ListProbe(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.ProbeList, error) {
	result, err := c.backend.List(ctx, "probes", namespace, opts, &monitoringv1.Probe{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ProbeList), nil
}

func (c *CoreosComV1) WatchProbe(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "probes"}, namespace, opts)
}

func (c *CoreosComV1) GetPrometheus(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.Get(ctx, "prometheuses", namespace, name, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreosComV1) CreatePrometheus(ctx context.Context, v *monitoringv1.Prometheus, opts metav1.CreateOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.Create(ctx, "prometheuses", v, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreosComV1) UpdatePrometheus(ctx context.Context, v *monitoringv1.Prometheus, opts metav1.UpdateOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.Update(ctx, "prometheuses", v, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreosComV1) UpdateStatusPrometheus(ctx context.Context, v *monitoringv1.Prometheus, opts metav1.UpdateOptions) (*monitoringv1.Prometheus, error) {
	result, err := c.backend.UpdateStatus(ctx, "prometheuses", v, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.Prometheus), nil
}

func (c *CoreosComV1) DeletePrometheus(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "prometheuses"}, namespace, name, opts)
}

func (c *CoreosComV1) ListPrometheus(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.PrometheusList, error) {
	result, err := c.backend.List(ctx, "prometheuses", namespace, opts, &monitoringv1.Prometheus{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusList), nil
}

func (c *CoreosComV1) WatchPrometheus(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "prometheuses"}, namespace, opts)
}

func (c *CoreosComV1) GetPrometheusRule(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.PrometheusRule, error) {
	result, err := c.backend.Get(ctx, "prometheusrules", namespace, name, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRule), nil
}

func (c *CoreosComV1) CreatePrometheusRule(ctx context.Context, v *monitoringv1.PrometheusRule, opts metav1.CreateOptions) (*monitoringv1.PrometheusRule, error) {
	result, err := c.backend.Create(ctx, "prometheusrules", v, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRule), nil
}

func (c *CoreosComV1) UpdatePrometheusRule(ctx context.Context, v *monitoringv1.PrometheusRule, opts metav1.UpdateOptions) (*monitoringv1.PrometheusRule, error) {
	result, err := c.backend.Update(ctx, "prometheusrules", v, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRule), nil
}

func (c *CoreosComV1) DeletePrometheusRule(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "prometheusrules"}, namespace, name, opts)
}

func (c *CoreosComV1) ListPrometheusRule(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.PrometheusRuleList, error) {
	result, err := c.backend.List(ctx, "prometheusrules", namespace, opts, &monitoringv1.PrometheusRule{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.PrometheusRuleList), nil
}

func (c *CoreosComV1) WatchPrometheusRule(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "prometheusrules"}, namespace, opts)
}

func (c *CoreosComV1) GetServiceMonitor(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.ServiceMonitor, error) {
	result, err := c.backend.Get(ctx, "servicemonitors", namespace, name, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitor), nil
}

func (c *CoreosComV1) CreateServiceMonitor(ctx context.Context, v *monitoringv1.ServiceMonitor, opts metav1.CreateOptions) (*monitoringv1.ServiceMonitor, error) {
	result, err := c.backend.Create(ctx, "servicemonitors", v, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitor), nil
}

func (c *CoreosComV1) UpdateServiceMonitor(ctx context.Context, v *monitoringv1.ServiceMonitor, opts metav1.UpdateOptions) (*monitoringv1.ServiceMonitor, error) {
	result, err := c.backend.Update(ctx, "servicemonitors", v, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitor), nil
}

func (c *CoreosComV1) DeleteServiceMonitor(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "servicemonitors"}, namespace, name, opts)
}

func (c *CoreosComV1) ListServiceMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.ServiceMonitorList, error) {
	result, err := c.backend.List(ctx, "servicemonitors", namespace, opts, &monitoringv1.ServiceMonitor{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ServiceMonitorList), nil
}

func (c *CoreosComV1) WatchServiceMonitor(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "servicemonitors"}, namespace, opts)
}

func (c *CoreosComV1) GetThanosRuler(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.Get(ctx, "thanosrulers", namespace, name, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreosComV1) CreateThanosRuler(ctx context.Context, v *monitoringv1.ThanosRuler, opts metav1.CreateOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.Create(ctx, "thanosrulers", v, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreosComV1) UpdateThanosRuler(ctx context.Context, v *monitoringv1.ThanosRuler, opts metav1.UpdateOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.Update(ctx, "thanosrulers", v, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreosComV1) UpdateStatusThanosRuler(ctx context.Context, v *monitoringv1.ThanosRuler, opts metav1.UpdateOptions) (*monitoringv1.ThanosRuler, error) {
	result, err := c.backend.UpdateStatus(ctx, "thanosrulers", v, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRuler), nil
}

func (c *CoreosComV1) DeleteThanosRuler(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "thanosrulers"}, namespace, name, opts)
}

func (c *CoreosComV1) ListThanosRuler(ctx context.Context, namespace string, opts metav1.ListOptions) (*monitoringv1.ThanosRulerList, error) {
	result, err := c.backend.List(ctx, "thanosrulers", namespace, opts, &monitoringv1.ThanosRuler{})
	if err != nil {
		return nil, err
	}
	return result.(*monitoringv1.ThanosRulerList), nil
}

func (c *CoreosComV1) WatchThanosRuler(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "coreos.com.monitoring", Version: "v1", Resource: "thanosrulers"}, namespace, opts)
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
	case *certmanagerv1.Certificate:
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).CertificateInformer()
	case *certmanagerv1.CertificateRequest:
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).CertificateRequestInformer()
	case *certmanagerv1.ClusterIssuer:
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).ClusterIssuerInformer()
	case *certmanagerv1.Issuer:
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).IssuerInformer()
	case *monitoringv1.Alertmanager:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).AlertmanagerInformer()
	case *monitoringv1.PodMonitor:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).PodMonitorInformer()
	case *monitoringv1.Probe:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).ProbeInformer()
	case *monitoringv1.Prometheus:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).PrometheusInformer()
	case *monitoringv1.PrometheusRule:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).PrometheusRuleInformer()
	case *monitoringv1.ServiceMonitor:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).ServiceMonitorInformer()
	case *monitoringv1.ThanosRuler:
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).ThanosRulerInformer()
	default:
		return nil
	}
}

func (f *InformerFactory) InformerForResource(gvr schema.GroupVersionResource) cache.SharedIndexInformer {
	switch gvr {
	case certmanagerv1.SchemaGroupVersion.WithResource("certificates"):
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).CertificateInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("certificaterequests"):
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).CertificateRequestInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("clusterissuers"):
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).ClusterIssuerInformer()
	case certmanagerv1.SchemaGroupVersion.WithResource("issuers"):
		return NewCertManagerIoV1Informer(f.cache, f.set.CertManagerIoV1, f.namespace, f.resyncPeriod).IssuerInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("alertmanagers"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).AlertmanagerInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("podmonitors"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).PodMonitorInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("probes"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).ProbeInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("prometheuses"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).PrometheusInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("prometheusrules"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).PrometheusRuleInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("servicemonitors"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).ServiceMonitorInformer()
	case monitoringv1.SchemaGroupVersion.WithResource("thanosrulers"):
		return NewCoreosComV1Informer(f.cache, f.set.CoreosComV1, f.namespace, f.resyncPeriod).ThanosRulerInformer()
	default:
		return nil
	}
}

func (f *InformerFactory) Run(ctx context.Context) {
	for _, v := range f.cache.Informers() {
		go v.Run(ctx.Done())
	}
}

type CertManagerIoV1Informer struct {
	cache        *InformerCache
	client       *CertManagerIoV1
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewCertManagerIoV1Informer(c *InformerCache, client *CertManagerIoV1, namespace string, resyncPeriod time.Duration) *CertManagerIoV1Informer {
	return &CertManagerIoV1Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *CertManagerIoV1Informer) CertificateInformer() cache.SharedIndexInformer {
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

func (f *CertManagerIoV1Informer) CertificateLister() *CertManagerIoV1CertificateLister {
	return NewCertManagerIoV1CertificateLister(f.CertificateInformer().GetIndexer())
}

func (f *CertManagerIoV1Informer) CertificateRequestInformer() cache.SharedIndexInformer {
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

func (f *CertManagerIoV1Informer) CertificateRequestLister() *CertManagerIoV1CertificateRequestLister {
	return NewCertManagerIoV1CertificateRequestLister(f.CertificateRequestInformer().GetIndexer())
}

func (f *CertManagerIoV1Informer) ClusterIssuerInformer() cache.SharedIndexInformer {
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

func (f *CertManagerIoV1Informer) ClusterIssuerLister() *CertManagerIoV1ClusterIssuerLister {
	return NewCertManagerIoV1ClusterIssuerLister(f.ClusterIssuerInformer().GetIndexer())
}

func (f *CertManagerIoV1Informer) IssuerInformer() cache.SharedIndexInformer {
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

func (f *CertManagerIoV1Informer) IssuerLister() *CertManagerIoV1IssuerLister {
	return NewCertManagerIoV1IssuerLister(f.IssuerInformer().GetIndexer())
}

type CoreosComV1Informer struct {
	cache        *InformerCache
	client       *CoreosComV1
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewCoreosComV1Informer(c *InformerCache, client *CoreosComV1, namespace string, resyncPeriod time.Duration) *CoreosComV1Informer {
	return &CoreosComV1Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *CoreosComV1Informer) AlertmanagerInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) AlertmanagerLister() *CoreosComV1AlertmanagerLister {
	return NewCoreosComV1AlertmanagerLister(f.AlertmanagerInformer().GetIndexer())
}

func (f *CoreosComV1Informer) PodMonitorInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) PodMonitorLister() *CoreosComV1PodMonitorLister {
	return NewCoreosComV1PodMonitorLister(f.PodMonitorInformer().GetIndexer())
}

func (f *CoreosComV1Informer) ProbeInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) ProbeLister() *CoreosComV1ProbeLister {
	return NewCoreosComV1ProbeLister(f.ProbeInformer().GetIndexer())
}

func (f *CoreosComV1Informer) PrometheusInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) PrometheusLister() *CoreosComV1PrometheusLister {
	return NewCoreosComV1PrometheusLister(f.PrometheusInformer().GetIndexer())
}

func (f *CoreosComV1Informer) PrometheusRuleInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) PrometheusRuleLister() *CoreosComV1PrometheusRuleLister {
	return NewCoreosComV1PrometheusRuleLister(f.PrometheusRuleInformer().GetIndexer())
}

func (f *CoreosComV1Informer) ServiceMonitorInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) ServiceMonitorLister() *CoreosComV1ServiceMonitorLister {
	return NewCoreosComV1ServiceMonitorLister(f.ServiceMonitorInformer().GetIndexer())
}

func (f *CoreosComV1Informer) ThanosRulerInformer() cache.SharedIndexInformer {
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

func (f *CoreosComV1Informer) ThanosRulerLister() *CoreosComV1ThanosRulerLister {
	return NewCoreosComV1ThanosRulerLister(f.ThanosRulerInformer().GetIndexer())
}

type CertManagerIoV1CertificateLister struct {
	indexer cache.Indexer
}

func NewCertManagerIoV1CertificateLister(indexer cache.Indexer) *CertManagerIoV1CertificateLister {
	return &CertManagerIoV1CertificateLister{indexer: indexer}
}

func (x *CertManagerIoV1CertificateLister) List(namespace string, selector labels.Selector) ([]*certmanagerv1.Certificate, error) {
	var ret []*certmanagerv1.Certificate
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.Certificate).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerIoV1CertificateLister) Get(namespace, name string) (*certmanagerv1.Certificate, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("certificate").GroupResource(), name)
	}
	return obj.(*certmanagerv1.Certificate).DeepCopy(), nil
}

type CertManagerIoV1CertificateRequestLister struct {
	indexer cache.Indexer
}

func NewCertManagerIoV1CertificateRequestLister(indexer cache.Indexer) *CertManagerIoV1CertificateRequestLister {
	return &CertManagerIoV1CertificateRequestLister{indexer: indexer}
}

func (x *CertManagerIoV1CertificateRequestLister) List(namespace string, selector labels.Selector) ([]*certmanagerv1.CertificateRequest, error) {
	var ret []*certmanagerv1.CertificateRequest
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.CertificateRequest).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerIoV1CertificateRequestLister) Get(namespace, name string) (*certmanagerv1.CertificateRequest, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("certificaterequest").GroupResource(), name)
	}
	return obj.(*certmanagerv1.CertificateRequest).DeepCopy(), nil
}

type CertManagerIoV1ClusterIssuerLister struct {
	indexer cache.Indexer
}

func NewCertManagerIoV1ClusterIssuerLister(indexer cache.Indexer) *CertManagerIoV1ClusterIssuerLister {
	return &CertManagerIoV1ClusterIssuerLister{indexer: indexer}
}

func (x *CertManagerIoV1ClusterIssuerLister) List(selector labels.Selector) ([]*certmanagerv1.ClusterIssuer, error) {
	var ret []*certmanagerv1.ClusterIssuer
	err := cache.ListAll(x.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.ClusterIssuer).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerIoV1ClusterIssuerLister) Get(name string) (*certmanagerv1.ClusterIssuer, error) {
	obj, exists, err := x.indexer.GetByKey("/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("clusterissuer").GroupResource(), name)
	}
	return obj.(*certmanagerv1.ClusterIssuer).DeepCopy(), nil
}

type CertManagerIoV1IssuerLister struct {
	indexer cache.Indexer
}

func NewCertManagerIoV1IssuerLister(indexer cache.Indexer) *CertManagerIoV1IssuerLister {
	return &CertManagerIoV1IssuerLister{indexer: indexer}
}

func (x *CertManagerIoV1IssuerLister) List(namespace string, selector labels.Selector) ([]*certmanagerv1.Issuer, error) {
	var ret []*certmanagerv1.Issuer
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*certmanagerv1.Issuer).DeepCopy())
	})
	return ret, err
}

func (x *CertManagerIoV1IssuerLister) Get(namespace, name string) (*certmanagerv1.Issuer, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(certmanagerv1.SchemaGroupVersion.WithResource("issuer").GroupResource(), name)
	}
	return obj.(*certmanagerv1.Issuer).DeepCopy(), nil
}

type CoreosComV1AlertmanagerLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1AlertmanagerLister(indexer cache.Indexer) *CoreosComV1AlertmanagerLister {
	return &CoreosComV1AlertmanagerLister{indexer: indexer}
}

func (x *CoreosComV1AlertmanagerLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.Alertmanager, error) {
	var ret []*monitoringv1.Alertmanager
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.Alertmanager).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1AlertmanagerLister) Get(namespace, name string) (*monitoringv1.Alertmanager, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("alertmanager").GroupResource(), name)
	}
	return obj.(*monitoringv1.Alertmanager).DeepCopy(), nil
}

type CoreosComV1PodMonitorLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1PodMonitorLister(indexer cache.Indexer) *CoreosComV1PodMonitorLister {
	return &CoreosComV1PodMonitorLister{indexer: indexer}
}

func (x *CoreosComV1PodMonitorLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.PodMonitor, error) {
	var ret []*monitoringv1.PodMonitor
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.PodMonitor).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1PodMonitorLister) Get(namespace, name string) (*monitoringv1.PodMonitor, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("podmonitor").GroupResource(), name)
	}
	return obj.(*monitoringv1.PodMonitor).DeepCopy(), nil
}

type CoreosComV1ProbeLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1ProbeLister(indexer cache.Indexer) *CoreosComV1ProbeLister {
	return &CoreosComV1ProbeLister{indexer: indexer}
}

func (x *CoreosComV1ProbeLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.Probe, error) {
	var ret []*monitoringv1.Probe
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.Probe).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1ProbeLister) Get(namespace, name string) (*monitoringv1.Probe, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("probe").GroupResource(), name)
	}
	return obj.(*monitoringv1.Probe).DeepCopy(), nil
}

type CoreosComV1PrometheusLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1PrometheusLister(indexer cache.Indexer) *CoreosComV1PrometheusLister {
	return &CoreosComV1PrometheusLister{indexer: indexer}
}

func (x *CoreosComV1PrometheusLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.Prometheus, error) {
	var ret []*monitoringv1.Prometheus
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.Prometheus).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1PrometheusLister) Get(namespace, name string) (*monitoringv1.Prometheus, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("prometheus").GroupResource(), name)
	}
	return obj.(*monitoringv1.Prometheus).DeepCopy(), nil
}

type CoreosComV1PrometheusRuleLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1PrometheusRuleLister(indexer cache.Indexer) *CoreosComV1PrometheusRuleLister {
	return &CoreosComV1PrometheusRuleLister{indexer: indexer}
}

func (x *CoreosComV1PrometheusRuleLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.PrometheusRule, error) {
	var ret []*monitoringv1.PrometheusRule
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.PrometheusRule).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1PrometheusRuleLister) Get(namespace, name string) (*monitoringv1.PrometheusRule, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("prometheusrule").GroupResource(), name)
	}
	return obj.(*monitoringv1.PrometheusRule).DeepCopy(), nil
}

type CoreosComV1ServiceMonitorLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1ServiceMonitorLister(indexer cache.Indexer) *CoreosComV1ServiceMonitorLister {
	return &CoreosComV1ServiceMonitorLister{indexer: indexer}
}

func (x *CoreosComV1ServiceMonitorLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.ServiceMonitor, error) {
	var ret []*monitoringv1.ServiceMonitor
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.ServiceMonitor).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1ServiceMonitorLister) Get(namespace, name string) (*monitoringv1.ServiceMonitor, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("servicemonitor").GroupResource(), name)
	}
	return obj.(*monitoringv1.ServiceMonitor).DeepCopy(), nil
}

type CoreosComV1ThanosRulerLister struct {
	indexer cache.Indexer
}

func NewCoreosComV1ThanosRulerLister(indexer cache.Indexer) *CoreosComV1ThanosRulerLister {
	return &CoreosComV1ThanosRulerLister{indexer: indexer}
}

func (x *CoreosComV1ThanosRulerLister) List(namespace string, selector labels.Selector) ([]*monitoringv1.ThanosRuler, error) {
	var ret []*monitoringv1.ThanosRuler
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*monitoringv1.ThanosRuler).DeepCopy())
	})
	return ret, err
}

func (x *CoreosComV1ThanosRulerLister) Get(namespace, name string) (*monitoringv1.ThanosRuler, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(monitoringv1.SchemaGroupVersion.WithResource("thanosruler").GroupResource(), name)
	}
	return obj.(*monitoringv1.ThanosRuler).DeepCopy(), nil
}
