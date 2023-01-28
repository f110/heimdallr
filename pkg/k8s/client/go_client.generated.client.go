package client

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha1"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha1"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
)

var (
	Scheme         = runtime.NewScheme()
	ParameterCodec = runtime.NewParameterCodec(Scheme)
	Codecs         = serializer.NewCodecFactory(Scheme)
	AddToScheme    = localSchemeBuilder.AddToScheme
)

var localSchemeBuilder = runtime.SchemeBuilder{
	etcdv1alpha1.AddToScheme,
	etcdv1alpha2.AddToScheme,
	proxyv1alpha1.AddToScheme,
	proxyv1alpha2.AddToScheme,
}

func init() {
	for _, v := range []func(*runtime.Scheme) error{
		etcdv1alpha1.AddToScheme,
		etcdv1alpha2.AddToScheme,
		proxyv1alpha1.AddToScheme,
		proxyv1alpha2.AddToScheme,
	} {
		if err := v(Scheme); err != nil {
			panic(err)
		}
	}
}

type Backend interface {
	Get(ctx context.Context, resourceName, kindName, namespace, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error)
	List(ctx context.Context, resourceName, kindName, namespace string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error)
	Create(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error)
	Update(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	UpdateStatus(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	Delete(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string, opts metav1.DeleteOptions) error
	Watch(ctx context.Context, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) (watch.Interface, error)
	GetClusterScoped(ctx context.Context, resourceName, kindName, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error)
	ListClusterScoped(ctx context.Context, resourceName, kindName string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error)
	CreateClusterScoped(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error)
	UpdateClusterScoped(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	UpdateStatusClusterScoped(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error)
	DeleteClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, name string, opts metav1.DeleteOptions) error
	WatchClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error)
}
type Set struct {
	EtcdV1alpha1  *EtcdV1alpha1
	EtcdV1alpha2  *EtcdV1alpha2
	ProxyV1alpha1 *ProxyV1alpha1
	ProxyV1alpha2 *ProxyV1alpha2
}

func NewSet(cfg *rest.Config) (*Set, error) {
	s := &Set{}
	{
		conf := *cfg
		conf.GroupVersion = &etcdv1alpha1.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.EtcdV1alpha1 = NewEtcdV1alpha1Client(&restBackend{client: c})
	}
	{
		conf := *cfg
		conf.GroupVersion = &etcdv1alpha2.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.EtcdV1alpha2 = NewEtcdV1alpha2Client(&restBackend{client: c})
	}
	{
		conf := *cfg
		conf.GroupVersion = &proxyv1alpha1.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.ProxyV1alpha1 = NewProxyV1alpha1Client(&restBackend{client: c})
	}
	{
		conf := *cfg
		conf.GroupVersion = &proxyv1alpha2.SchemaGroupVersion
		conf.APIPath = "/apis"
		conf.NegotiatedSerializer = Codecs.WithoutConversion()
		c, err := rest.RESTClientFor(&conf)
		if err != nil {
			return nil, err
		}
		s.ProxyV1alpha2 = NewProxyV1alpha2Client(&restBackend{client: c})
	}

	return s, nil
}

type restBackend struct {
	client *rest.RESTClient
}

func (r *restBackend) Get(ctx context.Context, resourceName, kindName, namespace, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error) {
	return result, r.client.Get().
		Namespace(namespace).
		Resource(resourceName).
		Name(name).
		VersionedParams(&opts, ParameterCodec).
		Do(ctx).
		Into(result)
}

func (r *restBackend) List(ctx context.Context, resourceName, kindName, namespace string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	return result, r.client.Get().
		Namespace(namespace).
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
}

func (r *restBackend) Create(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	return result, r.client.Post().
		Namespace(m.GetNamespace()).
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) Update(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	return result, r.client.Put().
		Namespace(m.GetNamespace()).
		Resource(resourceName).
		Name(m.GetName()).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) UpdateStatus(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	return result, r.client.Put().
		Namespace(m.GetNamespace()).
		Resource(resourceName).
		Name(m.GetName()).
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
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return r.client.Get().
		Namespace(namespace).
		Resource(gvr.Resource).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

func (r *restBackend) GetClusterScoped(ctx context.Context, resourceName, kindName, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error) {
	return result, r.client.Get().
		Resource(resourceName).
		Name(name).
		VersionedParams(&opts, ParameterCodec).
		Do(ctx).
		Into(result)
}

func (r *restBackend) ListClusterScoped(ctx context.Context, resourceName, kindName string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	return result, r.client.Get().
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
}

func (r *restBackend) CreateClusterScoped(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error) {
	return result, r.client.Post().
		Resource(resourceName).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) UpdateClusterScoped(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	return result, r.client.Put().
		Resource(resourceName).
		Name(m.GetName()).
		VersionedParams(&opts, ParameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
}

func (r *restBackend) UpdateStatusClusterScoped(ctx context.Context, resourceName, kindName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	m := obj.(metav1.Object)
	if m == nil {
		return nil, errors.New("obj is not implement metav1.Object")
	}
	return result, r.client.Put().
		Resource(resourceName).
		Name(m.GetName()).
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
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return r.client.Get().
		Resource(gvr.Resource).
		VersionedParams(&opts, ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

type EtcdV1alpha1 struct {
	backend Backend
}

func NewEtcdV1alpha1Client(b Backend) *EtcdV1alpha1 {
	return &EtcdV1alpha1{backend: b}
}

func (c *EtcdV1alpha1) GetEtcdCluster(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*etcdv1alpha1.EtcdCluster, error) {
	result, err := c.backend.Get(ctx, "etcdclusters", "EtcdCluster", namespace, name, opts, &etcdv1alpha1.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha1.EtcdCluster), nil
}

func (c *EtcdV1alpha1) CreateEtcdCluster(ctx context.Context, v *etcdv1alpha1.EtcdCluster, opts metav1.CreateOptions) (*etcdv1alpha1.EtcdCluster, error) {
	result, err := c.backend.Create(ctx, "etcdclusters", "EtcdCluster", v, opts, &etcdv1alpha1.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha1.EtcdCluster), nil
}

func (c *EtcdV1alpha1) UpdateEtcdCluster(ctx context.Context, v *etcdv1alpha1.EtcdCluster, opts metav1.UpdateOptions) (*etcdv1alpha1.EtcdCluster, error) {
	result, err := c.backend.Update(ctx, "etcdclusters", "EtcdCluster", v, opts, &etcdv1alpha1.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha1.EtcdCluster), nil
}

func (c *EtcdV1alpha1) UpdateStatusEtcdCluster(ctx context.Context, v *etcdv1alpha1.EtcdCluster, opts metav1.UpdateOptions) (*etcdv1alpha1.EtcdCluster, error) {
	result, err := c.backend.UpdateStatus(ctx, "etcdclusters", "EtcdCluster", v, opts, &etcdv1alpha1.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha1.EtcdCluster), nil
}

func (c *EtcdV1alpha1) DeleteEtcdCluster(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "etcd.f110.dev", Version: "v1alpha1", Resource: "etcdclusters"}, namespace, name, opts)
}

func (c *EtcdV1alpha1) ListEtcdCluster(ctx context.Context, namespace string, opts metav1.ListOptions) (*etcdv1alpha1.EtcdClusterList, error) {
	result, err := c.backend.List(ctx, "etcdclusters", "EtcdCluster", namespace, opts, &etcdv1alpha1.EtcdClusterList{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha1.EtcdClusterList), nil
}

func (c *EtcdV1alpha1) WatchEtcdCluster(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "etcd.f110.dev", Version: "v1alpha1", Resource: "etcdclusters"}, namespace, opts)
}

type EtcdV1alpha2 struct {
	backend Backend
}

func NewEtcdV1alpha2Client(b Backend) *EtcdV1alpha2 {
	return &EtcdV1alpha2{backend: b}
}

func (c *EtcdV1alpha2) GetEtcdCluster(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*etcdv1alpha2.EtcdCluster, error) {
	result, err := c.backend.Get(ctx, "etcdclusters", "EtcdCluster", namespace, name, opts, &etcdv1alpha2.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha2.EtcdCluster), nil
}

func (c *EtcdV1alpha2) CreateEtcdCluster(ctx context.Context, v *etcdv1alpha2.EtcdCluster, opts metav1.CreateOptions) (*etcdv1alpha2.EtcdCluster, error) {
	result, err := c.backend.Create(ctx, "etcdclusters", "EtcdCluster", v, opts, &etcdv1alpha2.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha2.EtcdCluster), nil
}

func (c *EtcdV1alpha2) UpdateEtcdCluster(ctx context.Context, v *etcdv1alpha2.EtcdCluster, opts metav1.UpdateOptions) (*etcdv1alpha2.EtcdCluster, error) {
	result, err := c.backend.Update(ctx, "etcdclusters", "EtcdCluster", v, opts, &etcdv1alpha2.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha2.EtcdCluster), nil
}

func (c *EtcdV1alpha2) UpdateStatusEtcdCluster(ctx context.Context, v *etcdv1alpha2.EtcdCluster, opts metav1.UpdateOptions) (*etcdv1alpha2.EtcdCluster, error) {
	result, err := c.backend.UpdateStatus(ctx, "etcdclusters", "EtcdCluster", v, opts, &etcdv1alpha2.EtcdCluster{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha2.EtcdCluster), nil
}

func (c *EtcdV1alpha2) DeleteEtcdCluster(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "etcd.f110.dev", Version: "v1alpha2", Resource: "etcdclusters"}, namespace, name, opts)
}

func (c *EtcdV1alpha2) ListEtcdCluster(ctx context.Context, namespace string, opts metav1.ListOptions) (*etcdv1alpha2.EtcdClusterList, error) {
	result, err := c.backend.List(ctx, "etcdclusters", "EtcdCluster", namespace, opts, &etcdv1alpha2.EtcdClusterList{})
	if err != nil {
		return nil, err
	}
	return result.(*etcdv1alpha2.EtcdClusterList), nil
}

func (c *EtcdV1alpha2) WatchEtcdCluster(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "etcd.f110.dev", Version: "v1alpha2", Resource: "etcdclusters"}, namespace, opts)
}

type ProxyV1alpha1 struct {
	backend Backend
}

func NewProxyV1alpha1Client(b Backend) *ProxyV1alpha1 {
	return &ProxyV1alpha1{backend: b}
}

func (c *ProxyV1alpha1) GetBackend(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha1.Backend, error) {
	result, err := c.backend.Get(ctx, "backends", "Backend", namespace, name, opts, &proxyv1alpha1.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Backend), nil
}

func (c *ProxyV1alpha1) CreateBackend(ctx context.Context, v *proxyv1alpha1.Backend, opts metav1.CreateOptions) (*proxyv1alpha1.Backend, error) {
	result, err := c.backend.Create(ctx, "backends", "Backend", v, opts, &proxyv1alpha1.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Backend), nil
}

func (c *ProxyV1alpha1) UpdateBackend(ctx context.Context, v *proxyv1alpha1.Backend, opts metav1.UpdateOptions) (*proxyv1alpha1.Backend, error) {
	result, err := c.backend.Update(ctx, "backends", "Backend", v, opts, &proxyv1alpha1.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Backend), nil
}

func (c *ProxyV1alpha1) UpdateStatusBackend(ctx context.Context, v *proxyv1alpha1.Backend, opts metav1.UpdateOptions) (*proxyv1alpha1.Backend, error) {
	result, err := c.backend.UpdateStatus(ctx, "backends", "Backend", v, opts, &proxyv1alpha1.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Backend), nil
}

func (c *ProxyV1alpha1) DeleteBackend(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "backends"}, namespace, name, opts)
}

func (c *ProxyV1alpha1) ListBackend(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha1.BackendList, error) {
	result, err := c.backend.List(ctx, "backends", "Backend", namespace, opts, &proxyv1alpha1.BackendList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.BackendList), nil
}

func (c *ProxyV1alpha1) WatchBackend(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "backends"}, namespace, opts)
}

func (c *ProxyV1alpha1) GetProxy(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha1.Proxy, error) {
	result, err := c.backend.Get(ctx, "proxies", "Proxy", namespace, name, opts, &proxyv1alpha1.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Proxy), nil
}

func (c *ProxyV1alpha1) CreateProxy(ctx context.Context, v *proxyv1alpha1.Proxy, opts metav1.CreateOptions) (*proxyv1alpha1.Proxy, error) {
	result, err := c.backend.Create(ctx, "proxies", "Proxy", v, opts, &proxyv1alpha1.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Proxy), nil
}

func (c *ProxyV1alpha1) UpdateProxy(ctx context.Context, v *proxyv1alpha1.Proxy, opts metav1.UpdateOptions) (*proxyv1alpha1.Proxy, error) {
	result, err := c.backend.Update(ctx, "proxies", "Proxy", v, opts, &proxyv1alpha1.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Proxy), nil
}

func (c *ProxyV1alpha1) UpdateStatusProxy(ctx context.Context, v *proxyv1alpha1.Proxy, opts metav1.UpdateOptions) (*proxyv1alpha1.Proxy, error) {
	result, err := c.backend.UpdateStatus(ctx, "proxies", "Proxy", v, opts, &proxyv1alpha1.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Proxy), nil
}

func (c *ProxyV1alpha1) DeleteProxy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "proxies"}, namespace, name, opts)
}

func (c *ProxyV1alpha1) ListProxy(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha1.ProxyList, error) {
	result, err := c.backend.List(ctx, "proxies", "Proxy", namespace, opts, &proxyv1alpha1.ProxyList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.ProxyList), nil
}

func (c *ProxyV1alpha1) WatchProxy(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "proxies"}, namespace, opts)
}

func (c *ProxyV1alpha1) GetRole(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha1.Role, error) {
	result, err := c.backend.Get(ctx, "roles", "Role", namespace, name, opts, &proxyv1alpha1.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Role), nil
}

func (c *ProxyV1alpha1) CreateRole(ctx context.Context, v *proxyv1alpha1.Role, opts metav1.CreateOptions) (*proxyv1alpha1.Role, error) {
	result, err := c.backend.Create(ctx, "roles", "Role", v, opts, &proxyv1alpha1.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Role), nil
}

func (c *ProxyV1alpha1) UpdateRole(ctx context.Context, v *proxyv1alpha1.Role, opts metav1.UpdateOptions) (*proxyv1alpha1.Role, error) {
	result, err := c.backend.Update(ctx, "roles", "Role", v, opts, &proxyv1alpha1.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Role), nil
}

func (c *ProxyV1alpha1) UpdateStatusRole(ctx context.Context, v *proxyv1alpha1.Role, opts metav1.UpdateOptions) (*proxyv1alpha1.Role, error) {
	result, err := c.backend.UpdateStatus(ctx, "roles", "Role", v, opts, &proxyv1alpha1.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.Role), nil
}

func (c *ProxyV1alpha1) DeleteRole(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "roles"}, namespace, name, opts)
}

func (c *ProxyV1alpha1) ListRole(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha1.RoleList, error) {
	result, err := c.backend.List(ctx, "roles", "Role", namespace, opts, &proxyv1alpha1.RoleList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RoleList), nil
}

func (c *ProxyV1alpha1) WatchRole(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "roles"}, namespace, opts)
}

func (c *ProxyV1alpha1) GetRoleBinding(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha1.RoleBinding, error) {
	result, err := c.backend.Get(ctx, "rolebindings", "RoleBinding", namespace, name, opts, &proxyv1alpha1.RoleBinding{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RoleBinding), nil
}

func (c *ProxyV1alpha1) CreateRoleBinding(ctx context.Context, v *proxyv1alpha1.RoleBinding, opts metav1.CreateOptions) (*proxyv1alpha1.RoleBinding, error) {
	result, err := c.backend.Create(ctx, "rolebindings", "RoleBinding", v, opts, &proxyv1alpha1.RoleBinding{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RoleBinding), nil
}

func (c *ProxyV1alpha1) UpdateRoleBinding(ctx context.Context, v *proxyv1alpha1.RoleBinding, opts metav1.UpdateOptions) (*proxyv1alpha1.RoleBinding, error) {
	result, err := c.backend.Update(ctx, "rolebindings", "RoleBinding", v, opts, &proxyv1alpha1.RoleBinding{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RoleBinding), nil
}

func (c *ProxyV1alpha1) DeleteRoleBinding(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "rolebindings"}, namespace, name, opts)
}

func (c *ProxyV1alpha1) ListRoleBinding(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha1.RoleBindingList, error) {
	result, err := c.backend.List(ctx, "rolebindings", "RoleBinding", namespace, opts, &proxyv1alpha1.RoleBindingList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RoleBindingList), nil
}

func (c *ProxyV1alpha1) WatchRoleBinding(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "rolebindings"}, namespace, opts)
}

func (c *ProxyV1alpha1) GetRpcPermission(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha1.RpcPermission, error) {
	result, err := c.backend.Get(ctx, "rpcpermissions", "RpcPermission", namespace, name, opts, &proxyv1alpha1.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RpcPermission), nil
}

func (c *ProxyV1alpha1) CreateRpcPermission(ctx context.Context, v *proxyv1alpha1.RpcPermission, opts metav1.CreateOptions) (*proxyv1alpha1.RpcPermission, error) {
	result, err := c.backend.Create(ctx, "rpcpermissions", "RpcPermission", v, opts, &proxyv1alpha1.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RpcPermission), nil
}

func (c *ProxyV1alpha1) UpdateRpcPermission(ctx context.Context, v *proxyv1alpha1.RpcPermission, opts metav1.UpdateOptions) (*proxyv1alpha1.RpcPermission, error) {
	result, err := c.backend.Update(ctx, "rpcpermissions", "RpcPermission", v, opts, &proxyv1alpha1.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RpcPermission), nil
}

func (c *ProxyV1alpha1) DeleteRpcPermission(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "rpcpermissions"}, namespace, name, opts)
}

func (c *ProxyV1alpha1) ListRpcPermission(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha1.RpcPermissionList, error) {
	result, err := c.backend.List(ctx, "rpcpermissions", "RpcPermission", namespace, opts, &proxyv1alpha1.RpcPermissionList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha1.RpcPermissionList), nil
}

func (c *ProxyV1alpha1) WatchRpcPermission(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha1", Resource: "rpcpermissions"}, namespace, opts)
}

type ProxyV1alpha2 struct {
	backend Backend
}

func NewProxyV1alpha2Client(b Backend) *ProxyV1alpha2 {
	return &ProxyV1alpha2{backend: b}
}

func (c *ProxyV1alpha2) GetBackend(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha2.Backend, error) {
	result, err := c.backend.Get(ctx, "backends", "Backend", namespace, name, opts, &proxyv1alpha2.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Backend), nil
}

func (c *ProxyV1alpha2) CreateBackend(ctx context.Context, v *proxyv1alpha2.Backend, opts metav1.CreateOptions) (*proxyv1alpha2.Backend, error) {
	result, err := c.backend.Create(ctx, "backends", "Backend", v, opts, &proxyv1alpha2.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Backend), nil
}

func (c *ProxyV1alpha2) UpdateBackend(ctx context.Context, v *proxyv1alpha2.Backend, opts metav1.UpdateOptions) (*proxyv1alpha2.Backend, error) {
	result, err := c.backend.Update(ctx, "backends", "Backend", v, opts, &proxyv1alpha2.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Backend), nil
}

func (c *ProxyV1alpha2) UpdateStatusBackend(ctx context.Context, v *proxyv1alpha2.Backend, opts metav1.UpdateOptions) (*proxyv1alpha2.Backend, error) {
	result, err := c.backend.UpdateStatus(ctx, "backends", "Backend", v, opts, &proxyv1alpha2.Backend{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Backend), nil
}

func (c *ProxyV1alpha2) DeleteBackend(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "backends"}, namespace, name, opts)
}

func (c *ProxyV1alpha2) ListBackend(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha2.BackendList, error) {
	result, err := c.backend.List(ctx, "backends", "Backend", namespace, opts, &proxyv1alpha2.BackendList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.BackendList), nil
}

func (c *ProxyV1alpha2) WatchBackend(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "backends"}, namespace, opts)
}

func (c *ProxyV1alpha2) GetProxy(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha2.Proxy, error) {
	result, err := c.backend.Get(ctx, "proxies", "Proxy", namespace, name, opts, &proxyv1alpha2.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Proxy), nil
}

func (c *ProxyV1alpha2) CreateProxy(ctx context.Context, v *proxyv1alpha2.Proxy, opts metav1.CreateOptions) (*proxyv1alpha2.Proxy, error) {
	result, err := c.backend.Create(ctx, "proxies", "Proxy", v, opts, &proxyv1alpha2.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Proxy), nil
}

func (c *ProxyV1alpha2) UpdateProxy(ctx context.Context, v *proxyv1alpha2.Proxy, opts metav1.UpdateOptions) (*proxyv1alpha2.Proxy, error) {
	result, err := c.backend.Update(ctx, "proxies", "Proxy", v, opts, &proxyv1alpha2.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Proxy), nil
}

func (c *ProxyV1alpha2) UpdateStatusProxy(ctx context.Context, v *proxyv1alpha2.Proxy, opts metav1.UpdateOptions) (*proxyv1alpha2.Proxy, error) {
	result, err := c.backend.UpdateStatus(ctx, "proxies", "Proxy", v, opts, &proxyv1alpha2.Proxy{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Proxy), nil
}

func (c *ProxyV1alpha2) DeleteProxy(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "proxies"}, namespace, name, opts)
}

func (c *ProxyV1alpha2) ListProxy(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha2.ProxyList, error) {
	result, err := c.backend.List(ctx, "proxies", "Proxy", namespace, opts, &proxyv1alpha2.ProxyList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.ProxyList), nil
}

func (c *ProxyV1alpha2) WatchProxy(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "proxies"}, namespace, opts)
}

func (c *ProxyV1alpha2) GetRole(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha2.Role, error) {
	result, err := c.backend.Get(ctx, "roles", "Role", namespace, name, opts, &proxyv1alpha2.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Role), nil
}

func (c *ProxyV1alpha2) CreateRole(ctx context.Context, v *proxyv1alpha2.Role, opts metav1.CreateOptions) (*proxyv1alpha2.Role, error) {
	result, err := c.backend.Create(ctx, "roles", "Role", v, opts, &proxyv1alpha2.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Role), nil
}

func (c *ProxyV1alpha2) UpdateRole(ctx context.Context, v *proxyv1alpha2.Role, opts metav1.UpdateOptions) (*proxyv1alpha2.Role, error) {
	result, err := c.backend.Update(ctx, "roles", "Role", v, opts, &proxyv1alpha2.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Role), nil
}

func (c *ProxyV1alpha2) UpdateStatusRole(ctx context.Context, v *proxyv1alpha2.Role, opts metav1.UpdateOptions) (*proxyv1alpha2.Role, error) {
	result, err := c.backend.UpdateStatus(ctx, "roles", "Role", v, opts, &proxyv1alpha2.Role{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.Role), nil
}

func (c *ProxyV1alpha2) DeleteRole(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "roles"}, namespace, name, opts)
}

func (c *ProxyV1alpha2) ListRole(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha2.RoleList, error) {
	result, err := c.backend.List(ctx, "roles", "Role", namespace, opts, &proxyv1alpha2.RoleList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RoleList), nil
}

func (c *ProxyV1alpha2) WatchRole(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "roles"}, namespace, opts)
}

func (c *ProxyV1alpha2) GetRoleBinding(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha2.RoleBinding, error) {
	result, err := c.backend.Get(ctx, "rolebindings", "RoleBinding", namespace, name, opts, &proxyv1alpha2.RoleBinding{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RoleBinding), nil
}

func (c *ProxyV1alpha2) CreateRoleBinding(ctx context.Context, v *proxyv1alpha2.RoleBinding, opts metav1.CreateOptions) (*proxyv1alpha2.RoleBinding, error) {
	result, err := c.backend.Create(ctx, "rolebindings", "RoleBinding", v, opts, &proxyv1alpha2.RoleBinding{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RoleBinding), nil
}

func (c *ProxyV1alpha2) UpdateRoleBinding(ctx context.Context, v *proxyv1alpha2.RoleBinding, opts metav1.UpdateOptions) (*proxyv1alpha2.RoleBinding, error) {
	result, err := c.backend.Update(ctx, "rolebindings", "RoleBinding", v, opts, &proxyv1alpha2.RoleBinding{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RoleBinding), nil
}

func (c *ProxyV1alpha2) DeleteRoleBinding(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "rolebindings"}, namespace, name, opts)
}

func (c *ProxyV1alpha2) ListRoleBinding(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha2.RoleBindingList, error) {
	result, err := c.backend.List(ctx, "rolebindings", "RoleBinding", namespace, opts, &proxyv1alpha2.RoleBindingList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RoleBindingList), nil
}

func (c *ProxyV1alpha2) WatchRoleBinding(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "rolebindings"}, namespace, opts)
}

func (c *ProxyV1alpha2) GetRpcPermission(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*proxyv1alpha2.RpcPermission, error) {
	result, err := c.backend.Get(ctx, "rpcpermissions", "RpcPermission", namespace, name, opts, &proxyv1alpha2.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RpcPermission), nil
}

func (c *ProxyV1alpha2) CreateRpcPermission(ctx context.Context, v *proxyv1alpha2.RpcPermission, opts metav1.CreateOptions) (*proxyv1alpha2.RpcPermission, error) {
	result, err := c.backend.Create(ctx, "rpcpermissions", "RpcPermission", v, opts, &proxyv1alpha2.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RpcPermission), nil
}

func (c *ProxyV1alpha2) UpdateRpcPermission(ctx context.Context, v *proxyv1alpha2.RpcPermission, opts metav1.UpdateOptions) (*proxyv1alpha2.RpcPermission, error) {
	result, err := c.backend.Update(ctx, "rpcpermissions", "RpcPermission", v, opts, &proxyv1alpha2.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RpcPermission), nil
}

func (c *ProxyV1alpha2) UpdateStatusRpcPermission(ctx context.Context, v *proxyv1alpha2.RpcPermission, opts metav1.UpdateOptions) (*proxyv1alpha2.RpcPermission, error) {
	result, err := c.backend.UpdateStatus(ctx, "rpcpermissions", "RpcPermission", v, opts, &proxyv1alpha2.RpcPermission{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RpcPermission), nil
}

func (c *ProxyV1alpha2) DeleteRpcPermission(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.backend.Delete(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "rpcpermissions"}, namespace, name, opts)
}

func (c *ProxyV1alpha2) ListRpcPermission(ctx context.Context, namespace string, opts metav1.ListOptions) (*proxyv1alpha2.RpcPermissionList, error) {
	result, err := c.backend.List(ctx, "rpcpermissions", "RpcPermission", namespace, opts, &proxyv1alpha2.RpcPermissionList{})
	if err != nil {
		return nil, err
	}
	return result.(*proxyv1alpha2.RpcPermissionList), nil
}

func (c *ProxyV1alpha2) WatchRpcPermission(ctx context.Context, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.backend.Watch(ctx, schema.GroupVersionResource{Group: "proxy.f110.dev", Version: "v1alpha2", Resource: "rpcpermissions"}, namespace, opts)
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
	case *etcdv1alpha1.EtcdCluster:
		return NewEtcdV1alpha1Informer(f.cache, f.set.EtcdV1alpha1, f.namespace, f.resyncPeriod).EtcdClusterInformer()
	case *etcdv1alpha2.EtcdCluster:
		return NewEtcdV1alpha2Informer(f.cache, f.set.EtcdV1alpha2, f.namespace, f.resyncPeriod).EtcdClusterInformer()
	case *proxyv1alpha1.Backend:
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).BackendInformer()
	case *proxyv1alpha1.Proxy:
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).ProxyInformer()
	case *proxyv1alpha1.Role:
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).RoleInformer()
	case *proxyv1alpha1.RoleBinding:
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).RoleBindingInformer()
	case *proxyv1alpha1.RpcPermission:
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).RpcPermissionInformer()
	case *proxyv1alpha2.Backend:
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).BackendInformer()
	case *proxyv1alpha2.Proxy:
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).ProxyInformer()
	case *proxyv1alpha2.Role:
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).RoleInformer()
	case *proxyv1alpha2.RoleBinding:
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).RoleBindingInformer()
	case *proxyv1alpha2.RpcPermission:
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).RpcPermissionInformer()
	default:
		return nil
	}
}

func (f *InformerFactory) InformerForResource(gvr schema.GroupVersionResource) cache.SharedIndexInformer {
	switch gvr {
	case etcdv1alpha1.SchemaGroupVersion.WithResource("etcdclusters"):
		return NewEtcdV1alpha1Informer(f.cache, f.set.EtcdV1alpha1, f.namespace, f.resyncPeriod).EtcdClusterInformer()
	case etcdv1alpha2.SchemaGroupVersion.WithResource("etcdclusters"):
		return NewEtcdV1alpha2Informer(f.cache, f.set.EtcdV1alpha2, f.namespace, f.resyncPeriod).EtcdClusterInformer()
	case proxyv1alpha1.SchemaGroupVersion.WithResource("backends"):
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).BackendInformer()
	case proxyv1alpha1.SchemaGroupVersion.WithResource("proxies"):
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).ProxyInformer()
	case proxyv1alpha1.SchemaGroupVersion.WithResource("roles"):
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).RoleInformer()
	case proxyv1alpha1.SchemaGroupVersion.WithResource("rolebindings"):
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).RoleBindingInformer()
	case proxyv1alpha1.SchemaGroupVersion.WithResource("rpcpermissions"):
		return NewProxyV1alpha1Informer(f.cache, f.set.ProxyV1alpha1, f.namespace, f.resyncPeriod).RpcPermissionInformer()
	case proxyv1alpha2.SchemaGroupVersion.WithResource("backends"):
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).BackendInformer()
	case proxyv1alpha2.SchemaGroupVersion.WithResource("proxies"):
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).ProxyInformer()
	case proxyv1alpha2.SchemaGroupVersion.WithResource("roles"):
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).RoleInformer()
	case proxyv1alpha2.SchemaGroupVersion.WithResource("rolebindings"):
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).RoleBindingInformer()
	case proxyv1alpha2.SchemaGroupVersion.WithResource("rpcpermissions"):
		return NewProxyV1alpha2Informer(f.cache, f.set.ProxyV1alpha2, f.namespace, f.resyncPeriod).RpcPermissionInformer()
	default:
		return nil
	}
}

func (f *InformerFactory) Run(ctx context.Context) {
	for _, v := range f.cache.Informers() {
		go v.Run(ctx.Done())
	}
}

type EtcdV1alpha1Informer struct {
	cache        *InformerCache
	client       *EtcdV1alpha1
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewEtcdV1alpha1Informer(c *InformerCache, client *EtcdV1alpha1, namespace string, resyncPeriod time.Duration) *EtcdV1alpha1Informer {
	return &EtcdV1alpha1Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *EtcdV1alpha1Informer) EtcdClusterInformer() cache.SharedIndexInformer {
	return f.cache.Write(&etcdv1alpha1.EtcdCluster{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListEtcdCluster(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchEtcdCluster(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&etcdv1alpha1.EtcdCluster{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *EtcdV1alpha1Informer) EtcdClusterLister() *EtcdV1alpha1EtcdClusterLister {
	return NewEtcdV1alpha1EtcdClusterLister(f.EtcdClusterInformer().GetIndexer())
}

type EtcdV1alpha2Informer struct {
	cache        *InformerCache
	client       *EtcdV1alpha2
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewEtcdV1alpha2Informer(c *InformerCache, client *EtcdV1alpha2, namespace string, resyncPeriod time.Duration) *EtcdV1alpha2Informer {
	return &EtcdV1alpha2Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *EtcdV1alpha2Informer) EtcdClusterInformer() cache.SharedIndexInformer {
	return f.cache.Write(&etcdv1alpha2.EtcdCluster{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListEtcdCluster(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchEtcdCluster(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&etcdv1alpha2.EtcdCluster{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *EtcdV1alpha2Informer) EtcdClusterLister() *EtcdV1alpha2EtcdClusterLister {
	return NewEtcdV1alpha2EtcdClusterLister(f.EtcdClusterInformer().GetIndexer())
}

type ProxyV1alpha1Informer struct {
	cache        *InformerCache
	client       *ProxyV1alpha1
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewProxyV1alpha1Informer(c *InformerCache, client *ProxyV1alpha1, namespace string, resyncPeriod time.Duration) *ProxyV1alpha1Informer {
	return &ProxyV1alpha1Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *ProxyV1alpha1Informer) BackendInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha1.Backend{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListBackend(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchBackend(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha1.Backend{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha1Informer) BackendLister() *ProxyV1alpha1BackendLister {
	return NewProxyV1alpha1BackendLister(f.BackendInformer().GetIndexer())
}

func (f *ProxyV1alpha1Informer) ProxyInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha1.Proxy{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListProxy(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchProxy(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha1.Proxy{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha1Informer) ProxyLister() *ProxyV1alpha1ProxyLister {
	return NewProxyV1alpha1ProxyLister(f.ProxyInformer().GetIndexer())
}

func (f *ProxyV1alpha1Informer) RoleInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha1.Role{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListRole(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchRole(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha1.Role{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha1Informer) RoleLister() *ProxyV1alpha1RoleLister {
	return NewProxyV1alpha1RoleLister(f.RoleInformer().GetIndexer())
}

func (f *ProxyV1alpha1Informer) RoleBindingInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha1.RoleBinding{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListRoleBinding(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchRoleBinding(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha1.RoleBinding{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha1Informer) RoleBindingLister() *ProxyV1alpha1RoleBindingLister {
	return NewProxyV1alpha1RoleBindingLister(f.RoleBindingInformer().GetIndexer())
}

func (f *ProxyV1alpha1Informer) RpcPermissionInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha1.RpcPermission{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListRpcPermission(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchRpcPermission(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha1.RpcPermission{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha1Informer) RpcPermissionLister() *ProxyV1alpha1RpcPermissionLister {
	return NewProxyV1alpha1RpcPermissionLister(f.RpcPermissionInformer().GetIndexer())
}

type ProxyV1alpha2Informer struct {
	cache        *InformerCache
	client       *ProxyV1alpha2
	namespace    string
	resyncPeriod time.Duration
	indexers     cache.Indexers
}

func NewProxyV1alpha2Informer(c *InformerCache, client *ProxyV1alpha2, namespace string, resyncPeriod time.Duration) *ProxyV1alpha2Informer {
	return &ProxyV1alpha2Informer{
		cache:        c,
		client:       client,
		namespace:    namespace,
		resyncPeriod: resyncPeriod,
		indexers:     cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	}
}

func (f *ProxyV1alpha2Informer) BackendInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha2.Backend{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListBackend(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchBackend(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha2.Backend{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha2Informer) BackendLister() *ProxyV1alpha2BackendLister {
	return NewProxyV1alpha2BackendLister(f.BackendInformer().GetIndexer())
}

func (f *ProxyV1alpha2Informer) ProxyInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha2.Proxy{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListProxy(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchProxy(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha2.Proxy{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha2Informer) ProxyLister() *ProxyV1alpha2ProxyLister {
	return NewProxyV1alpha2ProxyLister(f.ProxyInformer().GetIndexer())
}

func (f *ProxyV1alpha2Informer) RoleInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha2.Role{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListRole(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchRole(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha2.Role{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha2Informer) RoleLister() *ProxyV1alpha2RoleLister {
	return NewProxyV1alpha2RoleLister(f.RoleInformer().GetIndexer())
}

func (f *ProxyV1alpha2Informer) RoleBindingInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha2.RoleBinding{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListRoleBinding(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchRoleBinding(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha2.RoleBinding{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha2Informer) RoleBindingLister() *ProxyV1alpha2RoleBindingLister {
	return NewProxyV1alpha2RoleBindingLister(f.RoleBindingInformer().GetIndexer())
}

func (f *ProxyV1alpha2Informer) RpcPermissionInformer() cache.SharedIndexInformer {
	return f.cache.Write(&proxyv1alpha2.RpcPermission{}, func() cache.SharedIndexInformer {
		return cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return f.client.ListRpcPermission(context.TODO(), f.namespace, metav1.ListOptions{})
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return f.client.WatchRpcPermission(context.TODO(), f.namespace, metav1.ListOptions{})
				},
			},
			&proxyv1alpha2.RpcPermission{},
			f.resyncPeriod,
			f.indexers,
		)
	})
}

func (f *ProxyV1alpha2Informer) RpcPermissionLister() *ProxyV1alpha2RpcPermissionLister {
	return NewProxyV1alpha2RpcPermissionLister(f.RpcPermissionInformer().GetIndexer())
}

type EtcdV1alpha1EtcdClusterLister struct {
	indexer cache.Indexer
}

func NewEtcdV1alpha1EtcdClusterLister(indexer cache.Indexer) *EtcdV1alpha1EtcdClusterLister {
	return &EtcdV1alpha1EtcdClusterLister{indexer: indexer}
}

func (x *EtcdV1alpha1EtcdClusterLister) List(namespace string, selector labels.Selector) ([]*etcdv1alpha1.EtcdCluster, error) {
	var ret []*etcdv1alpha1.EtcdCluster
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*etcdv1alpha1.EtcdCluster).DeepCopy())
	})
	return ret, err
}

func (x *EtcdV1alpha1EtcdClusterLister) Get(namespace, name string) (*etcdv1alpha1.EtcdCluster, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(etcdv1alpha1.SchemaGroupVersion.WithResource("etcdcluster").GroupResource(), name)
	}
	return obj.(*etcdv1alpha1.EtcdCluster).DeepCopy(), nil
}

type EtcdV1alpha2EtcdClusterLister struct {
	indexer cache.Indexer
}

func NewEtcdV1alpha2EtcdClusterLister(indexer cache.Indexer) *EtcdV1alpha2EtcdClusterLister {
	return &EtcdV1alpha2EtcdClusterLister{indexer: indexer}
}

func (x *EtcdV1alpha2EtcdClusterLister) List(namespace string, selector labels.Selector) ([]*etcdv1alpha2.EtcdCluster, error) {
	var ret []*etcdv1alpha2.EtcdCluster
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*etcdv1alpha2.EtcdCluster).DeepCopy())
	})
	return ret, err
}

func (x *EtcdV1alpha2EtcdClusterLister) Get(namespace, name string) (*etcdv1alpha2.EtcdCluster, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(etcdv1alpha2.SchemaGroupVersion.WithResource("etcdcluster").GroupResource(), name)
	}
	return obj.(*etcdv1alpha2.EtcdCluster).DeepCopy(), nil
}

type ProxyV1alpha1BackendLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha1BackendLister(indexer cache.Indexer) *ProxyV1alpha1BackendLister {
	return &ProxyV1alpha1BackendLister{indexer: indexer}
}

func (x *ProxyV1alpha1BackendLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha1.Backend, error) {
	var ret []*proxyv1alpha1.Backend
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha1.Backend).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha1BackendLister) Get(namespace, name string) (*proxyv1alpha1.Backend, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha1.SchemaGroupVersion.WithResource("backend").GroupResource(), name)
	}
	return obj.(*proxyv1alpha1.Backend).DeepCopy(), nil
}

type ProxyV1alpha1ProxyLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha1ProxyLister(indexer cache.Indexer) *ProxyV1alpha1ProxyLister {
	return &ProxyV1alpha1ProxyLister{indexer: indexer}
}

func (x *ProxyV1alpha1ProxyLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha1.Proxy, error) {
	var ret []*proxyv1alpha1.Proxy
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha1.Proxy).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha1ProxyLister) Get(namespace, name string) (*proxyv1alpha1.Proxy, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha1.SchemaGroupVersion.WithResource("proxy").GroupResource(), name)
	}
	return obj.(*proxyv1alpha1.Proxy).DeepCopy(), nil
}

type ProxyV1alpha1RoleLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha1RoleLister(indexer cache.Indexer) *ProxyV1alpha1RoleLister {
	return &ProxyV1alpha1RoleLister{indexer: indexer}
}

func (x *ProxyV1alpha1RoleLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha1.Role, error) {
	var ret []*proxyv1alpha1.Role
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha1.Role).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha1RoleLister) Get(namespace, name string) (*proxyv1alpha1.Role, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha1.SchemaGroupVersion.WithResource("role").GroupResource(), name)
	}
	return obj.(*proxyv1alpha1.Role).DeepCopy(), nil
}

type ProxyV1alpha1RoleBindingLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha1RoleBindingLister(indexer cache.Indexer) *ProxyV1alpha1RoleBindingLister {
	return &ProxyV1alpha1RoleBindingLister{indexer: indexer}
}

func (x *ProxyV1alpha1RoleBindingLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha1.RoleBinding, error) {
	var ret []*proxyv1alpha1.RoleBinding
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha1.RoleBinding).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha1RoleBindingLister) Get(namespace, name string) (*proxyv1alpha1.RoleBinding, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha1.SchemaGroupVersion.WithResource("rolebinding").GroupResource(), name)
	}
	return obj.(*proxyv1alpha1.RoleBinding).DeepCopy(), nil
}

type ProxyV1alpha1RpcPermissionLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha1RpcPermissionLister(indexer cache.Indexer) *ProxyV1alpha1RpcPermissionLister {
	return &ProxyV1alpha1RpcPermissionLister{indexer: indexer}
}

func (x *ProxyV1alpha1RpcPermissionLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha1.RpcPermission, error) {
	var ret []*proxyv1alpha1.RpcPermission
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha1.RpcPermission).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha1RpcPermissionLister) Get(namespace, name string) (*proxyv1alpha1.RpcPermission, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha1.SchemaGroupVersion.WithResource("rpcpermission").GroupResource(), name)
	}
	return obj.(*proxyv1alpha1.RpcPermission).DeepCopy(), nil
}

type ProxyV1alpha2BackendLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha2BackendLister(indexer cache.Indexer) *ProxyV1alpha2BackendLister {
	return &ProxyV1alpha2BackendLister{indexer: indexer}
}

func (x *ProxyV1alpha2BackendLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha2.Backend, error) {
	var ret []*proxyv1alpha2.Backend
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha2.Backend).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha2BackendLister) Get(namespace, name string) (*proxyv1alpha2.Backend, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha2.SchemaGroupVersion.WithResource("backend").GroupResource(), name)
	}
	return obj.(*proxyv1alpha2.Backend).DeepCopy(), nil
}

type ProxyV1alpha2ProxyLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha2ProxyLister(indexer cache.Indexer) *ProxyV1alpha2ProxyLister {
	return &ProxyV1alpha2ProxyLister{indexer: indexer}
}

func (x *ProxyV1alpha2ProxyLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha2.Proxy, error) {
	var ret []*proxyv1alpha2.Proxy
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha2.Proxy).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha2ProxyLister) Get(namespace, name string) (*proxyv1alpha2.Proxy, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha2.SchemaGroupVersion.WithResource("proxy").GroupResource(), name)
	}
	return obj.(*proxyv1alpha2.Proxy).DeepCopy(), nil
}

type ProxyV1alpha2RoleLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha2RoleLister(indexer cache.Indexer) *ProxyV1alpha2RoleLister {
	return &ProxyV1alpha2RoleLister{indexer: indexer}
}

func (x *ProxyV1alpha2RoleLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha2.Role, error) {
	var ret []*proxyv1alpha2.Role
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha2.Role).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha2RoleLister) Get(namespace, name string) (*proxyv1alpha2.Role, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha2.SchemaGroupVersion.WithResource("role").GroupResource(), name)
	}
	return obj.(*proxyv1alpha2.Role).DeepCopy(), nil
}

type ProxyV1alpha2RoleBindingLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha2RoleBindingLister(indexer cache.Indexer) *ProxyV1alpha2RoleBindingLister {
	return &ProxyV1alpha2RoleBindingLister{indexer: indexer}
}

func (x *ProxyV1alpha2RoleBindingLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha2.RoleBinding, error) {
	var ret []*proxyv1alpha2.RoleBinding
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha2.RoleBinding).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha2RoleBindingLister) Get(namespace, name string) (*proxyv1alpha2.RoleBinding, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha2.SchemaGroupVersion.WithResource("rolebinding").GroupResource(), name)
	}
	return obj.(*proxyv1alpha2.RoleBinding).DeepCopy(), nil
}

type ProxyV1alpha2RpcPermissionLister struct {
	indexer cache.Indexer
}

func NewProxyV1alpha2RpcPermissionLister(indexer cache.Indexer) *ProxyV1alpha2RpcPermissionLister {
	return &ProxyV1alpha2RpcPermissionLister{indexer: indexer}
}

func (x *ProxyV1alpha2RpcPermissionLister) List(namespace string, selector labels.Selector) ([]*proxyv1alpha2.RpcPermission, error) {
	var ret []*proxyv1alpha2.RpcPermission
	err := cache.ListAllByNamespace(x.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*proxyv1alpha2.RpcPermission).DeepCopy())
	})
	return ret, err
}

func (x *ProxyV1alpha2RpcPermissionLister) Get(namespace, name string) (*proxyv1alpha2.RpcPermission, error) {
	obj, exists, err := x.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8serrors.NewNotFound(proxyv1alpha2.SchemaGroupVersion.WithResource("rpcpermission").GroupResource(), name)
	}
	return obj.(*proxyv1alpha2.RpcPermission).DeepCopy(), nil
}
