package testingclient

import (
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"

	"go.f110.dev/kubeproto/go/apis/metav1"
	"k8s.io/apimachinery/pkg/api/meta"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/structured-merge-diff/v6/typed"

	"go.f110.dev/heimdallr/pkg/k8s/client"
)

var (
	codecs = serializer.NewCodecFactory(client.Scheme)
)

type Set struct {
	client.Set

	fake    k8stesting.Fake
	tracker k8stesting.ObjectTracker
}

// typeSchema is the schema of structured-merge-diff for the kinds.
// The field manager of the tracker uses it to merge the objects in the same way as Server-Side Apply.
//
//go:embed kubeproto_testingclient.generated.testingclient.typeschema.yaml
var typeSchema string

var typeSchemaParser = sync.OnceValue(func() *typed.Parser {
	parser, err := typed.NewParser(typed.YAMLObject(typeSchema))
	if err != nil {
		panic(err)
	}
	return parser
})

// statusSubresourceKinds is the set of the kinds which have the status subresource.
// The apiserver ignores the status when the object of these kinds is applied to the main resource.
var statusSubresourceKinds = map[schema.GroupVersionKind]struct{}{
	{Group: "etcd.f110.dev", Version: "v1alpha1", Kind: "EtcdCluster"}:    {},
	{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"}:    {},
	{Group: "proxy.f110.dev", Version: "v1alpha1", Kind: "Backend"}:       {},
	{Group: "proxy.f110.dev", Version: "v1alpha1", Kind: "Proxy"}:         {},
	{Group: "proxy.f110.dev", Version: "v1alpha1", Kind: "Role"}:          {},
	{Group: "proxy.f110.dev", Version: "v1alpha2", Kind: "Backend"}:       {},
	{Group: "proxy.f110.dev", Version: "v1alpha2", Kind: "Proxy"}:         {},
	{Group: "proxy.f110.dev", Version: "v1alpha2", Kind: "Role"}:          {},
	{Group: "proxy.f110.dev", Version: "v1alpha2", Kind: "RpcPermission"}: {},
}

func NewSet() *Set {
	s := &Set{}
	typeConverter := managedfields.NewSchemeTypeConverter(client.Scheme, typeSchemaParser())
	s.tracker = k8stesting.NewFieldManagedObjectTracker(client.Scheme, codecs.UniversalDecoder(), typeConverter)
	s.fake.AddReactor("*", "*", k8stesting.ObjectReaction(s.tracker))
	s.fake.AddWatchReactor("*", func(action k8stesting.Action) (handled bool, ret watch.Interface, err error) {
		w, err := s.tracker.Watch(action.GetResource(), action.GetNamespace())
		if err != nil {
			return false, nil, err
		}
		return true, w, nil
	})

	s.EtcdV1alpha1 = client.NewEtcdV1alpha1Client(&fakerBackend{fake: &s.fake}, nil)
	s.EtcdV1alpha2 = client.NewEtcdV1alpha2Client(&fakerBackend{fake: &s.fake}, nil)
	s.ProxyV1alpha1 = client.NewProxyV1alpha1Client(&fakerBackend{fake: &s.fake}, nil)
	s.ProxyV1alpha2 = client.NewProxyV1alpha2Client(&fakerBackend{fake: &s.fake}, nil)
	return s
}

func (s *Set) Tracker() k8stesting.ObjectTracker {
	return s.tracker
}

func (s *Set) Actions() []k8stesting.Action {
	return s.fake.Actions()
}

func (s *Set) ClearActions() {
	s.fake.ClearActions()
}

type fakerBackend struct {
	fake *k8stesting.Fake
}

func (f *fakerBackend) Get(ctx context.Context, resourceName, namespace, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error) {
	gvks, _, err := client.Scheme.ObjectKinds(result)
	if err != nil {
		return nil, err
	}
	gvk := gvks[0]
	obj, err := f.fake.Invokes(k8stesting.NewGetAction(gvk.GroupVersion().WithResource(resourceName), namespace, name), result)
	if obj == nil {
		return nil, err
	}
	return obj.DeepCopyObject(), nil
}

func (f *fakerBackend) List(ctx context.Context, resourceName, namespace string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error) {
	gvks, _, err := client.Scheme.ObjectKinds(result)
	if err != nil {
		return nil, err
	}
	gvk := gvks[0]
	if strings.HasSuffix(gvk.Kind, "List") {
		gvk.Kind = strings.TrimSuffix(gvk.Kind, "List")
	}
	k8sListOpt := k8smetav1.ListOptions{
		LabelSelector:   opts.LabelSelector,
		FieldSelector:   opts.FieldSelector,
		ResourceVersion: opts.ResourceVersion,
	}
	obj, err := f.fake.Invokes(k8stesting.NewListAction(gvk.GroupVersion().WithResource(resourceName), gvk, namespace, k8sListOpt), result)

	if obj == nil {
		return nil, err
	}

	label, _, _ := k8stesting.ExtractFromListOptions(k8sListOpt)
	if label == nil {
		label = labels.Everything()
	}
	objs, err := meta.ExtractList(obj)
	if err != nil {
		return nil, err
	}
	filtered := make([]runtime.Object, 0)
	for _, item := range objs {
		m := item.(metav1.Object)
		objMeta := m.GetObjectMeta()
		if label.Matches(labels.Set(objMeta.Labels)) {
			filtered = append(filtered, item)
		}
	}
	if err := meta.SetList(obj, filtered); err != nil {
		return nil, err
	}
	return obj.DeepCopyObject(), err
}

func (f *fakerBackend) Create(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error) {
	gvks, _, err := client.Scheme.ObjectKinds(result)
	if err != nil {
		return nil, err
	}
	gvk := gvks[0]
	m := obj.(metav1.Object)
	objMeta := m.GetObjectMeta()
	obj, err = f.fake.Invokes(k8stesting.NewCreateAction(gvk.GroupVersion().WithResource(resourceName), objMeta.Namespace, obj), result)

	if obj == nil {
		return nil, err
	}
	return obj.DeepCopyObject(), err
}

func (f *fakerBackend) Update(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	gvks, _, err := client.Scheme.ObjectKinds(result)
	if err != nil {
		return nil, err
	}
	gvk := gvks[0]
	m := obj.(metav1.Object)
	objMeta := m.GetObjectMeta()
	obj, err = f.fake.Invokes(k8stesting.NewUpdateAction(gvk.GroupVersion().WithResource(resourceName), objMeta.Namespace, obj), result)

	if obj == nil {
		return nil, err
	}
	return obj.DeepCopyObject(), err
}
func (f *fakerBackend) UpdateStatus(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	gvks, _, err := client.Scheme.ObjectKinds(result)
	if err != nil {
		return nil, err
	}
	gvk := gvks[0]
	m := obj.(metav1.Object)
	objMeta := m.GetObjectMeta()
	obj, err = f.fake.Invokes(k8stesting.NewUpdateSubresourceAction(gvk.GroupVersion().WithResource(resourceName), "status", objMeta.Namespace, obj), result)

	if obj == nil {
		return nil, err
	}
	return obj.DeepCopyObject(), err
}
func (f *fakerBackend) Apply(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.ApplyOptions, result runtime.Object) (runtime.Object, error) {
	gvks, _, err := client.Scheme.ObjectKinds(result)
	if err != nil {
		return nil, err
	}
	gvk := gvks[0]
	m := obj.(metav1.Object)
	objMeta := m.GetObjectMeta()
	obj = obj.DeepCopyObject()
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	patch, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	if _, ok := statusSubresourceKinds[gvk]; ok {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(patch, &fields); err != nil {
			return nil, err
		}
		delete(fields, "status")
		patch, err = json.Marshal(fields)
		if err != nil {
			return nil, err
		}
	}
	patchOpts := k8smetav1.PatchOptions{DryRun: opts.DryRun, Force: &opts.Force, FieldManager: opts.FieldManager}
	action := k8stesting.NewPatchActionWithOptions(gvk.GroupVersion().WithResource(resourceName), objMeta.Namespace, objMeta.Name, types.ApplyPatchType, patch, patchOpts)
	obj, err = f.fake.Invokes(action, result)

	if obj == nil {
		return nil, err
	}
	return obj.DeepCopyObject(), err
}
func (f *fakerBackend) Delete(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string, opts metav1.DeleteOptions) error {
	_, err := f.fake.Invokes(k8stesting.NewDeleteAction(gvr, namespace, name), nil)

	return err
}
func (f *fakerBackend) Watch(ctx context.Context, gvr schema.GroupVersionResource, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return f.fake.InvokesWatch(k8stesting.NewWatchAction(gvr, namespace, opts))
}
func (f *fakerBackend) GetClusterScoped(ctx context.Context, resourceName, name string, opts metav1.GetOptions, result runtime.Object) (runtime.Object, error) {
	return f.Get(ctx, resourceName, "", name, opts, result)
}

func (f *fakerBackend) ListClusterScoped(ctx context.Context, resourceName string, opts metav1.ListOptions, result runtime.Object) (runtime.Object, error) {
	return f.List(ctx, resourceName, "", opts, result)
}

func (f *fakerBackend) CreateClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.CreateOptions, result runtime.Object) (runtime.Object, error) {
	return f.Create(ctx, resourceName, obj, opts, result)
}

func (f *fakerBackend) UpdateClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	return f.Update(ctx, resourceName, obj, opts, result)
}

func (f *fakerBackend) UpdateStatusClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.UpdateOptions, result runtime.Object) (runtime.Object, error) {
	return f.UpdateStatus(ctx, resourceName, obj, opts, result)
}

func (f *fakerBackend) ApplyClusterScoped(ctx context.Context, resourceName string, obj runtime.Object, opts metav1.ApplyOptions, result runtime.Object) (runtime.Object, error) {
	return f.Apply(ctx, resourceName, obj, opts, result)
}

func (f *fakerBackend) DeleteClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, name string, opts metav1.DeleteOptions) error {
	return f.Delete(ctx, gvr, "", name, opts)
}

func (f *fakerBackend) WatchClusterScoped(ctx context.Context, gvr schema.GroupVersionResource, opts metav1.ListOptions) (watch.Interface, error) {
	return f.Watch(ctx, gvr, "", opts)
}

func (f *fakerBackend) RESTClient() *rest.RESTClient {
	return nil
}
