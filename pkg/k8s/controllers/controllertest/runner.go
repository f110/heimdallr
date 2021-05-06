package controllertest

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/gengo/namer"
	"k8s.io/gengo/types"

	etcdv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/etcd/v1alpha2"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/fake"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
	informers "go.f110.dev/heimdallr/pkg/k8s/informers/externalversions"
)

type ActionVerb string

const (
	ActionUpdate ActionVerb = "update"
	ActionCreate ActionVerb = "create"
	ActionDelete ActionVerb = "delete"
)

func (a ActionVerb) String() string {
	return string(a)
}

type Action struct {
	Verb                 ActionVerb
	Subresource          string
	GroupVersionResource schema.GroupVersionResource
	Object               runtime.Object
	Name                 string
	Namespace            string
	Visited              bool
}

func (a Action) Resource() string {
	if a.Subresource != "" {
		return resourceName(a.Object) + "/" + a.Subresource
	}
	return resourceName(a.Object)
}

func resourceName(v runtime.Object) string {
	t := reflect.TypeOf(v)
	kind := t.Elem().Name()

	plural := namer.NewAllLowercasePluralNamer(nil)
	return plural.Name(&types.Type{
		Name: types.Name{
			Name: kind,
		},
	})
}

type TestRunner struct {
	Now     time.Time
	Actions []*Action

	Client                    *fake.Clientset
	CoreClient                *k8sfake.Clientset
	SharedInformerFactory     informers.SharedInformerFactory
	CoreSharedInformerFactory kubeinformers.SharedInformerFactory
}

func NewTestRunner() *TestRunner {
	client := fake.NewSimpleClientset()
	coreClient := k8sfake.NewSimpleClientset()
	coreClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "cert-manager.io/v1",
			APIResources: []metav1.APIResource{
				{
					Kind: "Certificate",
				},
			},
		},
	}

	sharedInformerFactory := informers.NewSharedInformerFactory(client, 30*time.Second)
	coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(coreClient, 30*time.Second)

	sharedInformerFactory.Start(context.Background().Done())
	coreSharedInformerFactory.Start(context.Background().Done())

	return &TestRunner{
		Now:                       time.Now(),
		Client:                    client,
		CoreClient:                coreClient,
		SharedInformerFactory:     sharedInformerFactory,
		CoreSharedInformerFactory: coreSharedInformerFactory,
	}
}

type Controller interface {
}

func (r *TestRunner) Reconcile(c controllerbase.ControllerBase, target runtime.Object) error {
	r.RegisterFixtures(target)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, controllerbase.TimeKey{}, r.Now)

	return c.Reconcile(ctx, target)
}

func (r *TestRunner) Finalize(c controllerbase.ControllerBase, target runtime.Object) error {
	r.RegisterFixtures(target)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, controllerbase.TimeKey{}, r.Now)

	return c.Finalize(ctx, target)
}

func (r *TestRunner) RegisterFixtures(objs ...runtime.Object) {
	for _, v := range objs {
		if v == nil {
			continue
		}

		copied := v.DeepCopyObject()
		switch obj := copied.(type) {
		case *proxyv1alpha2.Proxy:
			r.registerProxyFixture(obj)
		case *proxyv1alpha2.Backend:
			r.registerBackendFixture(obj)
		case *proxyv1alpha2.Role:
			r.registerProxyRoleFixture(obj)
		case *proxyv1alpha2.RoleBinding:
			r.registerProxyRoleBindingFixture(obj)
		case *etcdv1alpha2.EtcdCluster:
			r.registerEtcdClusterFixture(obj)
		case *corev1.Pod:
			r.registerPodFixture(obj)
		case *corev1.Secret:
			r.registerSecretFixture(obj)
		case *corev1.Service:
			r.registerServiceFixture(obj)
		case *corev1.ConfigMap:
			r.registerConfigMapFixture(obj)
		case *corev1.ServiceAccount:
			r.registerServiceAccountFixture(obj)
		case *rbacv1.Role:
			r.registerRoleFixture(obj)
		case *rbacv1.RoleBinding:
			r.registerRoleBindingFixture(obj)
		case *appsv1.Deployment:
			r.registerDeploymentFixture(obj)
		case *networkingv1.Ingress:
			r.registerIngressFixture(obj)
		case *networkingv1.IngressClass:
			r.registerIngressClassFixture(obj)
		case *policyv1beta1.PodDisruptionBudget:
			r.registerPodDisruptionBudgetFixture(obj)
		case *certmanagerv1.Certificate:
			r.registerCertificateFixture(obj)
		default:
			panic(fmt.Sprintf("%T is not supported", obj))
		}
	}
}

func (r *TestRunner) registerProxyFixture(p *proxyv1alpha2.Proxy) {
	r.Client.Tracker().Add(p)
	r.SharedInformerFactory.Proxy().V1alpha2().Proxies().Informer().GetIndexer().Add(p)
}

func (r *TestRunner) registerBackendFixture(b *proxyv1alpha2.Backend) {
	r.Client.Tracker().Add(b)
	r.SharedInformerFactory.Proxy().V1alpha2().Backends().Informer().GetIndexer().Add(b)
}

func (r *TestRunner) registerProxyRoleFixture(v *proxyv1alpha2.Role) {
	r.Client.Tracker().Add(v)
	r.SharedInformerFactory.Proxy().V1alpha2().Roles().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) registerProxyRoleBindingFixture(v *proxyv1alpha2.RoleBinding) {
	r.Client.Tracker().Add(v)
	r.SharedInformerFactory.Proxy().V1alpha2().RoleBindings().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) registerEtcdClusterFixture(ec *etcdv1alpha2.EtcdCluster) {
	r.Client.Tracker().Add(ec)
	r.SharedInformerFactory.Etcd().V1alpha2().EtcdClusters().Informer().GetIndexer().Add(ec)
}

func (r *TestRunner) registerPodFixture(v *corev1.Pod) {
	r.CoreClient.Tracker().Add(v)
	r.CoreSharedInformerFactory.Core().V1().Pods().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) registerSecretFixture(s *corev1.Secret) {
	s.CreationTimestamp = metav1.Now()
	r.CoreClient.Tracker().Add(s)
	r.CoreSharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(s)
}

func (r *TestRunner) registerDeploymentFixture(d *appsv1.Deployment) {
	r.CoreClient.Tracker().Add(d)
	r.CoreSharedInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(d)
}

func (r *TestRunner) registerPodDisruptionBudgetFixture(pdb *policyv1beta1.PodDisruptionBudget) {
	r.CoreClient.Tracker().Add(pdb)
	r.CoreSharedInformerFactory.Policy().V1beta1().PodDisruptionBudgets().Informer().GetIndexer().Add(pdb)
}

func (r *TestRunner) registerServiceFixture(s *corev1.Service) {
	r.CoreClient.Tracker().Add(s)
	r.CoreSharedInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(s)
}

func (r *TestRunner) registerServiceAccountFixture(sa *corev1.ServiceAccount) {
	r.CoreClient.Tracker().Add(sa)
	r.CoreSharedInformerFactory.Core().V1().ServiceAccounts().Informer().GetIndexer().Add(sa)
}

func (r *TestRunner) registerRoleFixture(v *rbacv1.Role) {
	r.CoreClient.Tracker().Add(v)
	r.CoreSharedInformerFactory.Rbac().V1().Roles().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) registerRoleBindingFixture(v *rbacv1.RoleBinding) {
	r.CoreClient.Tracker().Add(v)
	r.CoreSharedInformerFactory.Rbac().V1().RoleBindings().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) registerConfigMapFixture(v *corev1.ConfigMap) {
	r.CoreClient.Tracker().Add(v)
	r.CoreSharedInformerFactory.Core().V1().ConfigMaps().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) registerIngressFixture(i *networkingv1.Ingress) {
	r.CoreClient.Tracker().Add(i)
	r.CoreSharedInformerFactory.Networking().V1().Ingresses().Informer().GetIndexer().Add(i)
}

func (r *TestRunner) registerIngressClassFixture(ic *networkingv1.IngressClass) {
	r.CoreClient.Tracker().Add(ic)
	r.CoreSharedInformerFactory.Networking().V1().IngressClasses().Informer().GetIndexer().Add(ic)
}

func (r *TestRunner) registerCertificateFixture(v *certmanagerv1.Certificate) {
	r.Client.Tracker().Add(v)
	r.SharedInformerFactory.Certmanager().V1().Certificates().Informer().GetIndexer().Add(v)
}

func (r *TestRunner) AssertUpdateAction(t *testing.T, subresource string, obj runtime.Object) bool {
	t.Helper()

	return r.AssertAction(t, Action{
		Verb:        ActionUpdate,
		Subresource: subresource,
		Object:      obj,
	})
}

func (r *TestRunner) AssertCreateAction(t *testing.T, obj runtime.Object) bool {
	t.Helper()

	return r.AssertAction(t, Action{
		Verb:   ActionCreate,
		Object: obj,
	})
}

func (r *TestRunner) AssertDeleteAction(t *testing.T, obj runtime.Object) bool {
	t.Helper()

	m, ok := obj.(metav1.Object)
	if !ok {
		assert.Failf(t, "Failed type assertion", "%T is not metav1.Object", obj)
	}
	return r.AssertAction(t, Action{
		Verb:      ActionDelete,
		Object:    obj,
		Name:      m.GetName(),
		Namespace: m.GetNamespace(),
	})
}

func (r *TestRunner) AssertAction(t *testing.T, expect Action) bool {
	t.Helper()

	matchVerb := false
	matchObj := false
	var obj runtime.Object
Match:
	for _, got := range r.editActions() {
		if got.Visited {
			continue
		}
		if got.Verb != expect.Verb {
			continue
		}
		if expect.Subresource != "" && got.Subresource != expect.Subresource {
			continue
		}

		matchVerb = true
		switch got.Verb {
		case ActionCreate:
			if reflect.TypeOf(got.Object) != reflect.TypeOf(expect.Object) {
				continue
			}

			actualActionObjMeta, ok := got.Object.(metav1.Object)
			if !ok {
				continue
			}
			objMeta, ok := expect.Object.(metav1.Object)
			if !ok {
				continue
			}

			if actualActionObjMeta.GetNamespace() == objMeta.GetNamespace() &&
				actualActionObjMeta.GetName() == objMeta.GetName() {
				matchObj = true
				got.Visited = true
				break Match
			}
		case ActionUpdate:
			if got.Subresource != expect.Subresource {
				continue
			}

			obj = got.Object
			if fuzzyEqual(got.Object, expect.Object) {
				matchObj = true
				got.Visited = true
				break Match
			}
		case ActionDelete:
			expectMeta, ok := expect.Object.(metav1.Object)
			if !ok {
				continue
			}

			if resourceName(expect.Object) == got.GroupVersionResource.Resource &&
				got.Name == expectMeta.GetName() && got.Namespace == expectMeta.GetNamespace() {
				matchObj = true
				got.Visited = true
				break Match
			}
		}
	}
	if !matchVerb {
		assert.Fail(t, "The expect action was not called")
	} else if !matchObj {
		msg := "The expect action was called but the matched object was not found"
		if obj != nil {
			assert.Fail(t, msg, cmp.Diff(expect.Object, obj))
		} else {
			assert.Fail(t, msg)
		}
	}

	return matchVerb && matchObj
}

func (r *TestRunner) AssertNoUnexpectedAction(t *testing.T) {
	t.Helper()

	unexpectedActions := make([]*Action, 0)
	for _, v := range r.editActions() {
		if v.Visited {
			continue
		}
		unexpectedActions = append(unexpectedActions, v)
	}

	msg := ""
	if len(unexpectedActions) > 0 {
		line := make([]string, 0, len(unexpectedActions))
		for _, v := range unexpectedActions {
			key := ""
			meta, ok := v.Object.(metav1.Object)
			if ok {
				key = fmt.Sprintf(" %s/%s", meta.GetNamespace(), meta.GetName())
			}
			if v.Name != "" && v.Namespace != "" {
				key = fmt.Sprintf("%s/%s", v.Namespace, v.Name)
			}
			kind := ""
			if v.Object != nil {
				kind = reflect.TypeOf(v.Object).Elem().Name()
			}
			subresource := ""
			if v.Subresource != "" {
				subresource = "(" + v.Subresource + ")"
			}
			line = append(line, fmt.Sprintf("%s %s%s %s", v.Verb, kind, subresource, key))
		}
		msg = strings.Join(line, " ")
	}

	assert.Len(t, unexpectedActions, 0, "There are %d unexpected actions: %s", len(unexpectedActions), msg)
}

func (r *TestRunner) editActions() []*Action {
	if r.Actions != nil {
		return r.Actions
	}

	actions := make([]*Action, 0)
	for _, v := range append(r.Client.Actions(), r.CoreClient.Actions()...) {
		switch a := v.(type) {
		case k8stesting.CreateActionImpl:
			// Exclude Event object because adding the event is non-blocking operation.
			// If will be going to assert the event, we should wait to adding the event.
			// Buf currently EventRecorder doesn't have a such interface.
			// Hence, we can't wait to adding the event.
			if reflect.TypeOf(a.GetObject()) == reflect.TypeOf(&corev1.Event{}) {
				continue
			}

			var name, namespace string
			m, ok := a.GetObject().(metav1.Object)
			if ok {
				name = m.GetName()
				namespace = m.GetNamespace()
			}
			actions = append(actions, &Action{
				Verb:        ActionVerb(v.GetVerb()),
				Subresource: v.GetSubresource(),
				Object:      a.GetObject(),
				Name:        name,
				Namespace:   namespace,
			})
		case k8stesting.UpdateActionImpl:
			var name, namespace string
			m, ok := a.GetObject().(metav1.Object)
			if ok {
				name = m.GetName()
				namespace = m.GetNamespace()
			}
			actions = append(actions, &Action{
				Verb:        ActionVerb(v.GetVerb()),
				Subresource: v.GetSubresource(),
				Object:      a.GetObject(),
				Name:        name,
				Namespace:   namespace,
			})
		case k8stesting.DeleteActionImpl:
			actions = append(actions, &Action{
				Verb:                 ActionVerb(v.GetVerb()),
				Subresource:          v.GetSubresource(),
				GroupVersionResource: a.Resource,
				Name:                 a.Name,
				Namespace:            a.Namespace,
			})
		}
	}
	r.Actions = actions

	return actions
}

func fuzzyEqual(left, right runtime.Object) bool {
	return reflect.DeepEqual(excludeTimeFields(left), excludeTimeFields(right))
}

func excludeTimeFields(v runtime.Object) runtime.Object {
	obj := v.DeepCopyObject()
	m, ok := obj.(metav1.Object)
	if !ok {
		return v
	}

	m.SetCreationTimestamp(metav1.Time{})
	return obj
}
