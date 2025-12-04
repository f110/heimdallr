package controllertest

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"go.f110.dev/heimdallr/pkg/varptr"
	"go.f110.dev/kubeproto/go/apis/appsv1"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/apis/networkingv1"
	"go.f110.dev/kubeproto/go/apis/policyv1"
	"go.f110.dev/kubeproto/go/apis/rbacv1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/kubeproto/go/k8stestingclient"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/gengo/namer"
	"k8s.io/gengo/types"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/client/testingclient"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/cert-manager/certmanagerv1"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyclient"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyclient/testingthirdpartyclient"
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

	Client                    *testingclient.Set
	CoreClient                *k8stestingclient.Set
	K8sCoreClient             *k8sfake.Clientset
	ThirdPartyClient          *testingthirdpartyclient.Set
	SharedInformerFactory     *client.InformerFactory
	CoreSharedInformerFactory *k8sclient.InformerFactory
	ThirdPartyInformerFactory *thirdpartyclient.InformerFactory
}

func NewTestRunner() *TestRunner {
	clientSet := testingclient.NewSet()
	coreClient := k8stestingclient.NewSet()
	k8sCoreClient := k8sfake.NewSimpleClientset()
	thirdPartyClientSet := testingthirdpartyclient.NewSet()
	k8sCoreClient.Resources = []*k8smetav1.APIResourceList{
		{
			GroupVersion: "cert-manager.io/v1",
			APIResources: []k8smetav1.APIResource{
				{
					Kind: "Certificate",
				},
			},
		},
	}

	factory := client.NewInformerFactory(&clientSet.Set, client.NewInformerCache(), metav1.NamespaceAll, 30*time.Second)
	coreSharedInformerFactory := k8sclient.NewInformerFactory(&coreClient.Set, k8sclient.NewInformerCache(), metav1.NamespaceAll, 30*time.Second)
	thirdPartyInformerFactory := thirdpartyclient.NewInformerFactory(&thirdPartyClientSet.Set, thirdpartyclient.NewInformerCache(), metav1.NamespaceAll, 30*time.Second)

	factory.Run(context.Background())
	coreSharedInformerFactory.Run(context.Background())
	thirdPartyInformerFactory.Run(context.Background())

	return &TestRunner{
		Now:                       time.Now(),
		Client:                    clientSet,
		CoreClient:                coreClient,
		K8sCoreClient:             k8sCoreClient,
		ThirdPartyClient:          thirdPartyClientSet,
		SharedInformerFactory:     factory,
		CoreSharedInformerFactory: coreSharedInformerFactory,
		ThirdPartyInformerFactory: thirdPartyInformerFactory,
	}
}

type Controller interface {
}

func (r *TestRunner) Reconcile(c controllerbase.ControllerBase, target runtime.Object) error {
	r.RegisterFixtures(target)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, controllerbase.TimeKey{}, r.Now)

	return c.Reconcile(ctx, target.DeepCopyObject())
}

func (r *TestRunner) Finalize(c controllerbase.ControllerBase, target runtime.Object) error {
	r.RegisterFixtures(target)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, controllerbase.TimeKey{}, r.Now)

	return c.Finalize(ctx, target.DeepCopyObject())
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
		case *proxyv1alpha2.RpcPermission:
			r.registerRpcPermission(obj)
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
		case *policyv1.PodDisruptionBudget:
			r.registerPodDisruptionBudgetFixture(obj)
		case *certmanagerv1.Certificate:
			r.registerCertificateFixture(obj)
		default:
			panic(fmt.Sprintf("%T is not supported", obj))
		}
	}
}

func (r *TestRunner) registerProxyFixture(p *proxyv1alpha2.Proxy) {
	r.registerClientObject(p)
}

func (r *TestRunner) registerBackendFixture(b *proxyv1alpha2.Backend) {
	r.registerClientObject(b)
}

func (r *TestRunner) registerProxyRoleFixture(v *proxyv1alpha2.Role) {
	r.registerClientObject(v)
}

func (r *TestRunner) registerProxyRoleBindingFixture(v *proxyv1alpha2.RoleBinding) {
	r.registerClientObject(v)
}

func (r *TestRunner) registerRpcPermission(v *proxyv1alpha2.RpcPermission) {
	r.registerClientObject(v)
}

func (r *TestRunner) registerEtcdClusterFixture(ec *etcdv1alpha2.EtcdCluster) {
	r.registerClientObject(ec)
}

func (r *TestRunner) registerClientObject(obj runtime.Object) {
	if err := r.Client.Tracker().Add(obj); err != nil {
		panic(err)
	}
	if err := r.SharedInformerFactory.InformerFor(obj).GetIndexer().Add(obj); err != nil {
		panic(err)
	}
}

func (r *TestRunner) registerCoreObject(obj runtime.Object) {
	if err := r.CoreClient.Tracker().Add(obj); err != nil {
		panic(err)
	}
	if err := r.CoreSharedInformerFactory.InformerFor(obj).GetIndexer().Add(obj); err != nil {
		panic(err)
	}
}

func (r *TestRunner) registerPodFixture(v *corev1.Pod) {
	r.registerCoreObject(v)
}

func (r *TestRunner) registerSecretFixture(s *corev1.Secret) {
	s.CreationTimestamp = varptr.Ptr(metav1.Now())
	r.registerCoreObject(s)
}

func (r *TestRunner) registerCertificateFixture(v *certmanagerv1.Certificate) {
	if err := r.ThirdPartyClient.Tracker().Add(v); err != nil {
		panic(err)
	}
	if err := r.ThirdPartyInformerFactory.InformerFor(v).GetIndexer().Add(v); err != nil {
		panic(err)
	}
}

func (r *TestRunner) registerDeploymentFixture(d *appsv1.Deployment) {
	r.registerCoreObject(d)
}

func (r *TestRunner) registerPodDisruptionBudgetFixture(pdb *policyv1.PodDisruptionBudget) {
	r.registerCoreObject(pdb)
}

func (r *TestRunner) registerServiceFixture(s *corev1.Service) {
	r.registerCoreObject(s)
}

func (r *TestRunner) registerServiceAccountFixture(sa *corev1.ServiceAccount) {
	r.registerCoreObject(sa)
}

func (r *TestRunner) registerRoleFixture(v *rbacv1.Role) {
	r.registerCoreObject(v)
}

func (r *TestRunner) registerRoleBindingFixture(v *rbacv1.RoleBinding) {
	r.registerCoreObject(v)
}

func (r *TestRunner) registerConfigMapFixture(v *corev1.ConfigMap) {
	r.registerCoreObject(v)
}

func (r *TestRunner) registerIngressFixture(i *networkingv1.Ingress) {
	r.registerCoreObject(i)
}

func (r *TestRunner) registerIngressClassFixture(ic *networkingv1.IngressClass) {
	r.registerCoreObject(ic)
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
		Name:      m.GetObjectMeta().Name,
		Namespace: m.GetObjectMeta().Namespace,
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
				t.Logf("HERE? %T", got.Object)
				continue
			}
			objMeta, ok := expect.Object.(metav1.Object)
			if !ok {
				t.Logf("HERE? %T", got.Object)
				continue
			}

			if actualActionObjMeta.GetObjectMeta().Namespace == objMeta.GetObjectMeta().Namespace &&
				actualActionObjMeta.GetObjectMeta().Name == objMeta.GetObjectMeta().Name {
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
				got.Name == expectMeta.GetObjectMeta().Name && got.Namespace == expectMeta.GetObjectMeta().Namespace {
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
				key = fmt.Sprintf(" %s/%s", meta.GetObjectMeta().Namespace, meta.GetObjectMeta().Name)
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

	var calledActions []k8stesting.Action
	for _, v := range [][]k8stesting.Action{r.Client.Actions(), r.CoreClient.Actions(), r.ThirdPartyClient.Actions()} {
		calledActions = append(calledActions, v...)
	}
	actions := make([]*Action, 0)
	for _, v := range calledActions {
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
				name = m.GetObjectMeta().Name
				namespace = m.GetObjectMeta().Namespace
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
				name = m.GetObjectMeta().Name
				namespace = m.GetObjectMeta().Namespace
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

	m.GetObjectMeta().CreationTimestamp = nil
	return obj
}
