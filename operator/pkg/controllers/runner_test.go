package controllers

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jarcoal/httpmock"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	certmanagerv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/etcdserver/etcdserverpb"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/scale/scheme"
	core "k8s.io/client-go/testing"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/gengo/namer"
	"k8s.io/gengo/types"

	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/fake"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
)

type ActionVerb string

const (
	ActionUpdate ActionVerb = "update"
	ActionCreate ActionVerb = "create"
)

func (a ActionVerb) String() string {
	return string(a)
}

type Action struct {
	Verb        ActionVerb
	Subresource string
	Object      kruntime.Object
	Visited     bool
}

func (a Action) Resource() string {
	if a.Subresource != "" {
		return resourceName(a.Object) + "/" + a.Subresource
	}
	return resourceName(a.Object)
}

func resourceName(v kruntime.Object) string {
	t := reflect.TypeOf(v)
	kind := t.Elem().Name()

	plural := namer.NewAllLowercasePluralNamer(nil)
	return plural.Name(&types.Type{
		Name: types.Name{
			Name: kind,
		},
	})
}

type expectAction struct {
	core.Action
	Caller string
}

type commonTestRunner struct {
	t           *testing.T
	actions     []expectAction
	coreActions []expectAction
	Actions     []*Action

	client     *fake.Clientset
	coreClient *k8sfake.Clientset

	sharedInformerFactory     informers.SharedInformerFactory
	coreSharedInformerFactory kubeinformers.SharedInformerFactory

	transport *httpmock.MockTransport
}

func newCommonTestRunner(t *testing.T) *commonTestRunner {
	client := fake.NewSimpleClientset()
	coreClient := k8sfake.NewSimpleClientset()

	sharedInformerFactory := informers.NewSharedInformerFactory(client, 30*time.Second)
	coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(coreClient, 30*time.Second)

	sharedInformerFactory.Start(context.Background().Done())
	coreSharedInformerFactory.Start(context.Background().Done())

	return &commonTestRunner{
		t:                         t,
		actions:                   make([]expectAction, 0),
		coreActions:               make([]expectAction, 0),
		client:                    client,
		coreClient:                coreClient,
		sharedInformerFactory:     sharedInformerFactory,
		coreSharedInformerFactory: coreSharedInformerFactory,
		transport:                 httpmock.NewMockTransport(),
	}
}

func (f *commonTestRunner) RegisterFixtures(objs ...kruntime.Object) {
	for _, v := range objs {
		copied := v.DeepCopyObject()
		switch obj := copied.(type) {
		case *proxyv1alpha2.Proxy:
			f.RegisterProxyFixture(obj)
		case *proxyv1alpha2.Backend:
			f.RegisterBackendFixture(obj)
		case *etcdv1alpha2.EtcdCluster:
			f.RegisterEtcdClusterFixture(obj)
		case *corev1.Pod:
			f.RegisterPodFixture(obj)
		case *corev1.Secret:
			f.RegisterSecretFixture(obj)
		case *corev1.Service:
			f.RegisterServiceFixture(obj)
		case *corev1.ConfigMap:
			f.RegisterConfigMapFixture(obj)
		case *appsv1.Deployment:
			f.RegisterDeploymentFixture(obj)
		case *policyv1beta1.PodDisruptionBudget:
			f.RegisterPodDisruptionBudgetFixture(obj)
		case *certmanagerv1.Certificate:
			f.RegisterCertificateFixture(obj)
		}
	}
}

func (f *commonTestRunner) RegisterProxyFixture(p *proxyv1alpha2.Proxy) {
	f.client.Tracker().Add(p)
	f.sharedInformerFactory.Proxy().V1alpha2().Proxies().Informer().GetIndexer().Add(p)
}

func (f *commonTestRunner) RegisterBackendFixture(b ...*proxyv1alpha2.Backend) {
	for _, v := range b {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Proxy().V1alpha2().Backends().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterProxyRoleFixture(r ...*proxyv1alpha2.Role) {
	for _, v := range r {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Proxy().V1alpha2().Roles().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterProxyRoleBindingFixture(r ...*proxyv1alpha2.RoleBinding) {
	for _, v := range r {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Proxy().V1alpha2().RoleBindings().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterEtcdClusterFixture(ec *etcdv1alpha2.EtcdCluster) {
	f.client.Tracker().Add(ec)
	f.sharedInformerFactory.Etcd().V1alpha2().EtcdClusters().Informer().GetIndexer().Add(ec)
}

func (f *commonTestRunner) RegisterPodFixture(p ...*corev1.Pod) {
	for _, v := range p {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().Pods().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterSecretFixture(s ...*corev1.Secret) {
	for _, v := range s {
		v.CreationTimestamp = metav1.Now()
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterDeploymentFixture(d *appsv1.Deployment) {
	f.coreClient.Tracker().Add(d)
	f.coreSharedInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(d)
}

func (f *commonTestRunner) RegisterPodDisruptionBudgetFixture(pdb *policyv1beta1.PodDisruptionBudget) {
	f.coreClient.Tracker().Add(pdb)
	f.coreSharedInformerFactory.Policy().V1beta1().PodDisruptionBudgets().Informer().GetIndexer().Add(pdb)
}

func (f *commonTestRunner) RegisterServiceFixture(s ...*corev1.Service) {
	for _, v := range s {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterServiceAccountFixture(sa ...*corev1.ServiceAccount) {
	for _, v := range sa {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().ServiceAccounts().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterRoleFixture(r ...*rbacv1.Role) {
	for _, v := range r {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Rbac().V1().Roles().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterRoleBindingFixture(r ...*rbacv1.RoleBinding) {
	for _, v := range r {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Rbac().V1().RoleBindings().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterConfigMapFixture(c ...*corev1.ConfigMap) {
	for _, v := range c {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().ConfigMaps().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterIngressFixture(i *networkingv1.Ingress) {
	f.coreClient.Tracker().Add(i)
	f.coreSharedInformerFactory.Networking().V1().Ingresses().Informer().GetIndexer().Add(i)
}

func (f *commonTestRunner) RegisterIngressClassFixture(ic *networkingv1.IngressClass) {
	f.coreClient.Tracker().Add(ic)
	f.coreSharedInformerFactory.Networking().V1().IngressClasses().Informer().GetIndexer().Add(ic)
}

func (f *commonTestRunner) RegisterCertificateFixture(c ...*certmanagerv1.Certificate) {
	for _, v := range c {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Certmanager().V1().Certificates().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) ExpectCreateSecret() {
	action := core.NewCreateAction(scheme.SchemeGroupVersion.WithResource("secrets"), "", &corev1.Secret{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateServiceAccount() {
	action := core.NewCreateAction(scheme.SchemeGroupVersion.WithResource("serviceaccounts"), "", &corev1.ServiceAccount{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateRole() {
	action := core.NewCreateAction(rbacv1.SchemeGroupVersion.WithResource("roles"), "", &rbacv1.Role{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateRoleBinding() {
	action := core.NewCreateAction(rbacv1.SchemeGroupVersion.WithResource("rolebindings"), "", &rbacv1.RoleBinding{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreatePod() {
	action := core.NewCreateAction(scheme.SchemeGroupVersion.WithResource("pods"), "", &corev1.Pod{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectDeletePod() {
	action := core.NewDeleteAction(scheme.SchemeGroupVersion.WithResource("pods"), "", "")

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateDeployment() {
	action := core.NewCreateAction(appsv1.SchemeGroupVersion.WithResource("deployments"), "", &appsv1.Deployment{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateService() {
	action := core.NewCreateAction(corev1.SchemeGroupVersion.WithResource("services"), "", &corev1.Service{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateConfigMap() {
	action := core.NewCreateAction(corev1.SchemeGroupVersion.WithResource("configmaps"), "", &corev1.ConfigMap{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreatePodDisruptionBudget() {
	action := core.NewCreateAction(policyv1beta1.SchemeGroupVersion.WithResource("poddisruptionbudgets"), "", &policyv1beta1.PodDisruptionBudget{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateEtcdCluster() {
	action := core.NewCreateAction(etcdv1alpha2.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha2.EtcdCluster{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateBackend() {
	action := core.NewCreateAction(proxyv1alpha2.SchemeGroupVersion.WithResource("backends"), "", &proxyv1alpha2.Backend{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectCreateCertificate() {
	action := core.NewCreateAction(certmanagerv1alpha2.SchemeGroupVersion.WithResource("certificates"), "", &certmanagerv1alpha2.Certificate{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateSecret() {
	action := core.NewUpdateAction(corev1.SchemeGroupVersion.WithResource("secrets"), "", &corev1.Secret{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateIngress() {
	action := core.NewUpdateAction(networkingv1.SchemeGroupVersion.WithResource("ingresses"), "", &networkingv1.Ingress{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateProxy() {
	action := core.NewUpdateAction(proxyv1alpha2.SchemeGroupVersion.WithResource("proxies"), "", &proxyv1alpha2.Proxy{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateProxyStatus() {
	action := core.NewUpdateAction(proxyv1alpha2.SchemeGroupVersion.WithResource("proxies"), "", &proxyv1alpha2.Proxy{})
	action.Subresource = "status"

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateBackend() {
	action := core.NewUpdateAction(proxyv1alpha2.SchemeGroupVersion.WithResource("backends"), "", &proxyv1alpha2.Backend{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateBackendStatus() {
	action := core.NewUpdateAction(proxyv1alpha2.SchemeGroupVersion.WithResource("backends"), "", &proxyv1alpha2.Backend{})
	action.Subresource = "status"

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateEtcdCluster() {
	action := core.NewUpdateAction(etcdv1alpha2.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha2.EtcdCluster{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateEtcdClusterStatus() {
	action := core.NewUpdateAction(etcdv1alpha2.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha2.EtcdCluster{})
	action.Subresource = "status"

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateConfigMap() {
	action := core.NewUpdateAction(corev1.SchemeGroupVersion.WithResource("configmaps"), "", &corev1.ConfigMap{})

	f.coreActions = append(f.coreActions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) AssertUpdateAction(t *testing.T, subresource string, obj kruntime.Object) bool {
	t.Helper()

	return f.AssertAction(t, Action{
		Verb:        ActionUpdate,
		Subresource: subresource,
		Object:      obj,
	})
}

func (f *commonTestRunner) AssertCreateAction(t *testing.T, obj kruntime.Object) bool {
	t.Helper()

	return f.AssertAction(t, Action{
		Verb:   ActionCreate,
		Object: obj,
	})
}

func (f *commonTestRunner) AssertAction(t *testing.T, e Action) bool {
	t.Helper()

	matchVerb := false
	matchObj := false
	var obj kruntime.Object
Match:
	for _, v := range f.editActions() {
		if v.Visited {
			continue
		}
		if v.Verb != e.Verb {
			continue
		}

		matchVerb = true
		switch v.Verb {
		case ActionCreate:
			if reflect.TypeOf(v.Object) != reflect.TypeOf(e.Object) {
				continue
			}

			// Event is a special case.
			if reflect.TypeOf(e.Object) == reflect.TypeOf(&corev1.Event{}) &&
				reflect.TypeOf(v.Object) == reflect.TypeOf(&corev1.Event{}) {
				expect := e.Object.(*corev1.Event)
				actual := v.Object.(*corev1.Event)
				if expect.Reason == actual.Reason {
					matchObj = true
					v.Visited = true
					break
				}
			}

			actualActionObjMeta, ok := v.Object.(metav1.Object)
			if !ok {
				continue
			}
			objMeta, ok := e.Object.(metav1.Object)
			if !ok {
				continue
			}

			if actualActionObjMeta.GetNamespace() == objMeta.GetNamespace() &&
				actualActionObjMeta.GetName() == objMeta.GetName() {
				matchObj = true
				v.Visited = true
				break Match
			}
		case ActionUpdate:
			obj = v.Object
			if reflect.DeepEqual(v.Object, e.Object) {
				matchObj = true
				v.Visited = true
				break Match
			}
		}
	}
	if !matchVerb {
		assert.Fail(t, "The expect action was not called")
	} else if !matchObj {
		msg := "The expect action was called but the matched object was not found"
		if obj != nil {
			assert.Fail(t, msg, cmp.Diff(e.Object, obj))
		} else {
			assert.Fail(t, msg)
		}
	}

	return matchVerb && matchObj
}

func (f *commonTestRunner) AssertNoUnexpectedAction(t *testing.T) {
	unexpectedActions := make([]*Action, 0)
	for _, v := range f.editActions() {
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
			kind := ""
			if v.Object != nil {
				kind = reflect.TypeOf(v.Object).Elem().Name()
			}
			line = append(line, fmt.Sprintf("%s %s%s", v.Verb, kind, key))
		}
		msg = strings.Join(line, " ")
	}

	assert.Len(t, unexpectedActions, 0, "There are %d unexpected actions: %s", len(unexpectedActions), msg)
}

func (f *commonTestRunner) editActions() []*Action {
	if f.Actions != nil {
		return f.Actions
	}

	actions := make([]*Action, 0)
	for _, v := range append(f.client.Actions(), f.coreClient.Actions()...) {
		switch a := v.(type) {
		case k8stesting.CreateActionImpl:
			actions = append(actions, &Action{
				Verb:        ActionVerb(v.GetVerb()),
				Subresource: v.GetSubresource(),
				Object:      a.GetObject(),
			})
		case k8stesting.UpdateActionImpl:
			actions = append(actions, &Action{
				Verb:        ActionVerb(v.GetVerb()),
				Subresource: v.GetSubresource(),
				Object:      a.GetObject(),
			})
		case k8stesting.DeleteActionImpl:
			actions = append(actions, &Action{
				Verb:        ActionVerb(v.GetVerb()),
				Subresource: v.GetSubresource(),
			})
		}
	}
	f.Actions = actions

	return actions
}

func (f *commonTestRunner) expectActionWithCaller(action core.Action) expectAction {
	_, file, line, _ := runtime.Caller(2)
	return expectAction{Action: action, Caller: fmt.Sprintf("%s:%d", file, line)}
}

func (f *commonTestRunner) actionMatcher() {
	f.t.Helper()

	actions := excludeReadActions(f.client.Actions())
	for i, action := range actions {
		if len(f.actions) < i+1 {
			f.t.Errorf("%d unexpected actions:", len(actions)-len(f.actions))
			for _, v := range actions[i:] {
				f.t.Logf("unexpected action: %s %s", v.GetVerb(), v.GetResource().Resource)
			}
			break
		}

		expectedAction := f.actions[i]
		if !checkAction(f.t, expectedAction, action) {
			f.t.FailNow()
		}
	}

	if len(f.actions) > len(actions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.actions)-len(actions), f.actions[len(actions):])
	}

	kubeActions := excludeReadActions(f.coreClient.Actions())
	for i, action := range kubeActions {
		if len(f.coreActions) < i+1 {
			f.t.Errorf("%d unexpected actions:", len(kubeActions)-len(f.coreActions))
			for _, v := range kubeActions[i:] {
				f.t.Logf("unexpected action: %s %s", v.GetVerb(), v.GetResource().Resource)
			}
			break
		}

		expectedAction := f.coreActions[i]
		if !checkAction(f.t, expectedAction, action) {
			f.t.FailNow()
		}
	}

	if len(f.coreActions) > len(kubeActions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.coreActions)-len(kubeActions), f.coreActions[len(kubeActions):])
	}
}

type proxyControllerTestRunner struct {
	*commonTestRunner
	t *testing.T

	c *ProxyController
}

func newProxyControllerTestRunner(t *testing.T) *proxyControllerTestRunner {
	f := &proxyControllerTestRunner{
		commonTestRunner: newCommonTestRunner(t),
		t:                t,
	}

	f.commonTestRunner.coreClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "cert-manager.io/v1",
			APIResources: []metav1.APIResource{
				{
					Kind: "Certificate",
				},
			},
		},
	}

	c, err := NewProxyController(f.sharedInformerFactory, f.coreSharedInformerFactory, f.coreClient, f.client)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c

	return f
}

func (f *proxyControllerTestRunner) Run(t *testing.T, p *proxyv1alpha2.Proxy) {
	t.Helper()

	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := f.c.ProcessKey(key)
	f.actionMatcher()

	if syncErr != nil {
		t.Errorf("Expect to not occurred error: %+v", syncErr)
	}
}

func (f *proxyControllerTestRunner) RunExpectError(t *testing.T, p *proxyv1alpha2.Proxy, expectErr error) {
	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := f.c.ProcessKey(key)
	f.actionMatcher()

	IsError(t, syncErr, expectErr)
}

type githubControllerTestRunner struct {
	*commonTestRunner
	t *testing.T

	c *GitHubController
}

func newGitHubControllerTestRunner(t *testing.T) *githubControllerTestRunner {
	f := &githubControllerTestRunner{
		commonTestRunner: newCommonTestRunner(t),
		t:                t,
	}

	c, err := NewGitHubController(f.sharedInformerFactory, f.coreSharedInformerFactory, f.coreClient, f.client, f.commonTestRunner.transport)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c

	return f
}

func (f *githubControllerTestRunner) Run(t *testing.T, b *proxyv1alpha2.Backend) {
	key, err := cache.MetaNamespaceKeyFunc(b)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := f.c.ProcessKey(key)
	f.actionMatcher()

	if syncErr != nil {
		t.Errorf("Expect to not occurred error: %+v", syncErr)
	}
}

func (f *githubControllerTestRunner) RunExpectError(t *testing.T, b *proxyv1alpha2.Backend, expectErr error) {
	key, err := cache.MetaNamespaceKeyFunc(b)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := f.c.ProcessKey(key)
	f.actionMatcher()

	IsError(t, syncErr, expectErr)
}

type etcdControllerTestRunner struct {
	*commonTestRunner
	t *testing.T

	c *EtcdController
}

func newEtcdControllerTestRunner(t *testing.T) (*etcdControllerTestRunner, *MockOption) {
	f := &etcdControllerTestRunner{
		commonTestRunner: newCommonTestRunner(t),
		t:                t,
	}

	etcdMockCluster := NewMockCluster()
	etcdMockMaintenance := NewMockMaintenance()
	mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}

	// The controller assumes running inside cluster.
	// Thus we don't have to pass rest.Config.
	c, err := NewEtcdController(
		f.sharedInformerFactory,
		f.coreSharedInformerFactory,
		f.coreClient,
		f.client,
		nil,
		"cluster.local",
		false,
		f.commonTestRunner.transport,
		mockOpt,
	)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c

	return f, mockOpt
}

func (f *etcdControllerTestRunner) Run(t *testing.T, e *etcdv1alpha2.EtcdCluster) {
	t.Helper()

	key, err := cache.MetaNamespaceKeyFunc(e)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := f.c.ProcessKey(key)
	f.actionMatcher()

	if syncErr != nil {
		t.Errorf("Expect to not occurred error: %+v", syncErr)
	}
}

type MockCluster struct {
	members []*etcdserverpb.Member
}

func NewMockCluster() *MockCluster {
	return &MockCluster{members: make([]*etcdserverpb.Member, 0)}
}

func (m *MockCluster) AddMember(member *etcdserverpb.Member) {
	member.ID = rand.Uint64()
	m.members = append(m.members, member)
}

func (m *MockCluster) MemberList(_ context.Context) (*clientv3.MemberListResponse, error) {
	return &clientv3.MemberListResponse{Members: m.members}, nil
}

func (m *MockCluster) MemberAdd(_ context.Context, peerAddrs []string) (*clientv3.MemberAddResponse, error) {
	member := &etcdserverpb.Member{PeerURLs: peerAddrs, ID: rand.Uint64()}
	m.members = append(m.members, member)

	return &clientv3.MemberAddResponse{Member: member, Members: m.members}, nil
}

func (m *MockCluster) MemberAddAsLearner(ctx context.Context, peerAddrs []string) (*clientv3.MemberAddResponse, error) {
	panic("implement me")
}

func (m *MockCluster) MemberRemove(_ context.Context, id uint64) (*clientv3.MemberRemoveResponse, error) {
	for i, v := range m.members {
		if v.ID == id {
			m.members = append(m.members[:i], m.members[i+1:]...)
			break
		}
	}

	return &clientv3.MemberRemoveResponse{}, nil
}

func (m *MockCluster) MemberUpdate(ctx context.Context, id uint64, peerAddrs []string) (*clientv3.MemberUpdateResponse, error) {
	panic("implement me")
}

func (m *MockCluster) MemberPromote(ctx context.Context, id uint64) (*clientv3.MemberPromoteResponse, error) {
	panic("implement me")
}

type MockMaintenance struct {
}

func NewMockMaintenance() *MockMaintenance {
	return &MockMaintenance{}
}

func (m *MockMaintenance) AlarmList(ctx context.Context) (*clientv3.AlarmResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) AlarmDisarm(ctx context.Context, alerm *clientv3.AlarmMember) (*clientv3.AlarmResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) Defragment(ctx context.Context, endpoint string) (*clientv3.DefragmentResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) Status(ctx context.Context, endpoint string) (*clientv3.StatusResponse, error) {
	return &clientv3.StatusResponse{
		Header: &etcdserverpb.ResponseHeader{},
	}, nil
}

func (m *MockMaintenance) HashKV(ctx context.Context, endpoint string, rev int64) (*clientv3.HashKVResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	f, err := os.Open("testdata/snapshot.db")
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (m *MockMaintenance) MoveLeader(ctx context.Context, transfereeID uint64) (*clientv3.MoveLeaderResponse, error) {
	panic("implement me")
}

type ingressControllerTestRunner struct {
	*commonTestRunner
	t *testing.T

	c *IngressController
}

func newIngressControllerTestRunner(t *testing.T) *ingressControllerTestRunner {
	f := &ingressControllerTestRunner{
		commonTestRunner: newCommonTestRunner(t),
		t:                t,
	}

	c := NewIngressController(f.coreSharedInformerFactory, f.sharedInformerFactory, f.coreClient, f.client)
	f.c = c

	return f
}

func (f *ingressControllerTestRunner) Run(t *testing.T, ing *networkingv1.Ingress) {
	key, err := cache.MetaNamespaceKeyFunc(ing)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := f.c.ProcessKey(key)
	f.actionMatcher()

	if syncErr != nil {
		t.Errorf("Expect to not occurred error: %+v", syncErr)
	}
}

func IsError(t *testing.T, actual, expect error) {
	if actual == nil {
		t.Errorf("Expect occurred error but not")
	} else if !xerrors.Is(actual, expect) {
		t.Logf("%+v", actual)
		t.Errorf("%q is not %q error", actual, expect)
	}
}

func excludeReadActions(actions []core.Action) []core.Action {
	ret := make([]core.Action, 0)
	for _, action := range actions {
		if len(action.GetNamespace()) == 0 {
			continue
		}

		switch action.GetVerb() {
		case "get", "list", "watch":
			continue
		}
		ret = append(ret, action)
	}

	return ret
}

func checkAction(t *testing.T, expected expectAction, actual core.Action) bool {
	t.Helper()

	if !(expected.Matches(actual.GetVerb(), actual.GetResource().Resource) && actual.GetSubresource() == expected.GetSubresource()) {
		t.Errorf("Expected %s %s Got %s %s", expected.GetVerb(), expected.GetResource().Resource, actual.GetVerb(), actual.GetResource().Resource)
		return false
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected.Action) {
		t.Errorf("Action has wrong type. Expected: %s. Got: %s", reflect.TypeOf(expected.Action).Name(), reflect.TypeOf(actual).Name())
		return false
	}

	return true
}

func normalizeName(name string) string {
	name = strings.Replace(name, "/", "-", -1)
	return name
}
