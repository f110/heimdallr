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

	mfake "github.com/coreos/prometheus-operator/pkg/client/versioned/fake"
	"github.com/jarcoal/httpmock"
	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/etcdserver/etcdserverpb"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/scale/scheme"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	proxyv1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/fake"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
)

type expectAction struct {
	core.Action
	Caller string
}

type commonTestRunner struct {
	t           *testing.T
	actions     []expectAction
	coreActions []expectAction

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

func (f *commonTestRunner) RegisterFixtures(objs ...interface{}) {
	for _, v := range objs {
		switch obj := v.(type) {
		case *proxyv1.Proxy:
			f.RegisterProxyFixture(obj)
		case *proxyv1.Backend:
			f.RegisterBackendFixture(obj)
		case *etcdv1alpha1.EtcdCluster:
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
		}
	}
}

func (f *commonTestRunner) RegisterProxyFixture(p *proxyv1.Proxy) {
	f.client.Tracker().Add(p)
	f.sharedInformerFactory.Proxy().V1().Proxies().Informer().GetIndexer().Add(p)
}

func (f *commonTestRunner) RegisterBackendFixture(b ...*proxyv1.Backend) {
	for _, v := range b {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Proxy().V1().Backends().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterRoleFixture(r ...*proxyv1.Role) {
	for _, v := range r {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Proxy().V1().Roles().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterRoleBindingFixture(r ...*proxyv1.RoleBinding) {
	for _, v := range r {
		f.client.Tracker().Add(v)
		f.sharedInformerFactory.Proxy().V1().RoleBindings().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterEtcdClusterFixture(ec *etcdv1alpha1.EtcdCluster) {
	f.client.Tracker().Add(ec)
	f.sharedInformerFactory.Etcd().V1alpha1().EtcdClusters().Informer().GetIndexer().Add(ec)
}

func (f *commonTestRunner) RegisterPodFixture(p ...*corev1.Pod) {
	for _, v := range p {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().Pods().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) RegisterSecretFixture(s ...*corev1.Secret) {
	for _, v := range s {
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

func (f *commonTestRunner) RegisterServiceFixture(s *corev1.Service) {
	f.coreClient.Tracker().Add(s)
	f.coreSharedInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(s)
}

func (f *commonTestRunner) RegisterConfigMapFixture(c ...*corev1.ConfigMap) {
	for _, v := range c {
		f.coreClient.Tracker().Add(v)
		f.coreSharedInformerFactory.Core().V1().ConfigMaps().Informer().GetIndexer().Add(v)
	}
}

func (f *commonTestRunner) ExpectCreateSecret() {
	action := core.NewCreateAction(scheme.SchemeGroupVersion.WithResource("secrets"), "", &corev1.Secret{})

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
	action := core.NewCreateAction(etcdv1alpha1.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha1.EtcdCluster{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateProxy() {
	action := core.NewUpdateAction(proxyv1.SchemeGroupVersion.WithResource("proxies"), "", &proxyv1.Proxy{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateProxyStatus() {
	action := core.NewUpdateAction(proxyv1.SchemeGroupVersion.WithResource("proxies"), "", &proxyv1.Proxy{})
	action.Subresource = "status"

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateBackend() {
	action := core.NewUpdateAction(proxyv1.SchemeGroupVersion.WithResource("backends"), "", &proxyv1.Backend{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateBackendStatus() {
	action := core.NewUpdateAction(proxyv1.SchemeGroupVersion.WithResource("backends"), "", &proxyv1.Backend{})
	action.Subresource = "status"

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateEtcdCluster() {
	action := core.NewUpdateAction(etcdv1alpha1.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha1.EtcdCluster{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateEtcdClusterStatus() {
	action := core.NewUpdateAction(etcdv1alpha1.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha1.EtcdCluster{})
	action.Subresource = "status"

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) ExpectUpdateConfigMap() {
	action := core.NewUpdateAction(corev1.SchemeGroupVersion.WithResource("configmaps"), "", &corev1.ConfigMap{})

	f.actions = append(f.actions, f.expectActionWithCaller(action))
}

func (f *commonTestRunner) expectActionWithCaller(action core.Action) expectAction {
	_, file, line, _ := runtime.Caller(2)
	return expectAction{Action: action, Caller: fmt.Sprintf("%s:%d", file, line)}
}

func (f *commonTestRunner) actionMatcher() {
	actions := filterInformerActions(f.client.Actions())
	for i, action := range actions {
		if len(f.actions) < i+1 {
			f.t.Errorf("%d unexpected actions:", len(actions)-len(f.actions))
			for _, v := range actions[i:] {
				f.t.Logf("unexpected action: %+v", v)
			}
			break
		}

		expectedAction := f.actions[i]
		checkAction(f.t, expectedAction, action)
	}

	if len(f.actions) > len(actions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.actions)-len(actions), f.actions[len(actions):])
	}

	kubeActions := filterInformerActions(f.coreClient.Actions())
	for i, action := range kubeActions {
		if len(f.coreActions) < i+1 {
			f.t.Errorf("%d unexpected actions:", len(kubeActions)-len(f.coreActions))
			for _, v := range kubeActions[i:] {
				f.t.Logf("unexpected action: %+v", v)
			}
			break
		}

		expectedAction := f.coreActions[i]
		checkAction(f.t, expectedAction, action)
	}

	if len(f.coreActions) > len(kubeActions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.coreActions)-len(kubeActions), f.coreActions[len(kubeActions):])
	}
}

type proxyControllerTestRunner struct {
	*commonTestRunner
	t *testing.T

	c *ProxyController

	cmClient *cmfake.Clientset
	mClient  *mfake.Clientset
}

func newProxyControllerTestRunner(t *testing.T) *proxyControllerTestRunner {
	f := &proxyControllerTestRunner{
		commonTestRunner: newCommonTestRunner(t),
		t:                t,
	}

	f.cmClient = cmfake.NewSimpleClientset()
	f.mClient = mfake.NewSimpleClientset()

	f.commonTestRunner.coreClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "cert-manager.io/v1alpha2",
			APIResources: []metav1.APIResource{
				{
					Kind: "Certificate",
				},
			},
		},
	}

	c, err := NewProxyController(context.Background(), f.sharedInformerFactory, f.coreSharedInformerFactory, f.coreClient, f.client, f.cmClient, f.mClient)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c

	return f
}

func (f *proxyControllerTestRunner) Run(t *testing.T, p *proxyv1.Proxy) {
	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncProxy(key)
	f.actionMatcher()

	if syncErr != nil {
		t.Errorf("Expect to not occurred error: %+v", syncErr)
	}
}

func (f *proxyControllerTestRunner) RunExpectError(t *testing.T, p *proxyv1.Proxy, expectErr error) {
	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncProxy(key)
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

func (f *githubControllerTestRunner) Run(t *testing.T, p *proxyv1.Backend) {
	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncBackend(key)
	f.actionMatcher()

	if syncErr != nil {
		t.Errorf("Expect to not occurred error: %+v", syncErr)
	}
}

func (f *githubControllerTestRunner) RunExpectError(t *testing.T, p *proxyv1.Backend, expectErr error) {
	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncBackend(key)
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

func (f *etcdControllerTestRunner) Run(t *testing.T, e *etcdv1alpha1.EtcdCluster) {
	key, err := cache.MetaNamespaceKeyFunc(e)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncEtcdCluster(key)
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

func IsError(t *testing.T, actual, expect error) {
	if !xerrors.Is(actual, expect) {
		t.Logf("%+v", actual)
		t.Errorf("%q is not %q error", actual, expect)
	}
}

func filterInformerActions(actions []core.Action) []core.Action {
	ret := make([]core.Action, 0)
	for _, action := range actions {
		if len(action.GetNamespace()) == 0 {
			continue
		}

		switch action.GetVerb() {
		case "list", "watch":
			switch action.GetResource().Resource {
			case "proxies", "etcdclusters", "backends", "roles", "rpcpermissions":
				continue
			case "jobs":
				continue
			}
		case "get":
			continue
		}
		ret = append(ret, action)
	}

	return ret
}

func checkAction(t *testing.T, expected expectAction, actual core.Action) {
	if !(expected.Matches(actual.GetVerb(), actual.GetResource().Resource) && actual.GetSubresource() == expected.GetSubresource()) {
		t.Errorf("Expected\n\t%#v\ngot\n\t%#v", expected, actual)
		return
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected.Action) {
		t.Errorf("Action has wrong type. Expected: %s. Got: %s", reflect.TypeOf(expected.Action).Name(), reflect.TypeOf(actual).Name())
		return
	}
}

func normalizeName(name string) string {
	name = strings.Replace(name, "/", "-", -1)
	return name
}
