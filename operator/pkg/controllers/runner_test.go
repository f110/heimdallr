package controllers

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"time"

	mfake "github.com/coreos/prometheus-operator/pkg/client/versioned/fake"
	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
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

	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
	"github.com/f110/lagrangian-proxy/operator/pkg/client/versioned/fake"
	informers "github.com/f110/lagrangian-proxy/operator/pkg/informers/externalversions"
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
	}
}

func (f *commonTestRunner) RegisterProxyFixture(p *proxyv1.Proxy) {
	f.client.Tracker().Add(p)
	f.sharedInformerFactory.Proxy().V1().Proxies().Informer().GetIndexer().Add(p)
}

func (f *commonTestRunner) RegisterBackendFixture(b *proxyv1.Backend) {
	f.client.Tracker().Add(b)
	f.sharedInformerFactory.Proxy().V1().Backends().Informer().GetIndexer().Add(b)
}

func (f *commonTestRunner) RegisterEtcdClusterFixture(ec *etcdv1alpha1.EtcdCluster) {
	f.client.Tracker().Add(ec)
	f.sharedInformerFactory.Etcd().V1alpha1().EtcdClusters().Informer().GetIndexer().Add(ec)
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

	c, err := New(context.Background(), f.sharedInformerFactory, f.coreSharedInformerFactory, f.coreClient, f.client, f.cmClient, f.mClient)
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

	c, err := NewGitHubController(f.sharedInformerFactory, f.coreSharedInformerFactory, f.coreClient, f.client)
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
