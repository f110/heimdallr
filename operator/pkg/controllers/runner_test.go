package controllers

import (
	"context"
	"reflect"
	"testing"

	mfake "github.com/coreos/prometheus-operator/pkg/client/versioned/fake"
	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/scale/scheme"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
	"github.com/f110/lagrangian-proxy/operator/pkg/client/versioned/fake"
)

type proxyControllerTestRunner struct {
	t           *testing.T
	actions     []core.Action
	coreActions []core.Action

	proxyFixtures      []*proxyv1.Proxy
	etcdClusterFixture []*etcdv1alpha1.EtcdCluster
	secretFixtures     []*corev1.Secret
	serviceFixtures    []*corev1.Service
	configmapFixtures  []*corev1.ConfigMap
	deploymentFixtures []*appsv1.Deployment
	c                  *ProxyController

	client     *fake.Clientset
	coreClient *k8sfake.Clientset
	cmClient   *cmfake.Clientset
	mClient    *mfake.Clientset
}

func newFixture(t *testing.T) *proxyControllerTestRunner {
	f := &proxyControllerTestRunner{t: t, actions: make([]core.Action, 0), coreActions: make([]core.Action, 0)}

	f.client = fake.NewSimpleClientset()
	f.coreClient = k8sfake.NewSimpleClientset()
	f.cmClient = cmfake.NewSimpleClientset()
	f.mClient = mfake.NewSimpleClientset()

	f.coreClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "cert-manager.io/v1alpha2",
			APIResources: []metav1.APIResource{
				{
					Kind: "Certificate",
				},
			},
		},
	}

	c, err := New(context.Background(), f.coreClient, f.client, f.cmClient, f.mClient)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c

	return f
}

func (f *proxyControllerTestRunner) RegisterProxyFixture(p *proxyv1.Proxy) {
	f.client.Tracker().Add(p)
	f.proxyFixtures = append(f.proxyFixtures, p)
}

func (f *proxyControllerTestRunner) RegisterEtcdClusterFixture(ec *etcdv1alpha1.EtcdCluster) {
	f.client.Tracker().Add(ec)
	f.etcdClusterFixture = append(f.etcdClusterFixture, ec)
}

func (f *proxyControllerTestRunner) RegisterSecretFixture(s *corev1.Secret) {
	f.coreClient.Tracker().Add(s)
	f.secretFixtures = append(f.secretFixtures, s)
}

func (f *proxyControllerTestRunner) RegisterDeploymentFixture(d *appsv1.Deployment) {
	f.coreClient.Tracker().Add(d)
	f.deploymentFixtures = append(f.deploymentFixtures, d)
}

func (f *proxyControllerTestRunner) RegisterServiceFixture(s *corev1.Service) {
	f.coreClient.Tracker().Add(s)
	f.serviceFixtures = append(f.serviceFixtures, s)
}

func (f *proxyControllerTestRunner) RegisterConfigMapFixture(c *corev1.ConfigMap) {
	f.coreClient.Tracker().Add(c)
	f.configmapFixtures = append(f.configmapFixtures, c)
}

func checkAction(t *testing.T, expected, actual core.Action) {
	if !(expected.Matches(actual.GetVerb(), actual.GetResource().Resource) && actual.GetSubresource() == expected.GetSubresource()) {
		t.Errorf("Expected\n\t%#v\ngot\n\t%#v", expected, actual)
		return
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		t.Errorf("Action has wrong type. Expected: %t. Got: %t", expected, actual)
		return
	}
}

func (f *proxyControllerTestRunner) filterInformerActions(actions []core.Action) []core.Action {
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

func (f *proxyControllerTestRunner) actionMatcher() {
	actions := f.filterInformerActions(f.client.Actions())
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

	kubeActions := f.filterInformerActions(f.coreClient.Actions())
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

func (f *proxyControllerTestRunner) ExpectCreateSecret() {
	action := core.NewCreateAction(scheme.SchemeGroupVersion.WithResource("secrets"), "", &corev1.Secret{})

	f.coreActions = append(f.coreActions, action)
}

func (f *proxyControllerTestRunner) ExpectCreateDeployment() {
	action := core.NewCreateAction(appsv1.SchemeGroupVersion.WithResource("deployments"), "", &appsv1.Deployment{})

	f.coreActions = append(f.coreActions, action)
}

func (f *proxyControllerTestRunner) ExpectCreateService() {
	action := core.NewCreateAction(corev1.SchemeGroupVersion.WithResource("services"), "", &corev1.Service{})

	f.coreActions = append(f.coreActions, action)
}

func (f *proxyControllerTestRunner) ExpectCreateConfigMap() {
	action := core.NewCreateAction(corev1.SchemeGroupVersion.WithResource("configmaps"), "", &corev1.ConfigMap{})

	f.coreActions = append(f.coreActions, action)
}

func (f *proxyControllerTestRunner) ExpectCreatePodDisruptionBudget() {
	action := core.NewCreateAction(policyv1beta1.SchemeGroupVersion.WithResource("poddisruptionbudgets"), "", &policyv1beta1.PodDisruptionBudget{})

	f.coreActions = append(f.coreActions, action)
}

func (f *proxyControllerTestRunner) ExpectCreateEtcdCluster() {
	action := core.NewCreateAction(etcdv1alpha1.SchemeGroupVersion.WithResource("etcdclusters"), "", &etcdv1alpha1.EtcdCluster{})

	f.actions = append(f.actions, action)
}

func (f *proxyControllerTestRunner) ExpectUpdateProxyStatus() {
	action := core.NewUpdateAction(proxyv1.SchemeGroupVersion.WithResource("proxies"), "", &proxyv1.Proxy{})
	action.Subresource = "status"

	f.actions = append(f.actions, action)
}

func (f *proxyControllerTestRunner) prepareToRun() {
	proxyInformer := f.c.sharedInformer.Proxy().V1().Proxies().Informer()
	for _, p := range f.proxyFixtures {
		proxyInformer.GetIndexer().Add(p)
	}

	ecInformer := f.c.sharedInformer.Etcd().V1alpha1().EtcdClusters().Informer()
	for _, v := range f.etcdClusterFixture {
		ecInformer.GetIndexer().Add(v)
	}

	secretInformer := f.c.coreSharedInformer.Core().V1().Secrets().Informer()
	for _, s := range f.secretFixtures {
		secretInformer.GetIndexer().Add(s)
	}

	serviceInformer := f.c.coreSharedInformer.Core().V1().Services().Informer()
	for _, s := range f.serviceFixtures {
		serviceInformer.GetIndexer().Add(s)
	}

	configmapInformer := f.c.coreSharedInformer.Core().V1().ConfigMaps().Informer()
	for _, s := range f.configmapFixtures {
		configmapInformer.GetIndexer().Add(s)
	}

	deployemtInformer := f.c.coreSharedInformer.Apps().V1().Deployments().Informer()
	for _, v := range f.deploymentFixtures {
		deployemtInformer.GetIndexer().Add(v)
	}
}

func (f *proxyControllerTestRunner) Run(t *testing.T, p *proxyv1.Proxy) {
	f.prepareToRun()

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
	f.prepareToRun()

	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncProxy(key)
	f.actionMatcher()

	IsError(t, syncErr, expectErr)
}

func IsError(t *testing.T, actual, expect error) {
	if !xerrors.Is(actual, expect) {
		t.Logf("%+v", actual)
		t.Errorf("%q is not %q error", actual, expect)
	}
}
