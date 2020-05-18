package controllers

import (
	"context"
	"reflect"
	"strings"
	"testing"

	mfake "github.com/coreos/prometheus-operator/pkg/client/versioned/fake"
	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
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
	f.proxyFixtures = append(f.proxyFixtures, p)
}

func (f *proxyControllerTestRunner) RegisterEtcdClusterFixture(ec *etcdv1alpha1.EtcdCluster) {
	f.etcdClusterFixture = append(f.etcdClusterFixture, ec)
}

func (f *proxyControllerTestRunner) RegisterSecretFixture(s *corev1.Secret) {
	f.secretFixtures = append(f.secretFixtures, s)
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

	switch a := actual.(type) {
	case core.CreateActionImpl:
		e, _ := expected.(core.CreateActionImpl)
		expObject := e.GetObject()
		object := a.GetObject()

		switch expV := expObject.(type) {
		case *etcdv1alpha1.EtcdCluster:
			if ok, d := EqualEtcdCluster(object.(*etcdv1alpha1.EtcdCluster), expV); !ok {
				t.Errorf("Action %s %s has wrong object\nDiff:\n %s", a.GetVerb(), a.GetResource().Resource, d)
			}
		case *corev1.Secret:
			if ok, msg := EqualSecret(object.(*corev1.Secret), expV); !ok {
				t.Errorf("Action %s %s has wrong object\n%s", a.GetVerb(), a.GetResource(), strings.Join(msg, "\n"))
			}
		default:
			if !reflect.DeepEqual(expObject, object) {
				t.Errorf("Action %s %s has wrong object\nDiff:\n %s",
					a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expObject, object))
			}
		}
	case core.UpdateActionImpl:
		e, _ := expected.(core.UpdateActionImpl)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("Action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expObject, object))
		}
	case core.PatchActionImpl:
		e, _ := expected.(core.PatchActionImpl)
		expPatch := e.GetPatch()
		patch := a.GetPatch()

		if !reflect.DeepEqual(expPatch, patch) {
			t.Errorf("Action %s %s has wrong patch\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expPatch, patch))
		}
	case core.ListActionImpl:
		e, _ := expected.(core.ListActionImpl)
		expListRest := e.GetListRestrictions()
		listRest := a.GetListRestrictions()

		if !reflect.DeepEqual(expListRest, listRest) {
			t.Errorf("Action %s %s has wrong option\n %s", a.GetVerb(), a.GetResource(), diff.ObjectGoPrintSideBySide(expListRest, listRest))
		}
	default:
		t.Errorf("Uncaptured Action %s %s, you should explicitly add a case to capture it",
			actual.GetVerb(), actual.GetResource().Resource)
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
			f.t.Errorf("%d unexpected actions: %+v", len(actions)-len(f.actions), actions[i:])
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
			f.t.Errorf("%d unexpected actions: %+v", len(kubeActions)-len(f.coreActions), kubeActions[i:])
			break
		}

		expectedAction := f.coreActions[i]
		checkAction(f.t, expectedAction, action)
	}

	if len(f.coreActions) > len(kubeActions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.coreActions)-len(kubeActions), f.coreActions[len(kubeActions):])
	}
}

func (f *proxyControllerTestRunner) ExpectCreateSecretAction(s *corev1.Secret) {
	action := core.NewCreateAction(scheme.SchemeGroupVersion.WithResource("secrets"), s.Namespace, s)

	f.coreActions = append(f.coreActions, action)
}

func (f *proxyControllerTestRunner) ExpectCreateEtcdClusterAction(ec *etcdv1alpha1.EtcdCluster) {
	action := core.NewCreateAction(etcdv1alpha1.SchemeGroupVersion.WithResource("etcdclusters"), ec.Namespace, ec)

	f.actions = append(f.actions, action)
}

func (f *proxyControllerTestRunner) ExpectUpdateProxyStatusAction(proxy *proxyv1.Proxy) {
	action := core.NewUpdateAction(proxyv1.SchemeGroupVersion.WithResource("proxies"), proxy.Namespace, proxy)
	action.Subresource = "status"

	f.actions = append(f.actions, action)
}

func (f *proxyControllerTestRunner) prepareRun() {
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
}

func (f *proxyControllerTestRunner) Run(t *testing.T, p *proxyv1.Proxy) {
	f.prepareRun()

	key, err := cache.MetaNamespaceKeyFunc(p)
	if err != nil {
		t.Fatal(err)
	}

	syncErr := f.c.syncProxy(key)
	f.actionMatcher()

	assert.Nil(t, syncErr)
}

func (f *proxyControllerTestRunner) RunExpectError(t *testing.T, p *proxyv1.Proxy, expectErr error) {
	f.prepareRun()

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
		t.Errorf("%q is not %q error", actual, expect)
	}
}
