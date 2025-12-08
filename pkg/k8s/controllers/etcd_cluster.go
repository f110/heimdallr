package controllers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/kubeproto/go/apis/batchv1"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/apis/rbacv1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/varptr"
	"go.f110.dev/heimdallr/pkg/version"
)

type InternalState string

const (
	InternalStateCreatingFirstMember InternalState = "creatingFirstNode"
	InternalStateCreatingMembers     InternalState = "creatingMembers"
	InternalStateRepair              InternalState = "repair"
	InternalStateRestore             InternalState = "restore"
	InternalStatePreparingUpdate     InternalState = "preparingUpdate"
	InternalStateUpdatingMember      InternalState = "updatingMember"
	InternalStateTeardownUpdating    InternalState = "teardownUpdating"
	InternalStateRunning             InternalState = "running"
)

const (
	EtcdClientPort  = 2379
	EtcdPeerPort    = 2380
	EtcdMetricsPort = 2381
)

const addMemberScript = `
ETCDCTL_OPT="--cacert={{ .CACert }} --cert={{ .Cert }} --key={{ .Key }} --endpoints={{ .Endpoint }}"
MEMBER_LIST=$(/usr/local/bin/etcdctl ${ETCDCTL_OPT} member list)
if echo "${MEMBER_LIST}" | grep -sq "{{ .Name }}"; then
	MEMBER_ID=$(echo "${MEMBER_LIST}" | grep "{{ .Name }}" | cut -d, -f1)
	/usr/local/bin/etcdctl ${ETCDCTL_OPT} member update "${MEMBER_ID}" --peer-urls={{ .PeerUrl }}
else
/usr/local/bin/etcdctl ${ETCDCTL_OPT} \
	member add {{ .Name }} \
	--peer-urls={{ .PeerUrl }}
fi
`

const restoreDataScript = `
ETCDCTL_OPT="--cacert={{ .CACert }} --cert={{ .Cert }} --key={{ .Key }} --endpoints={{ .Endpoint }}"
/usr/local/bin/etcdctl ${ETCDCTL_OPT} snapshot restore {{ .DataFile }} \
	--data-dir=/data/{{ .Name }}.etcd \
	--name={{ .Name }} \
	--initial-cluster={{ .Name }}={{ .PeerUrl }} \
	--initial-advertise-peer-urls={{ .AdvertisePeerUrl }}
`

const (
	caSecretCertName               = "ca.crt"
	caSecretPrivateKeyName         = "ca.key"
	serverCertSecretCertName       = "tls.crt"
	serverCertSecretPrivateKeyName = "tls.key"
	clientCertSecretCACertName     = "ca.crt"
	clientCertSecretCertName       = "client.crt"
	clientCertSecretPrivateKeyName = "client.key"
)

type MockOption struct {
	Cluster     clientv3.Cluster
	Maintenance clientv3.Maintenance
}

type EtcdCluster struct {
	*etcdv1alpha2.EtcdCluster

	ClusterDomain string

	fetchedChildResources bool
	ownedPods             []*corev1.Pod
	ownedPVC              map[string]*corev1.PersistentVolumeClaim
	caSecret              *corev1.Secret
	serverCertSecret      *Certificate
	clientCertSecret      *corev1.Secret
	podsOnce              sync.Once
	expectedPods          []*EtcdMember

	log     *zap.Logger
	mockOpt *MockOption
}

func NewEtcdCluster(c *etcdv1alpha2.EtcdCluster, clusterDomain string, log *zap.Logger, mockOpt *MockOption) *EtcdCluster {
	return &EtcdCluster{
		EtcdCluster:   c.DeepCopy(),
		ClusterDomain: clusterDomain,
		log:           log,
		mockOpt:       mockOpt,
	}
}

func (c *EtcdCluster) Init(secretLister *k8sclient.CoreV1SecretLister) {
	caSecret, err := secretLister.Get(c.Namespace, c.CASecretName())
	if err == nil {
		c.caSecret = caSecret
	}

	certS, err := secretLister.Get(c.Namespace, c.ServerCertSecretName())
	if err == nil {
		tlsKeyPair, err := tls.X509KeyPair(certS.Data[serverCertSecretCertName], certS.Data[serverCertSecretPrivateKeyName])
		if err != nil {
			c.log.Warn("Failed decode a server certificate", zap.String("name", certS.Name))
		}

		serverCert, err := NewCertificate(certS, tlsKeyPair)
		if err != nil {
			c.log.Warn("Failed encode a private key", zap.Error(err))
		}
		c.serverCertSecret = &serverCert
	}

	clientS, err := secretLister.Get(c.Namespace, c.ClientCertSecretName())
	if err == nil {
		c.clientCertSecret = clientS
	}
}

func (c *EtcdCluster) EtcdVersion() string {
	if c.Spec.Version != "" {
		return c.Spec.Version
	} else {
		return defaultEtcdVersion
	}
}

func (c *EtcdCluster) SetOwnedPods(pods []*corev1.Pod) {
	sort.Slice(pods, func(i, j int) bool {
		return pods[i].Name < pods[j].Name
	})
	c.ownedPods = pods
}

func (c *EtcdCluster) SetCASecret(ca *corev1.Secret) {
	c.caSecret = ca
}

func (c *EtcdCluster) SetServerCertSecret(cert *corev1.Secret) {
	tlsKeyPair, err := tls.X509KeyPair(cert.Data[serverCertSecretCertName], cert.Data[serverCertSecretPrivateKeyName])
	if err != nil {
		c.log.Warn("Failed decode a server certificate", zap.String("name", cert.Name))
	}

	serverCert, err := NewCertificate(cert, tlsKeyPair)
	if err != nil {
		c.log.Warn("Failed encode a private key", zap.Error(err))
	}
	c.serverCertSecret = &serverCert
}

func (c *EtcdCluster) SetClientCertSecret(cert *corev1.Secret) {
	c.clientCertSecret = cert
}

func (c *EtcdCluster) GetOwnedPods(podLister *k8sclient.CoreV1PodLister, pvcLister *k8sclient.CoreV1PersistentVolumeClaimLister) error {
	if c.UID == "" {
		return nil
	}

	r, err := labels.NewRequirement(etcd.LabelNameClusterName, selection.Equals, []string{c.Name})
	if err != nil {
		return xerrors.WithStack(err)
	}

	pods, err := podLister.List(c.Namespace, labels.NewSelector().Add(*r))
	if err != nil {
		return xerrors.WithStack(err)
	}
	owned := make([]*corev1.Pod, 0)
	for _, v := range pods {
		if len(v.OwnerReferences) == 0 {
			continue
		}
		if !v.DeletionTimestamp.IsZero() {
			continue
		}
		for _, ref := range v.OwnerReferences {
			if ref.UID == c.UID {
				owned = append(owned, v.DeepCopy())
			}
		}
	}
	c.ownedPods = owned

	pvcs, err := pvcLister.List(c.Namespace, labels.Everything())
	if err != nil {
		return xerrors.WithStack(err)
	}
	myPVC := make(map[string]*corev1.PersistentVolumeClaim, 0)
	for _, v := range pvcs {
		if len(v.OwnerReferences) == 0 {
			continue
		}
		for _, ref := range v.OwnerReferences {
			if ref.UID == c.UID {
				myPVC[v.Name] = v.DeepCopy()
			}
		}
	}
	c.ownedPVC = myPVC

	c.fetchedChildResources = true
	return nil
}

func (c *EtcdCluster) CA() (*corev1.Secret, error) {
	if c.caSecret != nil {
		return c.caSecret, nil
	}

	caCert, privateKey, err := cert.CreateCertificateAuthority(fmt.Sprintf("%s-ca", c.Name), "", "", "", "ecdsa")
	if err != nil {
		return nil, err
	}
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	caCertBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})

	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(c.CASecretName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.Data(caSecretCertName, caCertBuf),
		k8sfactory.Data(caSecretPrivateKeyName, privateKeyBuf),
	)
	c.caSecret = secret
	return secret, nil
}

func (c *EtcdCluster) ServerCert() (Certificate, error) {
	certPair, err := c.parseCASecret(c.caSecret)
	if err != nil {
		return Certificate{}, err
	}

	serverCert, serverPrivateKey, err := cert.GenerateMutualTLSCertificate(
		certPair.Cert, certPair.PrivateKey,
		c.DNSNames(),
		[]string{"127.0.0.1"},
	)
	if err != nil {
		return Certificate{}, err
	}
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(serverPrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return Certificate{}, xerrors.WithStack(err)
	}
	serverCertBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})
	tlsKeyPair, err := tls.X509KeyPair(serverCertBuf, privateKeyBuf)
	if err != nil {
		return Certificate{}, err
	}

	return NewCertificate(nil, tlsKeyPair)
}

func (c *EtcdCluster) DNSNames() []string {
	dnsNames := make([]string, 0)
	dnsNames = append(dnsNames,
		fmt.Sprintf("%s.%s.svc.%s", c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain),
		fmt.Sprintf("%s.%s.svc.%s", c.ClientServiceName(), c.Namespace, c.ClusterDomain),
		fmt.Sprintf("%s.%s.svc", c.ClientServiceName(), c.Namespace),
		fmt.Sprintf("*.%s.pod.%s", c.Namespace, c.ClusterDomain),
	)

	return dnsNames
}

func (c *EtcdCluster) ServerCertSecret() (*corev1.Secret, error) {
	if c.serverCertSecret != nil {
		return c.serverCertSecret.ToSecret(), nil
	}

	serverCert, err := c.ServerCert()
	if err != nil {
		return nil, err
	}
	c.serverCertSecret = &serverCert

	secret := k8sfactory.SecretFactory(
		serverCert.ToSecret(),
		k8sfactory.Name(c.ServerCertSecretName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
	)
	c.serverCertSecret.secret = secret
	return secret, nil
}

func (c *EtcdCluster) CASecretName() string {
	return fmt.Sprintf("etcd-%s-ca", c.Name)
}

func (c *EtcdCluster) ServerCertSecretName() string {
	return fmt.Sprintf("etcd-%s-server-cert", c.Name)
}

func (c *EtcdCluster) ClientCertSecret() (*corev1.Secret, error) {
	if c.clientCertSecret != nil {
		return c.clientCertSecret, nil
	}

	certPair, err := c.parseCASecret(c.caSecret)
	if err != nil {
		return nil, err
	}

	clientCert, clientPrivateKey, err := cert.GenerateMutualTLSCertificate(
		certPair.Cert, certPair.PrivateKey,
		[]string{
			fmt.Sprintf("%s.%s.%s.svc.%s", c.Name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain),
		},
		nil,
	)
	if err != nil {
		return nil, err
	}
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(clientPrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	clientCertBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})

	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(c.ClientCertSecretName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.Data(clientCertSecretCACertName, c.caSecret.Data[caSecretCertName]),
		k8sfactory.Data(clientCertSecretCertName, clientCertBuf),
		k8sfactory.Data(clientCertSecretPrivateKeyName, privateKeyBuf),
	)
	c.clientCertSecret = secret
	return secret, nil
}

func (c *EtcdCluster) ClientCertSecretName() string {
	return fmt.Sprintf("etcd-%s-client-cert", c.Name)
}

func (c *EtcdCluster) ServiceAccount() *corev1.ServiceAccount {
	return k8sfactory.ServiceAccountFactory(nil,
		k8sfactory.Name(c.ServiceAccountName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
	)
}

func (c *EtcdCluster) ServiceAccountName() string {
	return fmt.Sprintf("%s-etcd", c.Name)
}

func (c *EtcdCluster) EtcdRole() *rbacv1.Role {
	return k8sfactory.RoleFactory(nil,
		k8sfactory.Name(fmt.Sprintf("%s-etcd", c.Name)),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.PolicyRule([]string{"*"}, []string{"pods"}, []string{"list", "watch"}),
	)
}

func (c *EtcdCluster) EtcdRoleBinding() *rbacv1.RoleBinding {
	return k8sfactory.RoleBindingFactory(nil,
		k8sfactory.Name(fmt.Sprintf("%s-etcd", c.Name)),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.Role(c.EtcdRole()),
		k8sfactory.Subject(c.ServiceAccount()),
	)
}

func (c *EtcdCluster) DefragmentCronJob() *batchv1.CronJob {
	caVolume := k8sfactory.NewSecretVolumeSource(
		"ca",
		"/etc/etcd-ca",
		c.caSecret,
		corev1.KeyToPath{Key: caSecretCertName, Path: caSecretCertName},
	)
	clientCertVolume := k8sfactory.NewSecretVolumeSource("cert", "/etc/etcd-client", c.clientCertSecret)

	cont := k8sfactory.ContainerFactory(nil,
		k8sfactory.Name("etcdctl"),
		k8sfactory.Image(
			fmt.Sprintf("gcr.io/etcd-development/etcd:%s", c.Spec.Version),
			[]string{"/usr/local/bin/etcdctl",
				fmt.Sprintf("--endpoints=https://%s.%s.svc.%s:%d", c.ClientServiceName(), c.Namespace, c.ClusterDomain, EtcdClientPort),
				fmt.Sprintf("--cacert=/etc/etcd-ca/%s", caCertificateFilename),
				fmt.Sprintf("--cert=/etc/etcd-client/%s", clientCertSecretCertName),
				fmt.Sprintf("--key=/etc/etcd-client/%s", clientCertSecretPrivateKeyName),
				"defrag",
			},
		),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(clientCertVolume),
	)
	pod := k8sfactory.PodFactory(nil,
		k8sfactory.Container(cont),
		k8sfactory.RestartPolicy(corev1.RestartPolicyNever),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(clientCertVolume),
	)
	job := k8sfactory.JobFactory(nil,
		k8sfactory.Label(
			etcd.LabelNameClusterName, c.Name,
			etcd.LabelNameRole, "defragment",
		),
		k8sfactory.Pod(pod),
	)

	return k8sfactory.CronJobFactory(nil,
		k8sfactory.Name(c.DefragmentCronJobName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.Schedule(c.Spec.DefragmentSchedule),
		k8sfactory.Job(job),
	)
}

func (c *EtcdCluster) DefragmentCronJobName() string {
	return fmt.Sprintf("etcd-%s-defragment", c.Name)
}

// AllMembers returns all members of etcd, regardless of status
func (c *EtcdCluster) AllMembers() []*EtcdMember {
	c.podsOnce.Do(func() {
		etcdVersion := defaultEtcdVersion
		if c.Spec.Version != "" {
			etcdVersion = c.Spec.Version
		}

		var initialClusters []string
		var updating bool
		result := make([]*EtcdMember, 0)
		pods := make(map[string]*corev1.Pod)
		for _, v := range c.ownedPods {
			pods[v.Name] = v
			if metav1.HasAnnotation(v.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
				updating = true
			}
			pvc := c.ownedPVC[v.Name]

			oldVersion := false
			_, err := strconv.Atoi(strings.TrimPrefix(v.Name, c.Name+"-"))
			if err != nil {
				oldVersion = true
			}

			result = append(result, &EtcdMember{Pod: v, PersistentVolumeClaim: pvc, OldVersion: oldVersion})
			if !v.CreationTimestamp.IsZero() && v.Status.Phase == corev1.PodPhaseRunning {
				initialClusters = append(initialClusters, fmt.Sprintf("%s=https://%s.%s.pod.%s:%d", v.Name, strings.Replace(v.Status.PodIP, ".", "-", -1), c.Namespace, c.ClusterDomain, EtcdPeerPort))
			}
		}

		expectMemberCount := c.Spec.Members
		if updating {
			expectMemberCount++
		}
		for i := 1; i <= expectMemberCount; i++ {
			clusterState := "existing"
			if i == 1 && c.CurrentInternalState() == InternalStateCreatingFirstMember {
				clusterState = "new"
				initialClusters = []string{}
			}

			newPod := c.newEtcdPod(
				etcdVersion,
				i,
				clusterState,
				append(initialClusters, fmt.Sprintf("$(MY_POD_NAME)=https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdPeerPort)),
				false,
			)
			if _, ok := pods[newPod.Name]; ok {
				continue
			}

			result = append(result, c.newEtcdMember(newPod))
		}

		switch c.CurrentInternalState() {
		case InternalStatePreparingUpdate, InternalStateUpdatingMember:
			if !c.HasTemporaryMember() {
				temporaryMemberPod := c.newTemporaryMemberPodSpec(etcdVersion, initialClusters)
				result = append(result, c.newEtcdMember(temporaryMemberPod))
			}
		}

		sort.Slice(result, func(i, j int) bool {
			if result[i].OldVersion {
				if !result[j].OldVersion {
					return true
				}
			} else {
				if result[j].OldVersion {
					return false
				}
			}
			return result[i].Pod.Name < result[j].Pod.Name
		})
		c.expectedPods = result
	})

	return c.expectedPods
}

func (c *EtcdCluster) PermanentMembers() []*corev1.Pod {
	result := make([]*corev1.Pod, 0, len(c.ownedPods))
	for _, v := range c.ownedPods {
		if metav1.HasAnnotation(v.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
			continue
		}
		result = append(result, v)
	}

	return result
}

func (c *EtcdCluster) TemporaryMember() *EtcdMember {
	for _, p := range c.ownedPods {
		if metav1.HasAnnotation(p.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
			return &EtcdMember{Pod: p}
		}
	}

	return nil
}

func (c *EtcdCluster) HasTemporaryMember() bool {
	return c.TemporaryMember() != nil
}

func (c *EtcdCluster) AllExistMembers() []*corev1.Pod {
	return c.ownedPods
}

func (c *EtcdCluster) ShouldUpdate(pod *corev1.Pod) bool {
	if metav1.HasAnnotation(pod.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
		return false
	}

	if pod.CreationTimestamp.IsZero() {
		c.log.Debug("Should be updated because not created yet", zap.String("pod.name", pod.Name))
		return true
	}

	etcdVersion := pod.Labels[etcd.LabelNameEtcdVersion]
	if (c.Spec.Version != "" && etcdVersion != c.Spec.Version) || (c.Spec.Version == "" && etcdVersion != defaultEtcdVersion) {
		c.log.Debug("Older version", zap.String("pod.name", pod.Name), zap.String("version", etcdVersion))
		return true
	}

	if v, ok := pod.Annotations[etcd.AnnotationKeyServerCertificate]; ok {
		if c.ShouldUpdateServerCertificate([]byte(v)) {
			c.log.Debug("Certificate is outdated", zap.String("pod.name", pod.Name))
			return true
		}
	} else if !ok {
		// If pod doesn't have AnnotationKeyServerCertificate, pod should be updated.
		c.log.Debug("Don't have AnnotationKeyServerCertificate", zap.String("pod.name", pod.Name))
		return true
	}
	if c.Spec.Template != nil && c.Spec.Template.Metadata != nil {
		if !c.EqualAnnotation(pod.Annotations, c.Spec.Template.Metadata.Annotations) {
			return true
		}
		if !c.EqualLabels(pod.Labels, c.Spec.Template.Metadata.Labels) {
			return true
		}
	}

	return false
}

func copyMap(a map[string]string) map[string]string {
	n := make(map[string]string)
	for k, v := range a {
		n[k] = v
	}
	return n
}

func (c *EtcdCluster) EqualAnnotation(a, b map[string]string) bool {
	if a == nil && b == nil {
		return true
	}

	newA := copyMap(a)
	c.normalizeAnnotation(newA)
	newB := copyMap(b)
	c.normalizeAnnotation(newB)

	return reflect.DeepEqual(newA, newB)
}

func (c *EtcdCluster) normalizeAnnotation(a map[string]string) {
	delete(a, etcd.AnnotationKeyServerCertificate)
	delete(a, etcd.AnnotationKeyTemporaryMember)
	delete(a, etcd.PodAnnotationKeyRunningAt)
}

// EqualLabels reports whether a and b are "semantic equal".
func (c *EtcdCluster) EqualLabels(a, b map[string]string) bool {
	if a == nil && b == nil {
		return true
	}

	newA := copyMap(a)
	c.normalizeLabel(newA)
	newB := copyMap(b)
	c.normalizeLabel(newB)

	return reflect.DeepEqual(newA, newB)
}

func (c *EtcdCluster) normalizeLabel(a map[string]string) {
	delete(a, etcd.LabelNameRole)
	delete(a, etcd.LabelNameClusterName)
	delete(a, etcd.LabelNameEtcdVersion)
}

func (c *EtcdCluster) ShouldUpdateServerCertificate(certPem []byte) bool {
	b, _ := pem.Decode(certPem)
	podCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		c.log.Warn("Could not parse a certificate")
		return true
	}

	if time.Now().Add(90 * 24 * time.Hour).After(podCert.NotAfter) {
		c.log.Debug("The expiration date of the certificate is approaching", zap.Time("not_after", podCert.NotAfter))
		return true
	}

	expectDNSName := c.DNSNames()
	if len(podCert.DNSNames) != len(expectDNSName) {
		c.log.Debug("cert doesn't have enough DNSNames")
		return true
	}

	for i, v := range podCert.DNSNames {
		if expectDNSName[i] != v {
			c.log.Debug("Unexpected DNSName", zap.String("expect", expectDNSName[i]), zap.String("got", v))
			return true
		}
	}

	return false
}

func (c *EtcdCluster) ShouldUpdateClientCertificate(certPem []byte) bool {
	b, _ := pem.Decode(certPem)
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		c.log.Warn("Could not parse the certificate")
		return true
	}

	if time.Now().Add(90 * 24 * time.Hour).After(clientCert.NotAfter) {
		c.log.Debug("The expiration date of the certificate is approaching", zap.Time("not_after", clientCert.NotAfter))
		return true
	}

	return false
}

func (c *EtcdCluster) NeedRepair(pod *corev1.Pod) bool {
	onceRunning := metav1.HasAnnotation(pod.ObjectMeta, etcd.PodAnnotationKeyRunningAt)
	creationTimestamp := pod.CreationTimestamp
	if creationTimestamp == nil {
		creationTimestamp = varptr.Ptr(metav1.NewTime(time.Time{}))
	}
	// If the Pod has never been running once, There is no need to repair it.
	// But there is need to repair if the age of Pod exceeds 5 minutes
	if !onceRunning && creationTimestamp.After(time.Now().Add(-5*time.Minute)) && pod.Status.Phase != corev1.PodPhaseFailed {
		return false
	}

	switch pod.Status.Phase {
	case corev1.PodPhaseFailed, corev1.PodPhaseSucceeded:
		return true
	case corev1.PodPhaseRunning:
		needRepair := false
		for _, cont := range pod.Status.ContainerStatuses {
			if !cont.Ready {
				needRepair = true
			}
		}
		return needRepair
	default:
		return false
	}
}

func (c *EtcdCluster) ServerDiscoveryServiceName() string {
	return fmt.Sprintf("%s-discovery", c.Name)
}

func (c *EtcdCluster) DiscoveryService() *corev1.Service {
	return k8sfactory.ServiceFactory(nil,
		k8sfactory.Name(c.ServerDiscoveryServiceName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.Label(etcd.LabelNameClusterName, c.Name),
		k8sfactory.ClusterIP,
		k8sfactory.IPNone,
		k8sfactory.Selector(etcd.LabelNameClusterName, c.Name),
		k8sfactory.Port("etcd-server-ssl", corev1.ProtocolTCP, EtcdPeerPort),
		k8sfactory.Port("etcd-client-ssl", corev1.ProtocolTCP, EtcdClientPort),
	)
}

func (c *EtcdCluster) ClientServiceName() string {
	return fmt.Sprintf("%s-client", c.Name)
}

func (c *EtcdCluster) ClientService() *corev1.Service {
	return k8sfactory.ServiceFactory(nil,
		k8sfactory.Name(c.ClientServiceName()),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.ControlledBy(c.EtcdCluster, scheme.Scheme),
		k8sfactory.Label(etcd.LabelNameClusterName, c.Name),
		k8sfactory.ClusterIP,
		k8sfactory.Selector(etcd.LabelNameClusterName, c.Name),
		k8sfactory.Port("https", corev1.ProtocolTCP, EtcdClientPort),
	)
}

func (c *EtcdCluster) CurrentPhase() etcdv1alpha2.EtcdClusterPhase {
	if len(c.ownedPods) == 0 {
		return etcdv1alpha2.EtcdClusterPhasePending
	}

	if len(c.ownedPods) == 1 && !c.IsPodReady(c.ownedPods[0]) {
		return etcdv1alpha2.EtcdClusterPhaseInitializing
	}

	if len(c.ownedPods) < c.Spec.Members {
		if c.Status.LastReadyTransitionTime.IsZero() || !c.Status.CreatingCompleted {
			return etcdv1alpha2.EtcdClusterPhaseCreating
		} else {
			c.log.Debug("The number of pods is not enough but LastReadyTransitionTime is not zero", zap.Int("ownedPods.len", len(c.ownedPods)))
			return etcdv1alpha2.EtcdClusterPhaseDegrading
		}
	}

	if c.HasTemporaryMember() {
		return etcdv1alpha2.EtcdClusterPhaseUpdating
	}

	for _, pod := range c.ownedPods {
		if c.NeedRepair(pod) {
			c.log.Debug("Need repair pod", zap.String("pod.name", pod.Name), zap.String("pod.Status.Phase", string(pod.Status.Phase)))
			return etcdv1alpha2.EtcdClusterPhaseDegrading
		}

		if !c.IsPodReady(pod) {
			if c.Status.LastReadyTransitionTime.IsZero() {
				return etcdv1alpha2.EtcdClusterPhaseCreating
			} else {
				c.log.Debug("Pod is not ready", zap.String("pod.name", pod.Name), zap.String("pod.Status.Phase", string(pod.Status.Phase)))
				if c.Status.CreatingCompleted {
					return etcdv1alpha2.EtcdClusterPhaseDegrading
				} else {
					return etcdv1alpha2.EtcdClusterPhaseCreating
				}
			}
		}
	}

	return etcdv1alpha2.EtcdClusterPhaseRunning
}

func (c *EtcdCluster) CurrentInternalState() InternalState {
	if c.Status.LastReadyTransitionTime.IsZero() {
		return c.currentInternalStateCreating()
	}

	needRepair := false
	canRepair := false
	if len(c.ownedPods) == 0 {
		needRepair = true
		canRepair = false
	} else {
		for _, p := range c.ownedPods {
			if !needRepair && c.NeedRepair(p) {
				needRepair = true
				continue
			}
		}

		if needRepair {
			if len(c.ownedPods) > c.Spec.Members/2+1 {
				numOfRunningPods := 0
				for _, p := range c.ownedPods {
					if p.Status.Phase != corev1.PodPhaseRunning {
						continue
					}
					numOfRunningPods++
				}
				canRepair = numOfRunningPods >= c.Spec.Members/2+1
			}
		}
	}
	if needRepair {
		if canRepair {
			return InternalStateRepair
		}

		ok := false
		if c.Status.Backup != nil {
			for _, v := range c.Status.Backup.History {
				if v.Succeeded {
					ok = true
					break
				}
			}
			if ok {
				return InternalStateRestore
			}
		}

		// TODO: Handle this case
		c.log.Info("TODO: Need handle this case")
		return InternalStateRunning
	}

	// Cluster updating works in progress
	if c.HasTemporaryMember() {
		return c.currentInternalStateUpdating()
	}

	for _, p := range c.ownedPods {
		if !c.IsPodReady(p) {
			if c.Status.LastReadyTransitionTime.IsZero() || !c.HasTemporaryMember() {
				return InternalStateCreatingMembers
			} else {
				return InternalStateUpdatingMember
			}
		}
	}

	for _, p := range c.ownedPods {
		if c.ShouldUpdate(p) {
			if len(c.PermanentMembers()) > 3 {
				return InternalStateUpdatingMember
			} else {
				// The cluster needs to update.
				// We'll create a temporary member for updating.
				return InternalStatePreparingUpdate
			}
		}
	}

	if len(c.ownedPods) < c.Spec.Members {
		return InternalStateCreatingMembers
	}

	return InternalStateRunning
}

func (c *EtcdCluster) currentInternalStateCreating() InternalState {
	if len(c.ownedPods) == 0 {
		return InternalStateCreatingFirstMember
	}
	if len(c.ownedPods) == 1 {
		if c.IsPodReady(c.ownedPods[0]) {
			return InternalStateCreatingMembers
		}

		return InternalStateCreatingFirstMember
	}

	return InternalStateCreatingMembers
}

func (c *EtcdCluster) currentInternalStateUpdating() InternalState {
	// If a temporary member is deleting then InternalState is TeardownUpdating.
	// If a temporary member is not ready, then InternalState is still PreparingUpdate
	if v := c.TemporaryMember(); v != nil {
		if !v.Pod.DeletionTimestamp.IsZero() {
			return InternalStateTeardownUpdating
		}

		if !c.IsPodReady(v.Pod) {
			return InternalStatePreparingUpdate
		}
	}

	if len(c.ownedPods) != c.Spec.Members+1 {
		return InternalStateUpdatingMember
	}

	for _, p := range c.ownedPods {
		if c.ShouldUpdate(p) {
			return InternalStateUpdatingMember
		}
		if !c.IsPodReady(p) {
			return InternalStateUpdatingMember
		}
	}

	return InternalStateTeardownUpdating
}

func (c *EtcdCluster) Client(endpoints []string) (*clientv3.Client, error) {
	// hack for test
	if c.mockOpt != nil {
		ctx, _ := context.WithCancel(context.Background())
		client := clientv3.NewCtxClient(ctx)
		client.Cluster = c.mockOpt.Cluster
		client.Maintenance = c.mockOpt.Maintenance

		return client, nil
	}

	caCertPair, err := c.parseCASecret(c.caSecret)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(caCertPair.Cert)

	if endpoints == nil {
		endpoints = []string{fmt.Sprintf("https://%s.%s.svc.%s:%d", c.ClientServiceName(), c.Namespace, c.ClusterDomain, EtcdClientPort)}
	}

	cfg := clientv3.Config{
		Endpoints: endpoints,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{c.serverCertSecret.Certificate},
			RootCAs:      certPool,
			ClientCAs:    certPool,
			ServerName:   fmt.Sprintf("%s.%s.svc.%s", c.ClientServiceName(), c.Namespace, c.ClusterDomain),
		},
	}
	client, err := clientv3.New(cfg)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return client, nil
}

func (c *EtcdCluster) GetMetrics(addr string) ([]*dto.MetricFamily, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/metrics", addr), nil)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	req.Header.Set("Accept", string(expfmt.FmtProtoDelim))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	d := expfmt.NewDecoder(res.Body, expfmt.FmtProtoDelim)

	metrics := make([]*dto.MetricFamily, 0)
	for {
		mf := &dto.MetricFamily{}
		err = d.Decode(mf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.WithStack(err)
		}
		metrics = append(metrics, mf)
	}

	return metrics, nil
}

func (c *EtcdCluster) SetAnnotationForPod(pod *corev1.Pod) {
	metav1.SetMetadataAnnotation(&pod.ObjectMeta, etcd.AnnotationKeyServerCertificate, string(c.serverCertSecret.MarshalCertificate()))
}

func (c *EtcdCluster) newTemporaryMemberPodSpec(etcdVersion string, initialClusters []string) *corev1.Pod {
	pod := c.newEtcdPod(
		etcdVersion,
		c.Spec.Members+1,
		"existing",
		append(initialClusters, fmt.Sprintf("$(MY_POD_NAME)=https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdPeerPort)),
		true,
	)
	pod = k8sfactory.PodFactory(pod,
		k8sfactory.Annotation(etcd.AnnotationKeyTemporaryMember, "true"),
	)

	return pod
}

func (c *EtcdCluster) DefaultLabels(etcdVersion string) map[string]string {
	return map[string]string{
		etcd.LabelNameClusterName: c.Name,
		etcd.LabelNameEtcdVersion: etcdVersion,
		etcd.LabelNameRole:        "etcd",
	}
}

func (c *EtcdCluster) DefaultAnnotations() map[string]string {
	return map[string]string{etcd.AnnotationKeyServerCertificate: string(c.serverCertSecret.MarshalCertificate())}
}

func (c *EtcdCluster) newEtcdPod(etcdVersion string, index int, clusterState string, initialCluster []string, temporaryMember bool) *corev1.Pod {
	antiAffinity := c.Spec.AntiAffinity
	if antiAffinity && temporaryMember {
		antiAffinity = false
	}
	podName := fmt.Sprintf("%s-%d", c.Name, index)
	pod := k8sfactory.PodFactory(nil,
		k8sfactory.Name(podName),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.Labels(c.DefaultLabels(etcdVersion)),
		k8sfactory.Annotations(c.DefaultAnnotations()),
		k8sfactory.ControlledBy(c.EtcdCluster, client.Scheme),
	)
	if c.Spec.Template != nil && c.Spec.Template.Metadata != nil {
		pod = k8sfactory.PodFactory(pod,
			k8sfactory.Labels(c.Spec.Template.Metadata.Labels),
			k8sfactory.Annotations(c.Spec.Template.Metadata.Annotations),
		)
	}

	return c.etcdPodSpec(pod, podName, etcdVersion, clusterState, initialCluster, antiAffinity)
}

func (c *EtcdCluster) etcdPodSpec(pod *corev1.Pod, podName, etcdVersion, clusterState string, initialCluster []string, antiAffinity bool) *corev1.Pod {
	memberManipulateScript := template.Must(template.New("").Parse(addMemberScript))

	caVolume := k8sfactory.NewSecretVolumeSource(
		"ca",
		"/etc/etcd-ca",
		c.caSecret,
		corev1.KeyToPath{Key: caSecretCertName, Path: caSecretCertName},
	)
	serverCertVolume := k8sfactory.NewSecretVolumeSource(
		"cert",
		"/etc/etcd-cert",
		c.serverCertSecret.ToSecret(),
	)
	clientCertVolume := k8sfactory.NewSecretVolumeSource(
		"client-cert",
		"/etc/etcd-client-cert",
		c.clientCertSecret,
	)
	dataVolume := k8sfactory.NewEmptyDirVolumeSource("data", "/data")
	if c.Spec.VolumeClaimTemplate != nil {
		dataVolume = k8sfactory.NewPersistentVolumeClaimVolumeSource("data", "/data", podName)
	}
	sidecarVolume := k8sfactory.NewEmptyDirVolumeSource("share", "/var/run/sidecar")
	runVolume := k8sfactory.NewEmptyDirVolumeSource("run", "/var/run/etcd")

	var addMemberContainer *corev1.Container
	if clusterState == "existing" {
		buf := new(bytes.Buffer)
		err := memberManipulateScript.Execute(buf, struct {
			Name     string
			CACert   string
			Cert     string
			Key      string
			Endpoint string
			PeerUrl  string
		}{
			Name:     podName,
			CACert:   clientCertVolume.PathJoin(clientCertSecretCACertName),
			Cert:     clientCertVolume.PathJoin(clientCertSecretCertName),
			Key:      clientCertVolume.PathJoin(clientCertSecretPrivateKeyName),
			Endpoint: fmt.Sprintf("%s.%s.svc.%s:%d", c.ClientServiceName(), c.Namespace, c.ClusterDomain, EtcdClientPort),
			PeerUrl:  fmt.Sprintf("https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdPeerPort),
		})
		if err != nil {
			panic(err)
		}

		addMemberContainer = k8sfactory.ContainerFactory(nil,
			k8sfactory.Name("add-member"),
			k8sfactory.Image(
				fmt.Sprintf("gcr.io/etcd-development/etcd:%s", etcdVersion),
				[]string{"/bin/sh", "-c", buf.String()},
			),
			k8sfactory.EnvFromField("MY_POD_IP", "status.podIP"),
			k8sfactory.Volume(clientCertVolume),
		)
	}

	etcdArgs := []string{
		"--name=$(MY_POD_NAME)",
		"--data-dir=/data/$(MY_POD_NAME).etcd",
		fmt.Sprintf("--initial-cluster-state=%s", clusterState),
		fmt.Sprintf("--initial-advertise-peer-urls=https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdPeerPort),
		fmt.Sprintf("--advertise-client-urls=https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdClientPort),
		fmt.Sprintf("--listen-client-urls=https://0.0.0.0:%d", EtcdClientPort),
		fmt.Sprintf("--listen-peer-urls=https://0.0.0.0:%d", EtcdPeerPort),
		fmt.Sprintf("--listen-metrics-urls=http://0.0.0.0:%d", EtcdMetricsPort),
		fmt.Sprintf("--trusted-ca-file=%s", caVolume.PathJoin(caSecretCertName)),
		"--client-cert-auth",
		fmt.Sprintf("--cert-file=%s", serverCertVolume.PathJoin(serverCertSecretCertName)),
		fmt.Sprintf("--key-file=%s", serverCertVolume.PathJoin(serverCertSecretPrivateKeyName)),
		fmt.Sprintf("--peer-cert-file=%s", serverCertVolume.PathJoin(serverCertSecretCertName)),
		fmt.Sprintf("--peer-key-file=%s", serverCertVolume.PathJoin(serverCertSecretPrivateKeyName)),
		fmt.Sprintf("--peer-trusted-ca-file=%s", caVolume.PathJoin(caSecretCertName)),
		"--peer-client-cert-auth",
	}
	if initialCluster != nil && len(initialCluster) > 0 {
		etcdArgs = append(etcdArgs, fmt.Sprintf("--initial-cluster=%s", strings.Join(initialCluster, ",")))
	}
	etcdScript := fmt.Sprintf(`
while ( ! ls /var/run/sidecar/ready )
do
	echo "Waiting for booting sidecar"
	sleep 1
done
echo '' > /etc/resolv.conf
mkdir -p /var/run/etcd
/usr/local/bin/etcd %s &
ETCD_PID=$!
echo $ETCD_PID > /var/run/etcd/pid
wait $ETCD_PID`, strings.Join(etcdArgs, " "))
	etcdContainer := k8sfactory.ContainerFactory(nil,
		k8sfactory.Name("etcd"),
		k8sfactory.Image(fmt.Sprintf("gcr.io/etcd-development/etcd:%s", etcdVersion), []string{"/bin/sh"}),
		k8sfactory.Args("-c", etcdScript),
		k8sfactory.EnvFromField("MY_POD_NAME", "metadata.name"),
		k8sfactory.EnvFromField("MY_POD_IP", "status.podIP"),
		k8sfactory.Port("client", corev1.ProtocolTCP, EtcdClientPort),
		k8sfactory.Port("peer", corev1.ProtocolTCP, EtcdPeerPort),
		k8sfactory.Port("metrics", corev1.ProtocolTCP, EtcdMetricsPort),
		k8sfactory.LivenessProbe(k8sfactory.TCPProbe(EtcdClientPort)),
		k8sfactory.ReadinessProbe(k8sfactory.HTTPProbe(EtcdMetricsPort, "/health")),
		k8sfactory.Volume(serverCertVolume),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(dataVolume),
		k8sfactory.Volume(sidecarVolume),
		k8sfactory.Volume(runVolume),
	)

	sidecarArgs := []string{
		"--port", "53",
		"--namespace", c.Namespace,
		"--cluster-domain", c.ClusterDomain,
		"--ttl", "5",
		"--ready-file", "/var/run/sidecar/ready",
		"--etcd-pid-file", "/var/run/etcd/pid",
	}
	if c.Spec.Development {
		sidecarArgs = append(sidecarArgs, "--log-level", "debug")
	}
	sidecarContainer := k8sfactory.ContainerFactory(nil,
		k8sfactory.Name("sidecar"),
		k8sfactory.Image(fmt.Sprintf("ghcr.io/f110/heimdallr/discovery-sidecar:%s", version.Version), nil),
		k8sfactory.PullPolicy(corev1.PullPolicyIfNotPresent),
		k8sfactory.Args(sidecarArgs...),
		k8sfactory.LivenessProbe(k8sfactory.HTTPProbe(8080, "/liveness")),
		k8sfactory.ReadinessProbe(k8sfactory.HTTPProbe(8080, "/readiness")),
		k8sfactory.Port("dns", corev1.ProtocolUDP, 53),
		k8sfactory.Port("pprof", corev1.ProtocolTCP, 8080),
		k8sfactory.Volume(sidecarVolume),
		k8sfactory.Volume(runVolume),
	)

	pod = k8sfactory.PodFactory(pod,
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(serverCertVolume),
		k8sfactory.Volume(clientCertVolume),
		k8sfactory.Volume(dataVolume),
		k8sfactory.Volume(sidecarVolume),
		k8sfactory.Volume(runVolume),
		k8sfactory.Subdomain(c.ServerDiscoveryServiceName()),
		k8sfactory.ServiceAccount(c.ServiceAccountName()),
		k8sfactory.RestartPolicy(corev1.RestartPolicyNever),
		k8sfactory.InitContainer(
			k8sfactory.ContainerFactory(nil,
				k8sfactory.Name("wipe-data"),
				k8sfactory.Image("busybox:latest", []string{"/bin/sh", "-c", "rm -rf /data/*"}),
				k8sfactory.Volume(dataVolume),
			),
		),
		k8sfactory.InitContainer(addMemberContainer),
		k8sfactory.Container(etcdContainer),
		k8sfactory.Container(sidecarContainer),
		k8sfactory.ShareProcessNamespace,
	)
	if antiAffinity {
		pod = k8sfactory.PodFactory(pod,
			k8sfactory.PreferredInterPodAntiAffinity(
				100,
				k8sfactory.MatchExpression(metav1.LabelSelectorRequirement{
					Key:      etcd.LabelNameClusterName,
					Operator: metav1.LabelSelectorOperatorIn,
					Values:   []string{c.Name},
				}),
				"kubernetes.io/hostname",
			),
		)
	}

	return pod
}

func (c *EtcdCluster) InjectRestoreContainer(pod *corev1.Pod) {
	dataVolume := &podVolume{
		Name: "data",
		Path: "/data",
		Source: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	receiverContainer := corev1.Container{
		Name:         "receive-backup-file",
		Image:        "busybox:latest",
		Command:      []string{"/bin/sh", "-c", "nc -l -p 2900 > /data/backup.db"},
		VolumeMounts: []corev1.VolumeMount{dataVolume.ToMount()},
	}
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, receiverContainer)

	clientCertVolume := &podVolume{
		Name: "client-cert",
		Path: "/etc/etcd-client-cert",
		Source: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: c.ClientCertSecretName(),
			},
		},
	}

	buf := new(bytes.Buffer)
	templateRestoreData := template.Must(template.New("").Parse(restoreDataScript))
	err := templateRestoreData.Execute(buf, struct {
		Name             string
		CACert           string
		Cert             string
		Key              string
		Endpoint         string
		DataFile         string
		PeerUrl          string
		AdvertisePeerUrl string
	}{
		CACert:           clientCertVolume.PathJoin(clientCertSecretCACertName),
		Cert:             clientCertVolume.PathJoin(clientCertSecretCertName),
		Key:              clientCertVolume.PathJoin(clientCertSecretPrivateKeyName),
		Endpoint:         fmt.Sprintf("%s.%s.svc.%s:%d", c.ClientServiceName(), c.Namespace, c.ClusterDomain, EtcdClientPort),
		DataFile:         "/data/backup.db",
		Name:             pod.Name,
		PeerUrl:          fmt.Sprintf("https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdPeerPort),
		AdvertisePeerUrl: fmt.Sprintf("https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, EtcdPeerPort),
	})
	if err != nil {
		logger.Log.Error("Failed render script", zap.Error(err))
		return
	}
	etcdVersion := c.Spec.Version
	if etcdVersion == "" {
		etcdVersion = defaultEtcdVersion
	}

	restoreContainer := corev1.Container{
		Name:    "restore-data",
		Image:   fmt.Sprintf("gcr.io/etcd-development/etcd:%s", etcdVersion),
		Command: []string{"/bin/sh", "-c", buf.String()},
		Env: []corev1.EnvVar{
			{
				Name: "MY_POD_IP",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "status.podIP",
					},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			clientCertVolume.ToMount(),
			dataVolume.ToMount(),
		},
	}
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, restoreContainer)
}

type podVolume struct {
	Name   string
	Path   string
	Source corev1.VolumeSource
}

func (p *podVolume) ToVolume() corev1.Volume {
	return corev1.Volume{
		Name:         p.Name,
		VolumeSource: p.Source,
	}
}

func (p *podVolume) ToMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      p.Name,
		MountPath: p.Path,
	}
}

func (p *podVolume) PathJoin(elem ...string) string {
	return filepath.Join(append([]string{p.Path}, elem...)...)
}

type certAndKey struct {
	Cert       *x509.Certificate
	PrivateKey crypto.PrivateKey
}

func (c *EtcdCluster) parseCASecret(s *corev1.Secret) (*certAndKey, error) {
	caCertPem, _ := pem.Decode(s.Data[caSecretCertName])

	caCert, err := x509.ParseCertificate(caCertPem.Bytes)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	privateKeyPem, _ := pem.Decode(s.Data[caSecretPrivateKeyName])
	caPrivateKey, err := x509.ParseECPrivateKey(privateKeyPem.Bytes)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return &certAndKey{Cert: caCert, PrivateKey: caPrivateKey}, nil
}

func (c *EtcdCluster) IsPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodPhaseRunning {
		return false
	}
	for _, v := range pod.Status.ContainerStatuses {
		if v.Name == "etcd" {
			return v.Ready
		}
	}

	return false
}

func (c *EtcdCluster) newEtcdMember(pod *corev1.Pod) *EtcdMember {
	var pvc *corev1.PersistentVolumeClaim
	if c.Spec.VolumeClaimTemplate != nil {
		pvc = c.ownedPVC[pod.Name]
		if pvc == nil {
			tmpl := c.Spec.VolumeClaimTemplate
			l := map[string]string{
				etcd.LabelNameClusterName: c.Name,
			}
			if tmpl.ObjectMeta != nil {
				for k, v := range tmpl.ObjectMeta.Labels {
					l[k] = v
				}
			}
			pvc = &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pod.Name,
					Namespace: c.Namespace,
					Labels:    l,
					OwnerReferences: []metav1.OwnerReference{
						metav1.NewControllerRef(c.EtcdCluster.ObjectMeta, etcdv1alpha2.SchemaGroupVersion.WithKind("EtcdCluster")),
					},
				},
				Spec: &tmpl.Spec,
			}
			if tmpl.ObjectMeta != nil {
				pvc.ObjectMeta.Annotations = tmpl.ObjectMeta.Annotations
			}
		}
	}

	return &EtcdMember{Pod: pod, PersistentVolumeClaim: pvc}
}

type etcdPod struct {
	*corev1.Pod
	*clientv3.StatusResponse
	Endpoint string
}

type Certificate struct {
	tls.Certificate

	secret     *corev1.Secret
	privateKey []byte
}

func NewCertificate(secret *corev1.Secret, source tls.Certificate) (Certificate, error) {
	var privateKey []byte
	switch key := source.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		v, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return Certificate{}, xerrors.WithStack(err)
		}
		privateKey = v
	case *rsa.PrivateKey:
		privateKey = x509.MarshalPKCS1PrivateKey(key)
	}

	return Certificate{Certificate: source, secret: secret, privateKey: privateKey}, nil
}

func (c *Certificate) ToSecret() *corev1.Secret {
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: c.privateKey})

	return k8sfactory.SecretFactory(c.secret,
		k8sfactory.Data(serverCertSecretCertName, c.MarshalCertificate()),
		k8sfactory.Data(serverCertSecretPrivateKeyName, privateKeyBuf),
	)
}

func (c *Certificate) MarshalCertificate() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Certificate[0]})
}

type EtcdMember struct {
	Pod                   *corev1.Pod
	PersistentVolumeClaim *corev1.PersistentVolumeClaim
	// TODO: Remove after v0.12
	OldVersion bool
}
