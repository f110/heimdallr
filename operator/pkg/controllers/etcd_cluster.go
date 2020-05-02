package controllers

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/coreos/etcd/clientv3"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"

	"github.com/f110/lagrangian-proxy/operator/pkg/api/etcd"
	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	"github.com/f110/lagrangian-proxy/pkg/cert"
)

type InternalState string

const (
	InternalStateCreatingFirstMember InternalState = "creatingFirstNode"
	InternalStateCreatingMembers     InternalState = "creatingMembers"
	InternalStatePreparingUpdate     InternalState = "preparingUpdate"
	InternalStateUpdatingMember      InternalState = "updatingMember"
	InternalStateTeardownUpdating    InternalState = "teardownUpdating"
	InternalStateRunning             InternalState = "running"
)

const waitScript = `while ( ! nslookup {{ .Host }} )
do
	echo "Waiting for DNS propagation..."
	sleep 1
done`

const (
	caSecretCertName               = "ca.crt"
	caSecretPrivateKeyName         = "ca.key"
	serverCertSecretCertName       = "tls.crt"
	serverCertSecretPrivateKeyName = "tls.key"
	clientCertSecretCACertName     = "ca.crt"
	clientCertSecretCertName       = "client.crt"
	clientCertSecretPrivateKeyName = "client.key"
)

type EtcdCluster struct {
	*etcdv1alpha1.EtcdCluster

	ClusterDomain string

	ownedPods        []*corev1.Pod
	caSecret         *corev1.Secret
	serverCertSecret Certificate
	podsOnce         sync.Once
	expectedPods     []*corev1.Pod
}

func NewEtcdCluster(c *etcdv1alpha1.EtcdCluster, clusterDomain string) *EtcdCluster {
	return &EtcdCluster{
		EtcdCluster:   c.DeepCopy(),
		ClusterDomain: clusterDomain,
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
		klog.Warningf("Failed decode a server certificate: %s", cert.Name)
	}

	serverCert, err := NewCertificate(tlsKeyPair)
	if err != nil {
		klog.Warningf("Failed encode a private key")
	}
	c.serverCertSecret = serverCert
}

func (c *EtcdCluster) CA(s *corev1.Secret) (*corev1.Secret, error) {
	if s != nil {
		return s, nil
	}

	caCert, privateKey, err := cert.CreateCertificateAuthority(fmt.Sprintf("%s-ca", c.Name), "", "", "")
	if err != nil {
		return nil, err
	}
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, err
	}
	caCertBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})

	s = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            c.CASecretName(),
			Namespace:       c.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c.EtcdCluster, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
		},
		Data: map[string][]byte{
			caSecretCertName:       caCertBuf,
			caSecretPrivateKeyName: privateKeyBuf,
		},
	}

	return s, nil
}

func (c *EtcdCluster) ServerCert(ca *corev1.Secret) (Certificate, error) {
	certPair, err := c.parseCASecret(ca)
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
		return Certificate{}, err
	}
	serverCertBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})
	tlsKeyPair, err := tls.X509KeyPair(serverCertBuf, privateKeyBuf)
	if err != nil {
		return Certificate{}, err
	}

	return NewCertificate(tlsKeyPair)
}

func (c *EtcdCluster) DNSNames() []string {
	dnsNames := make([]string, 0)
	for i := 1; i <= c.Spec.Members+1; i++ {
		dnsNames = append(dnsNames, fmt.Sprintf("%s-%d.%s.%s.svc.%s", c.Name, i, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain))
	}
	dnsNames = append(dnsNames, fmt.Sprintf("%s.%s.%s.svc.%s", c.Name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain))
	dnsNames = append(dnsNames, fmt.Sprintf("%s.%s.svc.%s", c.ClientServiceName(), c.Namespace, c.ClusterDomain))

	return dnsNames
}

func (c *EtcdCluster) ServerCertSecret(ca *corev1.Secret) (*corev1.Secret, error) {
	serverCert, err := c.ServerCert(ca)
	if err != nil {
		return nil, err
	}

	s := serverCert.ToSecret()
	s.ObjectMeta = metav1.ObjectMeta{
		Name:            c.ServerCertSecretName(),
		Namespace:       c.Namespace,
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c.EtcdCluster, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
	}

	return s, nil
}

func (c *EtcdCluster) CASecretName() string {
	return fmt.Sprintf("etcd-%s-ca", c.Name)
}

func (c *EtcdCluster) ServerCertSecretName() string {
	return fmt.Sprintf("etcd-%s-server-cert", c.Name)
}

func (c *EtcdCluster) ClientCertSecret(ca *corev1.Secret) (*corev1.Secret, error) {
	certPair, err := c.parseCASecret(ca)
	if err != nil {
		return nil, err
	}

	clientCert, clientPrivateKey, err := cert.GenerateMutualTLSCertificate(
		certPair.Cert, certPair.PrivateKey,
		[]string{fmt.Sprintf("%s.%s.%s.svc.%s", c.Name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain)},
		nil,
	)
	if err != nil {
		return nil, err
	}
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(clientPrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, err
	}
	clientCertBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            c.ClientCertSecretName(),
			Namespace:       c.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c.EtcdCluster, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
		},
		Data: map[string][]byte{
			clientCertSecretCACertName:     ca.Data[caSecretCertName],
			clientCertSecretCertName:       clientCertBuf,
			clientCertSecretPrivateKeyName: privateKeyBuf,
		},
	}
	return s, nil
}

func (c *EtcdCluster) ClientCertSecretName() string {
	return fmt.Sprintf("etcd-%s-client-cert", c.Name)
}

func (c *EtcdCluster) DefragmentCronJob() *batchv1beta1.CronJob {
	podSpec := corev1.PodSpec{
		RestartPolicy: corev1.RestartPolicyNever,
		Containers: []corev1.Container{
			{
				Name:  "etcdctl",
				Image: fmt.Sprintf("quay.io/coreos/etcd:%s", c.Spec.Version),
				Command: []string{"/usr/local/bin/etcdctl",
					fmt.Sprintf("--endpoints=https://%s.%s.svc.%s:2379", c.ClientServiceName(), c.Namespace, c.ClusterDomain),
					fmt.Sprintf("--cacert=/etc/etcd-ca/%s", caCertificateFilename),
					fmt.Sprintf("--cert=/etc/etcd-client/%s", clientCertSecretCertName),
					fmt.Sprintf("--key=/etc/etcd-client/%s", clientCertSecretPrivateKeyName),
					"defrag",
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "ca",
						MountPath: "/etc/etcd-ca",
					},
					{
						Name:      "cert",
						MountPath: "/etc/etcd-client",
					},
				},
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "ca",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: c.CASecretName(),
						Items: []corev1.KeyToPath{
							{Key: caSecretCertName, Path: caSecretCertName},
						},
					},
				},
			},
			{
				Name: "cert",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: c.ClientCertSecretName(),
					},
				},
			},
		},
	}

	return &batchv1beta1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:            c.DefragmentCronJobName(),
			Namespace:       c.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c.EtcdCluster, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
		},
		Spec: batchv1beta1.CronJobSpec{
			Schedule: c.Spec.DefragmentSchedule,
			JobTemplate: batchv1beta1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						etcd.LabelNameClusterName: c.Name,
						etcd.LabelNameRole:        "defragment",
					},
				},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: podSpec,
					},
				},
			},
		},
	}
}

func (c *EtcdCluster) DefragmentCronJobName() string {
	return fmt.Sprintf("etcd-%s-defragment", c.Name)
}

// AllMembers returns all members of etcd, regardless of status
func (c *EtcdCluster) AllMembers() []*corev1.Pod {
	c.podsOnce.Do(func() {
		etcdVersion := defaultEtcdVersion
		if c.Spec.Version != "" {
			etcdVersion = c.Spec.Version
		}

		var initialClusters []string
		pods := make(map[string]*corev1.Pod)
		for _, v := range c.ownedPods {
			pods[v.Name] = v
			if !v.CreationTimestamp.IsZero() && v.Status.Phase == corev1.PodRunning {
				initialClusters = append(initialClusters, fmt.Sprintf("%s=https://%s.%s.%s.svc.%s:2380", v.Name, v.Name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain))
			}
		}

		result := make([]*corev1.Pod, 0)
		for i := 1; i <= c.Spec.Members; i++ {
			name := fmt.Sprintf("%s-%d", c.Name, i)
			if _, ok := pods[name]; !ok {
				clusterState := "existing"
				if i == 1 && c.CurrentInternalState() == InternalStateCreatingFirstMember {
					clusterState = "new"
					initialClusters = []string{}
				}

				pods[name] = c.newEtcdPod(
					i,
					etcdVersion,
					clusterState,
					append(initialClusters, fmt.Sprintf("%s=https://%s.%s.%s.svc.%s:2380", name, name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain)),
				)
				result = append(result, pods[name])
				continue
			}

			pods[name].Spec = c.etcdPodSpec(i, etcdVersion, "existing", initialClusters)
			result = append(result, pods[name])
		}

		switch c.CurrentInternalState() {
		case InternalStatePreparingUpdate, InternalStateUpdatingMember:
			name := fmt.Sprintf("%s-%d", c.Name, c.Spec.Members+1)
			pod := c.newEtcdPod(
				c.Spec.Members+1,
				etcdVersion,
				"existing",
				append(initialClusters, fmt.Sprintf("%s=https://%s.%s.%s.svc.%s:2380", name, name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain)),
			)
			metav1.SetMetaDataAnnotation(&pod.ObjectMeta, etcd.AnnotationKeyTemporaryMember, "true")
			result = append(result, pod)
		}

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

func (c *EtcdCluster) TemporaryMember() *corev1.Pod {
	for _, p := range c.ownedPods {
		if metav1.HasAnnotation(p.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
			return p
		}
	}

	return nil
}

func (c *EtcdCluster) AllExistMembers() []*corev1.Pod {
	return c.ownedPods
}

func (c *EtcdCluster) ShouldUpdate(pod *corev1.Pod) bool {
	if metav1.HasAnnotation(pod.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
		return false
	}

	if pod.CreationTimestamp.IsZero() {
		klog.V(4).Infof("%s should be updated because not created yet", pod.Name)
		return true
	}

	if v, ok := pod.Labels[etcd.LabelNameEtcdVersion]; ok && v != c.Spec.Version {
		klog.V(4).Infof("%s is older version: %s", pod.Name, v)
		return true
	}

	if v, ok := pod.Annotations[etcd.AnnotationKeyServerCertificate]; ok {
		if c.ShouldUpdateServerCertificate([]byte(v)) {
			klog.V(4).Infof("%s's certificate is outdated", pod.Name)
			return true
		}
	} else if !ok {
		// If pod doesn't have AnnotationKeyServerCertificate, pod should be updated.
		klog.V(4).Infof("%s doesn't have AnnotationKeyServerCertificate", pod.Name)
		return true
	}

	return false
}

func (c *EtcdCluster) ShouldUpdateServerCertificate(certPem []byte) bool {
	b, _ := pem.Decode(certPem)
	podCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		klog.Warningf("Could not parse a certificate")
		return true
	}

	expectDNSName := c.DNSNames()
	if len(podCert.DNSNames) != len(expectDNSName) {
		klog.V(4).Infof("cert doesn't have enough DNSNames")
		return true
	}

	for i, v := range podCert.DNSNames {
		if expectDNSName[i] != v {
			klog.V(4).Infof("Unexpected DNSName: %s vs %s", expectDNSName[i], v)
			return true
		}
	}

	return false
}

func (c *EtcdCluster) ServerDiscoveryServiceName() string {
	return fmt.Sprintf("%s-discovery", c.Name)
}

func (c *EtcdCluster) DiscoveryService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            c.ServerDiscoveryServiceName(),
			Namespace:       c.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c.EtcdCluster, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
			Labels: map[string]string{
				etcd.LabelNameClusterName: c.Name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeClusterIP,
			ClusterIP:                corev1.ClusterIPNone,
			PublishNotReadyAddresses: true,
			Selector: map[string]string{
				etcd.LabelNameClusterName: c.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "etcd-server-ssl",
					Protocol: corev1.ProtocolTCP,
					Port:     2380,
				},
				{
					Name:     "etcd-client-ssl",
					Protocol: corev1.ProtocolTCP,
					Port:     2379,
				},
			},
		},
	}
}

func (c *EtcdCluster) ClientServiceName() string {
	return fmt.Sprintf("%s-client", c.Name)
}

func (c *EtcdCluster) ClientService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            c.ClientServiceName(),
			Namespace:       c.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c.EtcdCluster, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
			Labels: map[string]string{
				etcd.LabelNameClusterName: c.Name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeClusterIP,
			PublishNotReadyAddresses: true,
			Selector: map[string]string{
				etcd.LabelNameClusterName: c.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "https",
					Protocol: corev1.ProtocolTCP,
					Port:     2379,
				},
			},
		},
	}
}

func (c *EtcdCluster) CurrentPhase() etcdv1alpha1.EtcdClusterPhase {
	if len(c.ownedPods) == 0 {
		return etcdv1alpha1.ClusterPhasePending
	}

	if len(c.ownedPods) == 1 && !c.IsPodReady(c.ownedPods[0]) {
		return etcdv1alpha1.ClusterPhaseInitializing
	}

	if len(c.ownedPods) < c.Spec.Members && c.Status.LastReadyTransitionTime.IsZero() {
		return etcdv1alpha1.ClusterPhaseCreating
	}

	for _, pod := range c.ownedPods {
		if !c.IsPodReady(pod) {
			if c.Status.LastReadyTransitionTime.IsZero() {
				return etcdv1alpha1.ClusterPhaseCreating
			} else {
				return etcdv1alpha1.ClusterPhaseUpdating
			}
		}
	}

	return etcdv1alpha1.ClusterPhaseRunning
}

func (c *EtcdCluster) CurrentInternalState() InternalState {
	if len(c.ownedPods) < c.Spec.Members && c.Status.LastReadyTransitionTime.IsZero() {
		return c.currentInternalStateCreating()
	}

	// Cluster updating works in progress
	if metav1.HasAnnotation(c.ownedPods[len(c.ownedPods)-1].ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
		return c.currentInternalStateUpdating()
	}

	for _, p := range c.ownedPods {
		if !c.IsPodReady(p) {
			if c.Status.LastReadyTransitionTime.IsZero() {
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
	if !c.ownedPods[len(c.ownedPods)-1].DeletionTimestamp.IsZero() {
		return InternalStateTeardownUpdating
	}

	if !c.IsPodReady(c.ownedPods[len(c.ownedPods)-1]) {
		return InternalStatePreparingUpdate
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
	caCertPair, err := c.parseCASecret(c.caSecret)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(caCertPair.Cert)

	if endpoints == nil {
		endpoints = []string{fmt.Sprintf("https://%s:2379", c.ClientServiceName())}
	}

	cfg := clientv3.Config{
		Endpoints: endpoints,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{c.serverCertSecret.Certificate},
			RootCAs:      certPool,
			ClientCAs:    certPool,
			ServerName:   fmt.Sprintf("%s.%s.%s.svc.%s", c.Name, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain),
		},
	}
	client, err := clientv3.New(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *EtcdCluster) GetMetrics(addr string) ([]*dto.MetricFamily, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/metrics", addr), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", string(expfmt.FmtProtoDelim))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		metrics = append(metrics, mf)
	}

	return metrics, nil
}

func (c *EtcdCluster) SetAnnotationForPod(pod *corev1.Pod) {
	metav1.SetMetaDataAnnotation(&pod.ObjectMeta, etcd.AnnotationKeyServerCertificate, string(c.serverCertSecret.MarshalCertificate()))
}

func (c *EtcdCluster) newEtcdPod(num int, etcdVersion string, clusterState string, initialCluster []string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", c.Name, num),
			Namespace: c.Namespace,
			Labels: map[string]string{
				etcd.LabelNameClusterName: c.Name,
				etcd.LabelNameEtcdVersion: etcdVersion,
				etcd.LabelNameRole:        "etcd",
			},
			Annotations: map[string]string{
				etcd.AnnotationKeyServerCertificate: string(c.serverCertSecret.MarshalCertificate()),
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(c, etcdv1alpha1.SchemeGroupVersion.WithKind("EtcdCluster"))},
		},
		Spec: c.etcdPodSpec(num, etcdVersion, clusterState, initialCluster),
	}
}

func (c *EtcdCluster) etcdPodSpec(num int, etcdVersion, clusterState string, initialCluster []string) corev1.PodSpec {
	t, err := template.New("").Parse(waitScript)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	err = t.Execute(buf, struct {
		Host string
	}{
		Host: fmt.Sprintf("%s-%d.%s.%s.svc.%s", c.Name, num, c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain),
	})
	if err != nil {
		panic(err)
	}

	name := fmt.Sprintf("%s-%d", c.Name, num)
	discoveryService := fmt.Sprintf("%s.%s.svc.%s", c.ServerDiscoveryServiceName(), c.Namespace, c.ClusterDomain)
	args := []string{
		fmt.Sprintf("--name=%s", name),
		fmt.Sprintf("--data-dir=/var/%s.etcd", name),
		fmt.Sprintf("--initial-cluster-state=%s", clusterState),
		fmt.Sprintf("--initial-advertise-peer-urls=https://%s.%s:2380", name, discoveryService),
		fmt.Sprintf("--advertise-client-urls=https://%s.%s:2379", name, discoveryService),
		"--listen-client-urls=https://0.0.0.0:2379",
		"--listen-peer-urls=https://0.0.0.0:2380",
		"--listen-metrics-urls=http://0.0.0.0:2381",
		fmt.Sprintf("--trusted-ca-file=/etc/etcd-ca/%s", caSecretCertName),
		"--client-cert-auth",
		fmt.Sprintf("--cert-file=/etc/etcd-cert/%s", serverCertSecretCertName),
		fmt.Sprintf("--key-file=/etc/etcd-cert/%s", serverCertSecretPrivateKeyName),
		fmt.Sprintf("--peer-cert-file=/etc/etcd-cert/%s", serverCertSecretCertName),
		fmt.Sprintf("--peer-key-file=/etc/etcd-cert/%s", serverCertSecretPrivateKeyName),
		fmt.Sprintf("--peer-trusted-ca-file=/etc/etcd-ca/%s", caSecretCertName),
		"--peer-client-cert-auth",
	}
	if initialCluster != nil && len(initialCluster) > 0 {
		args = append(args, fmt.Sprintf("--initial-cluster=%s", strings.Join(initialCluster, ",")))
	}

	return corev1.PodSpec{
		Hostname:  fmt.Sprintf("%s-%d", c.Name, num),
		Subdomain: c.ServerDiscoveryServiceName(),
		InitContainers: []corev1.Container{
			{
				Name:    "wait",
				Image:   "busybox:latest",
				Command: []string{"/bin/sh", "-c", buf.String()},
			},
		},
		Containers: []corev1.Container{
			{
				Name:    "etcd",
				Image:   fmt.Sprintf("quay.io/coreos/etcd:%s", etcdVersion),
				Command: append([]string{"/usr/local/bin/etcd"}, args...),
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
				LivenessProbe: &corev1.Probe{
					Handler: corev1.Handler{
						TCPSocket: &corev1.TCPSocketAction{
							Port: intstr.FromInt(2379),
						},
					},
				},
				ReadinessProbe: &corev1.Probe{
					Handler: corev1.Handler{
						HTTPGet: &corev1.HTTPGetAction{
							Port: intstr.FromInt(2381),
							Path: "/health",
						},
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "cert",
						MountPath: "/etc/etcd-cert",
					},
					{
						Name:      "ca",
						MountPath: "/etc/etcd-ca",
					},
				},
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "cert",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: c.ServerCertSecretName(),
					},
				},
			},
			{
				Name: "ca",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: c.CASecretName(),
						Items: []corev1.KeyToPath{
							{Key: caSecretCertName, Path: caSecretCertName},
						},
					},
				},
			},
		},
	}
}

type certAndKey struct {
	Cert       *x509.Certificate
	PrivateKey crypto.PrivateKey
}

func (c *EtcdCluster) parseCASecret(s *corev1.Secret) (*certAndKey, error) {
	caCertPem, _ := pem.Decode(s.Data[caSecretCertName])

	caCert, err := x509.ParseCertificate(caCertPem.Bytes)
	if err != nil {
		return nil, err
	}

	privateKeyPem, _ := pem.Decode(s.Data[caSecretPrivateKeyName])
	caPrivateKey, err := x509.ParseECPrivateKey(privateKeyPem.Bytes)
	if err != nil {
		return nil, err
	}

	return &certAndKey{Cert: caCert, PrivateKey: caPrivateKey}, nil
}

func (c *EtcdCluster) IsPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, v := range pod.Status.ContainerStatuses {
		if v.Name == "etcd" {
			return v.Ready
		}
	}

	return false
}

type etcdPod struct {
	*corev1.Pod
	*clientv3.StatusResponse
	Endpoint string
}

type Certificate struct {
	tls.Certificate

	privateKey []byte
}

func NewCertificate(source tls.Certificate) (Certificate, error) {
	var privateKey []byte
	switch key := source.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		v, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return Certificate{}, err
		}
		privateKey = v
	case *rsa.PrivateKey:
		privateKey = x509.MarshalPKCS1PrivateKey(key)
	}

	return Certificate{Certificate: source, privateKey: privateKey}, nil
}

func (c *Certificate) ToSecret() *corev1.Secret {
	privateKeyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: c.privateKey})

	return &corev1.Secret{
		Data: map[string][]byte{
			serverCertSecretCertName:       c.MarshalCertificate(),
			serverCertSecretPrivateKeyName: privateKeyBuf,
		},
	}
}

func (c *Certificate) MarshalCertificate() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Certificate[0]})
}
