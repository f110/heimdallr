package framework

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/xerrors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/controllers"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/poll"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

// SetupWithDiscoverySidecar creates the cluster that consists of the Pods that have discovery-sidecar like the operator v0.16 created.
// The operator is paused until ResumeOperator is called.
//
// discovery-sidecar is replaced with CoreDNS because the image of discovery-sidecar supports only amd64.
// CoreDNS resolves only the names that discovery-sidecar resolves, which are derived from the ip address of the Pod.
//
// TODO: Remove this in v0.18.
func (e *EtcdClusters) SetupWithDiscoverySidecar(m *btesting.Matcher, traits ...k8sfactory.Trait) bool {
	ctx := context.TODO()
	resume, err := e2eutil.PauseOperator(ctx, e.restConfig, e.coreClient)
	m.Must(err)
	e.resumeOperator = resume

	ec, err := e.client.EtcdV1alpha2.CreateEtcdCluster(ctx, etcd.Factory(EtcdClusterBase, traits...), metav1.CreateOptions{})
	m.Must(err)
	e.clusters[ec.Name] = ec

	kubeClient, err := k8sclient.NewSet(e.restConfig)
	m.Must(err)
	return m.Must(e.createDiscoverySidecarCluster(ctx, kubeClient, ec))
}

// ResumeOperator resumes the operator that is paused by SetupWithDiscoverySidecar.
func (e *EtcdClusters) ResumeOperator() error {
	if e.resumeOperator == nil {
		return nil
	}
	if err := e.resumeOperator(context.TODO()); err != nil {
		return err
	}
	e.resumeOperator = nil
	return nil
}

func (e *EtcdClusters) createDiscoverySidecarCluster(ctx context.Context, kubeClient *k8sclient.Set, ec *etcdv1alpha2.EtcdCluster) error {
	cluster := controllers.NewEtcdCluster(ec, "cluster.local", logger.Log, nil)
	caSecret, err := cluster.CA()
	if err != nil {
		return err
	}
	cluster.SetCASecret(caSecret)
	serverCertSecret, err := cluster.ServerCertSecret()
	if err != nil {
		return err
	}
	clientCertSecret, err := cluster.ClientCertSecret()
	if err != nil {
		return err
	}
	for _, v := range []*corev1.Secret{caSecret, serverCertSecret, clientCertSecret} {
		if _, err := kubeClient.CoreV1.CreateSecret(ctx, v, metav1.CreateOptions{}); err != nil {
			return xerrors.WithStack(err)
		}
	}
	if _, err := kubeClient.CoreV1.CreateServiceAccount(ctx, cluster.ServiceAccount(), metav1.CreateOptions{}); err != nil {
		return xerrors.WithStack(err)
	}
	if _, err := kubeClient.RbacAuthorizationK8sIoV1.CreateRole(ctx, cluster.EtcdRole(), metav1.CreateOptions{}); err != nil {
		return xerrors.WithStack(err)
	}
	if _, err := kubeClient.RbacAuthorizationK8sIoV1.CreateRoleBinding(ctx, cluster.EtcdRoleBinding(), metav1.CreateOptions{}); err != nil {
		return xerrors.WithStack(err)
	}
	for _, v := range []*corev1.Service{cluster.DiscoveryService(), cluster.ClientService()} {
		if _, err := kubeClient.CoreV1.CreateService(ctx, v, metav1.CreateOptions{}); err != nil {
			return xerrors.WithStack(err)
		}
	}

	kubeDNS, err := e.coreClient.CoreV1().Services("kube-system").Get(ctx, "kube-dns", k8smetav1.GetOptions{})
	if err != nil {
		return xerrors.WithStack(err)
	}
	coreDNS, err := e.coreClient.AppsV1().Deployments("kube-system").Get(ctx, "coredns", k8smetav1.GetOptions{})
	if err != nil {
		return xerrors.WithStack(err)
	}
	sidecarConfig := k8sfactory.ConfigMapFactory(nil,
		k8sfactory.Name(fmt.Sprintf("%s-sidecar", ec.Name)),
		k8sfactory.Namespace(ec.Namespace),
		k8sfactory.ControlledBy(ec, client.Scheme),
		k8sfactory.Data("Corefile", []byte(fmt.Sprintf("%s.pod.%s:53 in-addr.arpa:53 {\n    forward . %s\n}\n", ec.Namespace, cluster.ClusterDomain, kubeDNS.Spec.ClusterIP))),
	)
	if _, err := kubeClient.CoreV1.CreateConfigMap(ctx, sidecarConfig, metav1.CreateOptions{}); err != nil {
		return xerrors.WithStack(err)
	}

	var initialCluster []string
	for i := 1; i <= ec.Spec.Members; i++ {
		pod := newDiscoverySidecarPod(cluster, i, initialCluster, sidecarConfig.Name, coreDNS.Spec.Template.Spec.Containers[0].Image)
		if _, err := kubeClient.CoreV1.CreatePod(ctx, pod, metav1.CreateOptions{}); err != nil {
			return xerrors.WithStack(err)
		}

		err := poll.PollImmediate(ctx, 1*time.Second, 3*time.Minute, func(ctx context.Context) (bool, error) {
			p, err := kubeClient.CoreV1.GetPod(ctx, pod.Namespace, pod.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if !cluster.IsPodReady(p) {
				return false, nil
			}
			pod = p
			return true, nil
		})
		if err != nil {
			return xerrors.WithMessagef(err, "%s is not ready", pod.Name)
		}
		initialCluster = append(initialCluster, fmt.Sprintf("%s=%s", pod.Name, cluster.PodPeerURL(pod.Status.PodIP)))
	}

	return nil
}

// newDiscoverySidecarPod returns the Pod that the operator v0.16 created.
func newDiscoverySidecarPod(c *controllers.EtcdCluster, index int, initialCluster []string, sidecarConfigName, coreDNSImage string) *corev1.Pod {
	podName := fmt.Sprintf("%s-%d", c.Name, index)
	image := fmt.Sprintf("gcr.io/etcd-development/etcd:%s", c.EtcdVersion())
	shellURL := func(port int) string {
		return fmt.Sprintf("https://$(echo $MY_POD_IP | tr . -).%s.pod.%s:%d", c.Namespace, c.ClusterDomain, port)
	}

	caVolume := k8sfactory.NewSecretVolumeSource("ca", "/etc/etcd-ca",
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: c.CASecretName()}},
		corev1.KeyToPath{Key: "ca.crt", Path: "ca.crt"},
	)
	serverCertVolume := k8sfactory.NewSecretVolumeSource("cert", "/etc/etcd-cert", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: c.ServerCertSecretName()}})
	clientCertVolume := k8sfactory.NewSecretVolumeSource("client-cert", "/etc/etcd-client-cert", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: c.ClientCertSecretName()}})
	dataVolume := k8sfactory.NewEmptyDirVolumeSource("data", "/data")
	sidecarConfigVolume := k8sfactory.NewConfigMapVolumeSource("sidecar-config", "/etc/coredns", sidecarConfigName)

	clusterState := "new"
	var addMemberContainer *corev1.Container
	if len(initialCluster) > 0 {
		clusterState = "existing"
		etcdctlOpt := fmt.Sprintf("--cacert=%s --cert=%s --key=%s --endpoints=%s.%s.svc.%s:%d",
			clientCertVolume.PathJoin("ca.crt"), clientCertVolume.PathJoin("client.crt"), clientCertVolume.PathJoin("client.key"),
			c.ClientServiceName(), c.Namespace, c.ClusterDomain, controllers.EtcdClientPort,
		)
		addMemberContainer = k8sfactory.ContainerFactory(nil,
			k8sfactory.Name("add-member"),
			k8sfactory.Image(image, []string{"/bin/sh", "-c", fmt.Sprintf("/usr/local/bin/etcdctl %s member add %s --peer-urls=%s", etcdctlOpt, podName, shellURL(controllers.EtcdPeerPort))}),
			k8sfactory.EnvFromField("MY_POD_IP", "status.podIP"),
			k8sfactory.Volume(clientCertVolume),
		)
	}
	initialCluster = append(initialCluster, fmt.Sprintf("%s=%s", podName, shellURL(controllers.EtcdPeerPort)))

	etcdArgs := []string{
		"--name=$(MY_POD_NAME)",
		"--data-dir=/data/$(MY_POD_NAME).etcd",
		"--initial-cluster-state=" + clusterState,
		"--initial-advertise-peer-urls=" + shellURL(controllers.EtcdPeerPort),
		"--advertise-client-urls=" + shellURL(controllers.EtcdClientPort),
		fmt.Sprintf("--listen-client-urls=https://0.0.0.0:%d", controllers.EtcdClientPort),
		fmt.Sprintf("--listen-peer-urls=https://0.0.0.0:%d", controllers.EtcdPeerPort),
		fmt.Sprintf("--listen-metrics-urls=http://0.0.0.0:%d", controllers.EtcdMetricsPort),
		"--trusted-ca-file=" + caVolume.PathJoin("ca.crt"),
		"--client-cert-auth",
		"--cert-file=" + serverCertVolume.PathJoin("tls.crt"),
		"--key-file=" + serverCertVolume.PathJoin("tls.key"),
		"--peer-cert-file=" + serverCertVolume.PathJoin("tls.crt"),
		"--peer-key-file=" + serverCertVolume.PathJoin("tls.key"),
		"--peer-trusted-ca-file=" + caVolume.PathJoin("ca.crt"),
		"--peer-client-cert-auth",
		"--initial-cluster=" + strings.Join(initialCluster, ","),
	}
	// Like the operator v0.16, etcd resolves the names only by the sidecar.
	etcdScript := fmt.Sprintf(`echo '' > /etc/resolv.conf
until getent hosts $(echo $MY_POD_IP | tr . -).%s.pod.%s > /dev/null; do sleep 1; done
exec /usr/local/bin/etcd %s`, c.Namespace, c.ClusterDomain, strings.Join(etcdArgs, " "))

	pod := k8sfactory.PodFactory(nil,
		k8sfactory.Name(podName),
		k8sfactory.Namespace(c.Namespace),
		k8sfactory.Labels(c.DefaultLabels(c.EtcdVersion())),
		k8sfactory.Annotations(c.DefaultAnnotations()),
		k8sfactory.ControlledBy(c.EtcdCluster, client.Scheme),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(serverCertVolume),
		k8sfactory.Volume(clientCertVolume),
		k8sfactory.Volume(dataVolume),
		k8sfactory.Volume(sidecarConfigVolume),
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
		k8sfactory.Container(
			k8sfactory.ContainerFactory(nil,
				k8sfactory.Name("etcd"),
				k8sfactory.Image(image, []string{"/bin/sh"}),
				k8sfactory.Args("-c", etcdScript),
				k8sfactory.EnvFromField("MY_POD_NAME", "metadata.name"),
				k8sfactory.EnvFromField("MY_POD_IP", "status.podIP"),
				k8sfactory.Port("client", corev1.ProtocolTCP, controllers.EtcdClientPort),
				k8sfactory.Port("peer", corev1.ProtocolTCP, controllers.EtcdPeerPort),
				k8sfactory.Port("metrics", corev1.ProtocolTCP, controllers.EtcdMetricsPort),
				k8sfactory.LivenessProbe(k8sfactory.TCPProbe(controllers.EtcdClientPort)),
				k8sfactory.ReadinessProbe(k8sfactory.HTTPProbe(controllers.EtcdMetricsPort, "/health")),
				k8sfactory.Volume(serverCertVolume),
				k8sfactory.Volume(caVolume),
				k8sfactory.Volume(dataVolume),
			),
		),
		k8sfactory.Container(
			k8sfactory.ContainerFactory(nil,
				k8sfactory.Name("sidecar"),
				k8sfactory.Image(coreDNSImage, nil),
				k8sfactory.Args("-conf", sidecarConfigVolume.PathJoin("Corefile")),
				k8sfactory.Volume(sidecarConfigVolume),
			),
		),
	)
	// CoreDNS may run as the non-root user.
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_unprivileged_port_start", Value: "0"}},
	}
	return pod
}

// HaveDiscoverySidecar reports whether all Pods of the cluster have discovery-sidecar.
func (c *EtcdCluster) HaveDiscoverySidecar(m *btesting.Matcher, expect bool) {
	if c.EtcdCluster == nil {
		m.Fail("EtcdCluster is not found")
	}
	pods, err := c.coreClient.CoreV1().Pods(c.EtcdCluster.Namespace).List(context.TODO(), k8smetav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, c.EtcdCluster.Name)})
	m.Must(err)
	if len(pods.Items) == 0 {
		m.Fail("Pod is not found")
	}
	for _, pod := range pods.Items {
		found := false
		for _, v := range pod.Spec.Containers {
			if v.Name == "sidecar" {
				found = true
			}
		}
		m.Equal(expect, found, pod.Name)
	}
}
