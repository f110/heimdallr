package kind

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	minioclient "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/xerrors"
	goyaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	configv1alpha4 "sigs.k8s.io/kind/pkg/apis/config/v1alpha4"

	"go.f110.dev/heimdallr/manifest/certmanager"
	"go.f110.dev/heimdallr/manifest/minio"
	"go.f110.dev/heimdallr/pkg/k8s"
	"go.f110.dev/heimdallr/pkg/poll"
)

var NodeImageHash = map[string]string{
	"v1.26.0":  "691e24bd2417609db7e589e1a479b902d2e209892a10ce375fab60a8407c7352",
	"v1.25.3":  "f52781bc0d7a19fb6c405c2af83abfeb311f130707a0e219175677e366cc45d1",
	"v1.25.2":  "9be91e9e9cdf116809841fc77ebdb8845443c4c72fe5218f3ae9eb57fdb4bace",
	"v1.24.7":  "577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315",
	"v1.24.6":  "97e8d00bc37a7598a0b32d1fabd155a96355c49fa0d4d4790aab0f161bf31be1",
	"v1.23.13": "ef453bb7c79f0e3caba88d2067d4196f427794086a7d0df8df4f019d5e336b61",
	"v1.23.12": "9402cf1330bbd3a0d097d2033fa489b2abe40d479cc5ef47d0b6a6960613148a",
	"v1.22.15": "7d9708c4b0873f0fe2e171e2b1b7f45ae89482617778c1c875f1053d4cef2e41",
	"v1.22.0":  "b8bda84bb3a190e6e028b1760d277454a72267a5454b57db34437c34a588d047",
	"v1.21.14": "9d9eb5fb26b4fbc0c6d95fa8c790414f9750dd583f5d7cee45d92e8c26670aa1",
	"v1.21.1":  "69860bda5563ac81e3c0057d654b5253219618a22ec3a346306239bba8cfa1a6",
	"v1.20.15": "a32bf55309294120616886b5338f95dd98a2f7231519c7dedcec32ba29699394",
	"v1.20.7":  "cbeaf907fc78ac97ce7b625e4bf0de16e3ea725daf6b04f930bd14c67c671ff9",
	"v1.19.16": "476cb3269232888437b61deca013832fee41f9f074f9bed79f57e4280f7c48b7",
	"v1.19.11": "07db187ae84b4b7de440a73886f008cf903fcf5764ba8106a9fd5243d6f32729",
}

const (
	MinIOBucketName = "heimdallr"
	minioAccessKey  = "05s43pHf7C7s"
	minioSecretKey  = "N/m6YdhZs0qiSxQ5etSQ6JTDgBcus4ZN"
)

type Cluster struct {
	kind          string
	name          string
	kubeConfig    string
	tmpKubeConfig bool

	clientset kubernetes.Interface
}

func NewCluster(kind, name, kubeConfig string) (*Cluster, error) {
	_, err := exec.LookPath(kind)
	if err != nil {
		return nil, err
	}

	return &Cluster{kind: kind, name: name, kubeConfig: kubeConfig}, nil
}

func (c *Cluster) IsExist(name string) (bool, error) {
	cmd := exec.CommandContext(context.TODO(), c.kind, "get", "clusters")
	buf, err := cmd.CombinedOutput()
	if err != nil {
		return false, xerrors.Errorf(": %w", err)
	}
	s := bufio.NewScanner(bytes.NewReader(buf))
	for s.Scan() {
		line := s.Text()
		if line == name {
			return true, nil
		}
	}

	return false, nil
}

func (c *Cluster) Create(clusterVersion string, workerNum int) error {
	kindConfFile, err := os.CreateTemp("", "kind.config.yaml")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer os.Remove(kindConfFile.Name())

	imageHash, ok := NodeImageHash[clusterVersion]
	if !ok {
		return xerrors.Errorf("Not supported k8s version: %s", clusterVersion)
	}
	image := fmt.Sprintf("kindest/node:%s@sha256:%s", clusterVersion, imageHash)

	clusterConf := &configv1alpha4.Cluster{
		TypeMeta: configv1alpha4.TypeMeta{
			APIVersion: "kind.x-k8s.io/v1alpha4",
			Kind:       "Cluster",
		},
		Nodes: []configv1alpha4.Node{
			{Role: configv1alpha4.ControlPlaneRole, Image: image},
		},
	}
	for i := 0; i < workerNum; i++ {
		clusterConf.Nodes = append(clusterConf.Nodes,
			configv1alpha4.Node{Role: configv1alpha4.WorkerRole, Image: image})
	}
	if buf, err := goyaml.Marshal(clusterConf); err != nil {
		return xerrors.Errorf(": %w", err)
	} else {
		if _, err := kindConfFile.Write(buf); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if c.kubeConfig == "" {
		f, err := os.CreateTemp("", "config")
		if err != nil {
			return err
		}
		c.kubeConfig = f.Name()
		c.tmpKubeConfig = true
	}
	cmd := exec.CommandContext(
		context.TODO(),
		c.kind, "create", "cluster",
		"--name", c.name,
		"--kubeconfig", c.kubeConfig,
		"--config", kindConfFile.Name(),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (c *Cluster) KubeConfig() string {
	return c.kubeConfig
}

func (c *Cluster) Delete() error {
	found, err := c.IsExist(c.name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if !found {
		return nil
	}

	if c.tmpKubeConfig {
		defer os.Remove(c.kubeConfig)
	}
	cmd := exec.CommandContext(context.TODO(), c.kind, "delete", "cluster", "--name", c.name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type ContainerImageFile struct {
	File       string
	Repository string
	Tag        string

	repoTags string
}

type manifest struct {
	RepoTags []string `json:"RepoTags"`
}

func (c *Cluster) LoadImageFiles(images ...*ContainerImageFile) error {
	for _, v := range images {
		if err := readImageManifest(v); err != nil {
			return err
		}

		log.Printf("Load image file: %s", v.repoTags)
		cmd := exec.CommandContext(context.TODO(), c.kind, "load", "image-archive", "--name", c.name, v.File)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	cmd := exec.CommandContext(context.TODO(), c.kind, "get", "nodes", "--name", c.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	nodes := make([]string, 0)
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		nodes = append(nodes, s.Text())
	}

	for _, node := range nodes {
		for _, image := range images {
			log.Printf("Set an image tag %s:%s on %s", image.Repository, image.Tag, node)
			cmd = exec.CommandContext(
				context.TODO(),
				"docker", "exec", node,
				"ctr", "-n", "k8s.io",
				"images", "tag",
				"--force",
				image.repoTags,
				fmt.Sprintf("%s:%s", image.Repository, image.Tag),
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Cluster) RESTConfig() (*rest.Config, error) {
	if exist, err := c.IsExist(c.name); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	} else if !exist {
		return nil, xerrors.New("The cluster is not created yet")
	}
	if c.kubeConfig == "" {
		kubeConf, err := os.CreateTemp("", "kubeconfig")
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		cmd := exec.CommandContext(
			context.TODO(),
			c.kind, "export", "kubeconfig",
			"--kubeconfig", kubeConf.Name(),
			"--name", c.name,
		)
		if err := cmd.Run(); err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		c.kubeConfig = kubeConf.Name()
		defer func() {
			os.Remove(kubeConf.Name())
			c.kubeConfig = ""
		}()
	}

	cfg, err := clientcmd.LoadFromFile(c.kubeConfig)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	clientConfig := clientcmd.NewDefaultClientConfig(*cfg, &clientcmd.ConfigOverrides{})
	restCfg, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	return restCfg, nil
}

func (c *Cluster) Clientset() (kubernetes.Interface, error) {
	if c.clientset != nil {
		return c.clientset, nil
	}

	restCfg, err := c.RESTConfig()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	c.clientset = cs

	return cs, nil
}

func (c *Cluster) WaitReady(ctx context.Context) error {
	client, err := c.Clientset()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return poll.PollImmediate(ctx, 1*time.Second, 3*time.Minute, func(ctx2 context.Context) (done bool, err error) {
		nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		notReadyNodes := make(map[string]struct{})
	Nodes:
		for _, v := range nodes.Items {
			for _, c := range v.Status.Conditions {
				if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
					continue Nodes
				}
			}
			notReadyNodes[v.Name] = struct{}{}
		}
		if len(notReadyNodes) == 0 {
			return true, nil
		}

		return false, nil
	})
}

func (c *Cluster) Apply(f, fieldManager string) error {
	buf, err := os.ReadFile(f)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cfg, err := c.RESTConfig()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := k8s.ApplyManifestFromString(cfg, buf, fieldManager); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func readImageManifest(image *ContainerImageFile) error {
	f, err := os.Open(image.File)
	if err != nil {
		return err
	}
	r := tar.NewReader(f)
	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Name != "manifest.json" {
			// Skip reading if the file name is not manifest.json.
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
			continue
		}

		manifests := make([]manifest, 0)
		if err := json.NewDecoder(r).Decode(&manifests); err != nil {
			return err
		}
		if len(manifests) == 0 {
			return errors.New("manifest.json is empty")
		}
		image.repoTags = manifests[0].RepoTags[0]
	}

	return nil
}

func InstallCertManager(cfg *rest.Config, fieldManager string) error {
	cm, err := certmanager.Data.ReadFile("cert-manager.yaml")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	objs, err := k8s.LoadUnstructuredFromString(cm)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	err = k8s.Objects(objs).Apply(cfg, fieldManager)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	crds, err := k8s.Objects(objs).SelectCustomResourceDefinitions()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := k8s.WaitForReadyWebhook(cfg, crds); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	ci, err := certmanager.Data.ReadFile("cluster-issuer.yaml")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := k8s.ApplyManifestFromString(cfg, ci, fieldManager); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func InstallMinIO(cfg *rest.Config, fieldManager string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "minio-token",
			Namespace: metav1.NamespaceDefault,
		},
		StringData: map[string]string{
			"accesskey": minioAccessKey,
			"secretkey": minioSecretKey,
		},
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if _, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		_, err = client.CoreV1().Secrets(secret.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	m, err := minio.Data.ReadFile("minio.yaml")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := k8s.ApplyManifestFromString(cfg, m, fieldManager); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := createMinIOBucket(cfg); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func createMinIOBucket(cfg *rest.Config) error {
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = poll.PollImmediate(context.TODO(), 10*time.Second, 3*time.Minute, func(ctx context.Context) (bool, error) {
		svc, err := client.CoreV1().Services(metav1.NamespaceDefault).Get(ctx, "minio", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		var forwarder *portforward.PortForwarder
		forwarder, err = portForward(ctx, cfg, client, svc, int(svc.Spec.Ports[0].Port))
		if err != nil {
			return false, nil
		}
		defer forwarder.Close()

		ports, err := forwarder.GetPorts()
		if err != nil {
			return false, nil
		}
		instanceEndpoint := fmt.Sprintf("127.0.0.1:%d", ports[0].Local)
		creds := credentials.NewStaticV4(minioAccessKey, minioSecretKey, "")
		mc, err := minioclient.New(instanceEndpoint, &minioclient.Options{Creds: creds})
		if err != nil {
			return false, nil
		}
		if exists, err := mc.BucketExists(context.TODO(), MinIOBucketName); err != nil {
			return false, nil
		} else if exists {
			return true, nil
		}

		if err := mc.MakeBucket(context.TODO(), MinIOBucketName, minioclient.MakeBucketOptions{}); err != nil {
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func portForward(ctx context.Context, cfg *rest.Config, client kubernetes.Interface, svc *corev1.Service, port int) (*portforward.PortForwarder, error) {
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	podList, err := client.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}
	var pod *corev1.Pod
	for i, v := range podList.Items {
		if v.Status.Phase == corev1.PodRunning {
			pod = &podList.Items[i]
			break
		}
	}
	if pod == nil {
		return nil, errors.New("all pods are not running yet")
	}

	req := client.CoreV1().RESTClient().Post().Resource("pods").Namespace(svc.Namespace).Name(pod.Name).SubResource("portforward")
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, req.URL())

	readyCh := make(chan struct{})
	pf, err := portforward.New(dialer, []string{fmt.Sprintf(":%d", port)}, context.Background().Done(), readyCh, nil, nil)
	if err != nil {
		return nil, err
	}

	go func() {
		err := pf.ForwardPorts()
		if err != nil {
			log.Print(err)
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out")
	}

	return pf, nil
}
