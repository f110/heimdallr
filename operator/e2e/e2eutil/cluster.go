package e2eutil

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsClientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/operator/e2e/data"
)

var kindImages = map[string]string{
	"v1.19.1":  "98cf5288864662e37115e362b23e4369c8c4a408f99cbc06e58ac30ddc721600",
	"v1.19.0":  "3b0289b2d1bab2cb9108645a006939d2f447a10ad2bb21919c332d06b548bbc6",
	"v1.18.8":  "f4bcc97a0ad6e7abaf3f643d890add7efe6ee4ab90baeb374b4f41a4c95567eb",
	"v1.17.11": "5240a7a2c34bf241afb54ac05669f8a46661912eab05705d660971eeb12f6555",
}

type kindConfigBinding struct {
	ClusterVersion string
	ImageHash      string
}

const kindConfigTemplate = `apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
  - role: control-plane
    image: kindest/node:{{ .ClusterVersion }}@sha256:{{ .ImageHash }}
  - role: worker
    image: kindest/node:{{ .ClusterVersion }}@sha256:{{ .ImageHash }}
  - role: worker
    image: kindest/node:{{ .ClusterVersion }}@sha256:{{ .ImageHash }}
`

type Cluster struct {
	id         string
	kubeconfig string
}

func NewCluster(id string) *Cluster {
	return &Cluster{id: id}
}

func (c *Cluster) Create(clusterVersion string) error {
	_, err := exec.LookPath("kind")
	if err != nil {
		return err
	}

	imageHash, ok := kindImages[clusterVersion]
	if !ok {
		return xerrors.Errorf("%s is not supported", clusterVersion)
	}

	kf, err := ioutil.TempFile("", "kind.yaml")
	if err != nil {
		return err
	}
	t := template.Must(template.New("").Parse(kindConfigTemplate))
	if err := t.Execute(kf, kindConfigBinding{
		ClusterVersion: clusterVersion,
		ImageHash:      imageHash,
	}); err != nil {
		return err
	}

	f, err := ioutil.TempFile("", "config")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(
		context.TODO(),
		"kind", "create", "cluster",
		"--name", fmt.Sprintf("e2e-%s", c.id),
		"--kubeconfig", f.Name(),
		"--config", kf.Name(),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	c.kubeconfig = f.Name()

	return nil
}

func (c *Cluster) KubeConfig() string {
	return c.kubeconfig
}

func (c *Cluster) Delete() error {
	cmd := exec.CommandContext(context.TODO(), "kind", "get", "clusters")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	found := false
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		t := s.Text()
		if strings.HasPrefix(t, fmt.Sprintf("e2e-%s", c.id)) {
			found = true
		}
	}

	if !found {
		return nil
	}

	cmd = exec.CommandContext(context.TODO(), "kind", "delete", "cluster", "--name", fmt.Sprintf("e2e-%s", c.id))
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
		if err := readManifest(v); err != nil {
			return err
		}

		log.Printf("Load image file: %s", v.repoTags)
		cmd := exec.CommandContext(context.TODO(), "kind", "load", "image-archive", "--name", "e2e-"+c.id, v.File)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	cmd := exec.CommandContext(context.TODO(), "kind", "get", "nodes", "--name", "e2e-"+c.id)
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
				"ctr", "-n", "k8s.io", "images", "tag",
				"docker.io/"+image.repoTags,
				fmt.Sprintf("%s:%s", image.Repository, image.Tag),
			)
			if err := cmd.Run(); err != nil {
				return err
			}
		}
	}

	return nil
}

func readManifest(image *ContainerImageFile) error {
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
			if _, err := io.Copy(ioutil.Discard, r); err != nil {
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

func WaitForReady(ctx context.Context, client *kubernetes.Clientset) error {
	return wait.PollImmediate(1*time.Second, 3*time.Minute, func() (done bool, err error) {
		nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		ready := false
	Nodes:
		for _, v := range nodes.Items {
			for _, c := range v.Status.Conditions {
				if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
					ready = true
					break Nodes
				}
			}
		}

		return ready, nil
	})
}

func ReadCRDFiles(dir string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	crdFiles := make([][]byte, 0)
	//filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
	//	if err != nil {
	//		return err
	//	}
	//	if info.IsDir() {
	//		return nil
	//	}

	f, err := ioutil.ReadFile(dir)
	if err != nil {
		return nil, err
	}
	crdFiles = append(crdFiles, f)

	//return nil
	//})

	crd := make([]*apiextensionsv1.CustomResourceDefinition, 0)
	sch := runtime.NewScheme()
	_ = apiextensionsv1.AddToScheme(sch)
	codecs := serializer.NewCodecFactory(sch)
	for _, v := range crdFiles {
		d := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(v), 4096)
		for {
			ext := &runtime.RawExtension{}
			err := d.Decode(ext)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			obj, _, err := codecs.UniversalDeserializer().Decode(ext.Raw, nil, nil)
			if err != nil {
				continue
			}
			c, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				continue
			}
			crd = append(crd, c)
		}
	}

	return crd, nil
}

func EnsureCertManager(cfg *rest.Config) error {
	if err := StartCertManager(cfg, data.Data["operator/e2e/data/cert-manager.yaml"]); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	d := yaml.NewYAMLOrJSONDecoder(strings.NewReader(data.Data["operator/e2e/data/cluster-issuer.yaml"]), 4096)
	ext := runtime.RawExtension{}
	if err := d.Decode(&ext); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	obj, gvk, err := unstructured.UnstructuredJSONScheme.Decode(ext.Raw, nil, nil)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	gv := gvk.GroupVersion()

	disClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	var apiResource *metav1.APIResource
	err = wait.PollImmediate(3*time.Second, 10*time.Second, func() (bool, error) {
		_, apiResourcesList, err := disClient.ServerGroupsAndResources()
		if err != nil {
			return false, xerrors.Errorf(": %w", err)
		}

		for _, v := range apiResourcesList {
			if v.GroupVersion == gv.String() {
				for _, v := range v.APIResources {
					if v.Kind == gvk.Kind && !strings.HasSuffix(v.Name, "/status") {
						apiResource = &v
						return true, nil
					}
				}
			}
		}

		return false, nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	conf := *cfg
	conf.GroupVersion = &gv
	conf.APIPath = "/apis"
	conf.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	client, err := rest.RESTClientFor(&conf)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = wait.PollImmediate(10*time.Second, 3*time.Minute, func() (bool, error) {
		res := client.Post().
			Resource(apiResource.Name).
			Body(obj).
			Do(context.TODO())

		if res.Error() == nil {
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

type object struct {
	Object           runtime.Object
	GroupVersionKind *schema.GroupVersionKind
}

func StartCertManager(cfg *rest.Config, manifest string) error {
	objs := make([]object, 0)
	d := yaml.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 4096)
	for {
		ext := runtime.RawExtension{}
		if err := d.Decode(&ext); err != nil {
			if err == io.EOF {
				break
			}
			return xerrors.Errorf(": %w", err)
		}
		if len(ext.Raw) == 0 {
			continue
		}

		obj, gvk, err := unstructured.UnstructuredJSONScheme.Decode(ext.Raw, nil, nil)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		objs = append(objs, object{Object: obj, GroupVersionKind: gvk})
	}

	disClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	_, apiResourcesList, err := disClient.ServerGroupsAndResources()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	for _, obj := range objs {
		gv := obj.GroupVersionKind.GroupVersion()

		conf := *cfg
		conf.GroupVersion = &gv
		if gv.Group == "" {
			conf.APIPath = "/api"
		} else {
			conf.APIPath = "/apis"
		}
		conf.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
		client, err := rest.RESTClientFor(&conf)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		var apiResource *metav1.APIResource
		for _, v := range apiResourcesList {
			if v.GroupVersion == gv.String() {
				for _, v := range v.APIResources {
					if v.Kind == obj.GroupVersionKind.Kind && !strings.HasSuffix(v.Name, "/status") {
						apiResource = &v
						break
					}
				}
			}
		}
		if apiResource == nil {
			continue
		}

		req := client.Post()
		if apiResource.Namespaced {
			o := obj.Object.(*unstructured.Unstructured)
			req.Namespace(o.GetNamespace())
		}

		res := req.Resource(apiResource.Name).
			Body(obj.Object).
			Do(context.TODO())

		if err := res.Error(); err != nil {
			switch {
			case apierrors.IsAlreadyExists(err):
				continue
			}

			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func EnsureCRD(config *rest.Config, crd []*apiextensionsv1.CustomResourceDefinition, timeout time.Duration) error {
	apiextensionsClient, err := apiextensionsClientset.NewForConfig(config)
	if err != nil {
		return err
	}

	createdCRD := make(map[string]struct{})
	for _, v := range crd {
		_, err = apiextensionsClient.CustomResourceDefinitions().Create(context.TODO(), v, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		createdCRD[v.Name] = struct{}{}
	}

	err = wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		for name := range createdCRD {
			_, err := apiextensionsClient.CustomResourceDefinitions().Get(context.TODO(), name, metav1.GetOptions{})
			if err == nil {
				delete(createdCRD, name)
			}
		}

		if len(createdCRD) == 0 {
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}
