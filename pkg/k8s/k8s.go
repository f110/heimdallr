package k8s

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsClientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/pkg/poll"
)

func ReadCRDFile(fileName string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	f, err := os.ReadFile(fileName)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	crd := make([]*apiextensionsv1.CustomResourceDefinition, 0)
	sch := runtime.NewScheme()
	_ = apiextensionsv1.AddToScheme(sch)
	codecs := serializer.NewCodecFactory(sch)
	d := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(f), 4096)
	for {
		ext := &runtime.RawExtension{}
		err := d.Decode(ext)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
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

	return crd, nil
}

func EnsureCRD(config *rest.Config, crd []*apiextensionsv1.CustomResourceDefinition, timeout time.Duration) error {
	apiextensionsClient, err := apiextensionsClientset.NewForConfig(config)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	createdCRD := make(map[string]struct{})
	for _, v := range crd {
		_, err = apiextensionsClient.CustomResourceDefinitions().Get(context.TODO(), v.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = apiextensionsClient.CustomResourceDefinitions().Create(context.TODO(), v, metav1.CreateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			createdCRD[v.Name] = struct{}{}
		}
	}

	err = poll.PollImmediate(context.TODO(), 10*time.Second, timeout, func(ctx context.Context) (bool, error) {
		for name := range createdCRD {
			_, err := apiextensionsClient.CustomResourceDefinitions().Get(ctx, name, metav1.GetOptions{})
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

func ApplyManifestFromString(cfg *rest.Config, manifest []byte, fieldManager string) error {
	objs, err := LoadUnstructuredFromString(manifest)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = Objects(objs).Apply(cfg, fieldManager)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func WaitForReadyWebhook(cfg *rest.Config, crds []*apiextensionsv1.CustomResourceDefinition) error {
	target := make(map[string]*apiextensionsv1.CustomResourceDefinition)
	for _, v := range crds {
		if v.Spec.Conversion != nil && v.Spec.Conversion.Webhook != nil {
			target[v.Name] = v
			continue
		}
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	t := time.NewTicker(1 * time.Second)
	after := time.After(3 * time.Minute)
	for {
		select {
		case <-t.C:
			for _, c := range target {
				clientConfig := c.Spec.Conversion.Webhook.ClientConfig
				ep, err := client.CoreV1().Endpoints(clientConfig.Service.Namespace).Get(context.Background(), clientConfig.Service.Name, metav1.GetOptions{})
				if err != nil && apierrors.IsNotFound(err) {
					continue
				} else if err != nil {
					return xerrors.Errorf(": %w", err)
				}
				if len(ep.Subsets) == 0 {
					continue
				}
				ready := false
				for _, v := range ep.Subsets {
					if len(v.Addresses) > 0 {
						ready = true
						break
					}
				}
				if ready {
					delete(target, c.Name)
				}
			}
			if len(target) == 0 {
				return nil
			}
		case <-after:
			return errors.New("kind: timed out")
		}
	}
}

func LoadUnstructuredFromString(manifest []byte) ([]*unstructured.Unstructured, error) {
	objs := make([]*unstructured.Unstructured, 0)
	d := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 4096)
	for {
		ext := runtime.RawExtension{}
		if err := d.Decode(&ext); err != nil {
			if err == io.EOF {
				break
			}
			return nil, xerrors.Errorf(": %w", err)
		}
		if len(ext.Raw) == 0 {
			continue
		}

		obj, _, err := unstructured.UnstructuredJSONScheme.Decode(ext.Raw, nil, nil)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		objs = append(objs, obj.(*unstructured.Unstructured))
	}

	return objs, nil
}

type Objects []*unstructured.Unstructured

func (k Objects) SelectCustomResourceDefinitions() ([]*apiextensionsv1.CustomResourceDefinition, error) {
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0)
	for _, v := range k {
		kind := v.GetObjectKind()
		if kind.GroupVersionKind().Kind == "CustomResourceDefinition" {
			crd := &apiextensionsv1.CustomResourceDefinition{}
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(v.Object, crd); err != nil {
				log.Printf("Failed %s decode CustomResourceDefinition from Unstructured: %v", v.GetName(), err)
				continue
			}
			crds = append(crds, crd)
		}
	}

	return crds, nil
}

func (k Objects) Apply(cfg *rest.Config, fieldManager string) error {
	disClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	_, apiResourcesList, err := disClient.ServerGroupsAndResources()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	for _, obj := range k {
		gv := obj.GroupVersionKind().GroupVersion()

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
					if v.Kind == obj.GroupVersionKind().Kind && !strings.HasSuffix(v.Name, "/status") {
						apiResource = &v
						break
					}
				}
			}
		}
		if apiResource == nil {
			continue
		}

		method := http.MethodPatch
		err = poll.PollImmediate(context.TODO(), 5*time.Second, 30*time.Second, func(ctx context.Context) (bool, error) {
			var req *rest.Request
			switch method {
			case http.MethodPatch:
				req = client.Patch(types.ApplyPatchType)
			default:
				req = client.Post()
			}
			data, err := runtime.Encode(unstructured.UnstructuredJSONScheme, obj)
			if err != nil {
				log.Print(err)
				return true, nil
			}
			force := true
			res := req.
				NamespaceIfScoped(obj.GetNamespace(), apiResource.Namespaced).
				Resource(apiResource.Name).
				Name(obj.GetName()).
				VersionedParams(&metav1.PatchOptions{FieldManager: fieldManager, Force: &force}, metav1.ParameterCodec).
				Body(data).
				Do(ctx)
			if err := res.Error(); err != nil {
				switch {
				case apierrors.IsAlreadyExists(err):
					method = http.MethodPatch
					return false, nil
				case apierrors.IsInternalError(err):
					log.Print(err)
					return false, nil
				}

				log.Printf("%s.%s: %v", obj.GetKind(), obj.GetName(), err)
				return true, nil
			}
			return true, nil
		})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}
