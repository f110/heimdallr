package e2eutil

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/xerrors"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsClientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
)

func ReadCRDFiles(dir string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	crdFiles := make([][]byte, 0)

	f, err := ioutil.ReadFile(dir)
	if err != nil {
		return nil, err
	}
	crdFiles = append(crdFiles, f)

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
