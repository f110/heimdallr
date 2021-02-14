package k8s

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/xerrors"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsClientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func ReadCRDFile(fileName string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	f, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
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
