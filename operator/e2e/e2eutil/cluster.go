package e2eutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsClientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apiextensionsbeta1Clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func CreateCluster(id string) (string, error) {
	_, err := exec.LookPath("kind")
	if err != nil {
		return "", err
	}

	f, err := ioutil.TempFile("", "config")
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(context.TODO(), "kind", "create", "cluster", "--name", fmt.Sprintf("e2e-%s", id), "--kubeconfig", f.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}

	return f.Name(), nil
}

func DeleteCluster(id string) error {
	cmd := exec.CommandContext(context.TODO(), "kind", "get", "clusters")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	found := false
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		t := s.Text()
		if strings.HasPrefix(t, fmt.Sprintf("e2e-%s", id)) {
			found = true
		}
	}

	if !found {
		return nil
	}

	cmd = exec.CommandContext(context.TODO(), "kind", "delete", "cluster", "--name", fmt.Sprintf("e2e-%s", id))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func WaitForReady(ctx context.Context, client *kubernetes.Clientset) error {
	t := time.Tick(1 * time.Second)
	for {
		select {
		case <-t:
			nodes, err := client.CoreV1().Nodes().List(metav1.ListOptions{})
			if err != nil {
				return err
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

			if ready {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func ReadCRDFiles(dir string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	crdFiles := make([][]byte, 0)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		f, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		crdFiles = append(crdFiles, f)

		return nil
	})

	crd := make([]*apiextensionsv1.CustomResourceDefinition, 0)
	sch := runtime.NewScheme()
	_ = apiextensionsv1.AddToScheme(sch)
	codecs := serializer.NewCodecFactory(sch)
	for _, v := range crdFiles {
		obj, _, err := codecs.UniversalDeserializer().Decode(v, nil, nil)
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

func EnsureCRD(config *rest.Config, crd []*apiextensionsv1.CustomResourceDefinition, crdbeta1 []*apiextensionsv1beta1.CustomResourceDefinition, timeout time.Duration) error {
	apiextensionsClient, err := apiextensionsClientset.NewForConfig(config)
	if err != nil {
		return err
	}
	apiextensionsbeta1Client, err := apiextensionsbeta1Clientset.NewForConfig(config)
	if err != nil {
		return err
	}

	createdCRD := make(map[string]struct{})
	for _, v := range crd {
		_, err = apiextensionsClient.CustomResourceDefinitions().Create(v)
		if err != nil {
			return err
		}
		createdCRD[v.Name] = struct{}{}
	}
	for _, v := range crdbeta1 {
		_, err = apiextensionsbeta1Client.CustomResourceDefinitions().Create(v)
		if err != nil {
			return err
		}
		createdCRD[v.Name] = struct{}{}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	t := time.Tick(10 * time.Second)
Check:
	for {
		select {
		case <-t:
			for name := range createdCRD {
				_, err := apiextensionsClient.CustomResourceDefinitions().Get(name, metav1.GetOptions{})
				if err == nil {
					delete(createdCRD, name)
				}

				_, err = apiextensionsbeta1Client.CustomResourceDefinitions().Get(name, metav1.GetOptions{})
				if err == nil {
					delete(createdCRD, name)
				}
			}

			if len(createdCRD) == 0 {
				break Check
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
