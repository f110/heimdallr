package e2eutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
