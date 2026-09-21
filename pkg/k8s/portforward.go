package k8s

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.f110.dev/xerrors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForward establishes the port forwarding to one of the Pods that is backed by the Service.
func PortForward(ctx context.Context, cfg *rest.Config, client kubernetes.Interface, svc *corev1.Service, port int) (*portforward.PortForwarder, error) {
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	podList, err := client.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	var pod *corev1.Pod
	for i, v := range podList.Items {
		if v.Status.Phase == corev1.PodRunning {
			pod = &podList.Items[i]
			break
		}
	}
	if pod == nil {
		return nil, xerrors.NewWithStack("all pods are not running yet")
	}

	req := client.CoreV1().RESTClient().Post().Resource("pods").Namespace(svc.Namespace).Name(pod.Name).SubResource("portforward")
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, req.URL())

	readyCh := make(chan struct{})
	pf, err := portforward.New(dialer, []string{fmt.Sprintf(":%d", port)}, context.Background().Done(), readyCh, nil, nil)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	go func() {
		err := pf.ForwardPorts()
		if err != nil {
			log.Printf("ForwardPorts returns an error: %v", err)
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		return nil, xerrors.NewWithStack("timed out")
	}

	return pf, nil
}
