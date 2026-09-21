package e2eutil

import (
	"context"
	"time"

	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/xerrors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/poll"
)

// WaitForWebhookReachable waits until the apiserver is able to reach the webhook of the operator.
// The Endpoints of the webhook gets an address before kube-proxy configures the route to that
// address. Sending the actual request is the only way to confirm that the path from the apiserver
// to the webhook is established.
func WaitForWebhookReachable(ctx context.Context, cfg *rest.Config) error {
	c, err := client.NewSet(cfg)
	if err != nil {
		return err
	}

	backend := &proxyv1alpha2.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook-probe", Namespace: metav1.NamespaceDefault},
		Spec: proxyv1alpha2.BackendSpec{
			Layer: "probe",
			HTTP: []proxyv1alpha2.BackendHTTPSpec{
				{
					Path:            "/",
					ServiceSelector: &proxyv1alpha2.ServiceSelector{Name: "webhook-probe", Port: "http"},
				},
			},
		},
	}

	var lastErr error
	err = poll.PollImmediate(ctx, 1*time.Second, 3*time.Minute, func(ctx context.Context) (bool, error) {
		_, lastErr = c.ProxyV1alpha2.CreateBackend(ctx, backend, metav1.CreateOptions{DryRun: []string{k8smetav1.DryRunAll}})
		return lastErr == nil, nil
	})
	if err != nil {
		if lastErr != nil {
			return xerrors.WithMessage(lastErr, "the webhook is not reachable from the apiserver")
		}
		return err
	}

	return nil
}
