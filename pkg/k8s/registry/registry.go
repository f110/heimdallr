package registry

import (
	"context"
	"time"

	"go.f110.dev/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/manifest/zot"
	"go.f110.dev/heimdallr/pkg/k8s"
	"go.f110.dev/heimdallr/pkg/poll"
)

const (
	Namespace   = metav1.NamespaceDefault
	ServiceName = "zot"
	Port        = 5000
	NodePort    = 30000
	// MirrorHost is the registry that the in-cluster registry stands in for.
	MirrorHost = "ghcr.io"
)

// Install deploys the container registry to the cluster and waits for it to become ready.
func Install(cfg *rest.Config, fieldManager string) error {
	m, err := zot.Data.ReadFile("zot.yaml")
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := k8s.ApplyManifestFromString(cfg, m, fieldManager); err != nil {
		return err
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return xerrors.WithStack(err)
	}
	return poll.PollImmediate(context.TODO(), 5*time.Second, 3*time.Minute, func(ctx context.Context) (bool, error) {
		deploy, err := client.AppsV1().Deployments(Namespace).Get(ctx, ServiceName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if deploy.Status.ObservedGeneration != deploy.Generation {
			return false, nil
		}
		return deploy.Spec.Replicas != nil && deploy.Status.ReadyReplicas == *deploy.Spec.Replicas, nil
	})
}
