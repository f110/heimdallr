package e2eutil

import (
	"context"
	"time"

	"go.f110.dev/xerrors"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/pkg/poll"
)

const (
	operatorNamespace      = "heimdallr"
	operatorDeploymentName = "heimdallr-operator"
	operatorLeaseName      = "operator"
)

// PauseOperator stops the controllers of the operator by holding the lease of the leader election.
// The webhook keeps serving because the operator starts it before the leader election.
// The returned function resumes the controllers.
func PauseOperator(ctx context.Context, cfg *rest.Config, coreClient kubernetes.Interface) (func(context.Context) error, error) {
	deploy, err := coreClient.AppsV1().Deployments(operatorNamespace).Get(ctx, operatorDeploymentName, k8smetav1.GetOptions{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	replicas := *deploy.Spec.Replicas
	selector, err := k8smetav1.LabelSelectorAsSelector(deploy.Spec.Selector)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	if err := scaleOperator(ctx, coreClient, 0); err != nil {
		return nil, err
	}
	err = poll.PollImmediate(ctx, 1*time.Second, 3*time.Minute, func(ctx context.Context) (bool, error) {
		pods, err := coreClient.CoreV1().Pods(operatorNamespace).List(ctx, k8smetav1.ListOptions{LabelSelector: selector.String()})
		if err != nil {
			return false, err
		}
		return len(pods.Items) == 0, nil
	})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	err = coreClient.CoordinationV1().Leases(operatorNamespace).Delete(ctx, operatorLeaseName, k8smetav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, xerrors.WithStack(err)
	}
	now := k8smetav1.NewMicroTime(time.Now())
	_, err = coreClient.CoordinationV1().Leases(operatorNamespace).Create(ctx, &coordinationv1.Lease{
		ObjectMeta: k8smetav1.ObjectMeta{Name: operatorLeaseName, Namespace: operatorNamespace},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       new("e2e"),
			LeaseDurationSeconds: new(int32(3600)),
			AcquireTime:          &now,
			RenewTime:            &now,
		},
	}, k8smetav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	if err := scaleOperator(ctx, coreClient, replicas); err != nil {
		return nil, err
	}
	if err := WaitForWebhookReachable(ctx, cfg); err != nil {
		return nil, err
	}

	return func(ctx context.Context) error {
		err := coreClient.CoordinationV1().Leases(operatorNamespace).Delete(ctx, operatorLeaseName, k8smetav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return xerrors.WithStack(err)
		}
		return nil
	}, nil
}

func scaleOperator(ctx context.Context, coreClient kubernetes.Interface, replicas int32) error {
	deploy, err := coreClient.AppsV1().Deployments(operatorNamespace).Get(ctx, operatorDeploymentName, k8smetav1.GetOptions{})
	if err != nil {
		return xerrors.WithStack(err)
	}
	deploy.Spec.Replicas = &replicas
	if _, err := coreClient.AppsV1().Deployments(operatorNamespace).Update(ctx, deploy, k8smetav1.UpdateOptions{}); err != nil {
		return xerrors.WithStack(err)
	}
	return nil
}
