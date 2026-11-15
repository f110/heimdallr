package e2eutil

import (
	"context"
	"os/exec"
	"strings"

	"go.f110.dev/xerrors"
	corev1 "k8s.io/api/core/v1"
)

// KillContainers sends SIGKILL to all containers of the pod.
// The pod has to be running on the node of kind because the containers are stopped through the node.
func KillContainers(ctx context.Context, pod *corev1.Pod) error {
	for _, v := range pod.Status.ContainerStatuses {
		_, id, ok := strings.Cut(v.ContainerID, "://")
		if !ok {
			return xerrors.NewfWithStack("unexpected container id: %s", v.ContainerID)
		}
		out, err := exec.CommandContext(ctx, "docker", "exec", pod.Spec.NodeName, "crictl", "stop", "--timeout", "0", id).CombinedOutput()
		if err != nil {
			return xerrors.WithMessagef(err, "failed to stop the container: %s", string(out))
		}
	}

	return nil
}
