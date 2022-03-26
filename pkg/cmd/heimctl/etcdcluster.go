package heimctl

import (
	"context"
	"os"
	"time"

	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	clientset "go.f110.dev/heimdallr/pkg/k8s/client/versioned"
)

func EtcdCluster(rootCmd *cmd.Command) {
	etcdClusterCmd := &cmd.Command{
		Use:   "etcdcluster",
		Short: "Manage the EtcdCluster",
	}

	namespaceFlag := ""
	forceUpdateCmd := &cmd.Command{
		Use:   "force-update cluster-name",
		Short: "Rolling update forcibly",
		Run: func(_ context.Context, c *cmd.Command, args []string) error {
			if len(args) == 0 {
				_, _ = os.Stderr.WriteString(c.Usage())
				return nil
			}
			name := args[0]

			loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
			overrides := &clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}
			loader := clientcmd.NewInteractiveDeferredLoadingClientConfig(loadingRules, overrides, os.Stdin)
			cfg, err := loader.ClientConfig()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			client, err := clientset.NewForConfig(cfg)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			ns := namespaceFlag
			if ns == "" {
				ns = metav1.NamespaceDefault
			}
			etcdCluster, err := client.EtcdV1alpha2().EtcdClusters(ns).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if etcdCluster.Spec.Template.Metadata.Annotations == nil {
				etcdCluster.Spec.Template.Metadata.Annotations = make(map[string]string)
			}
			etcdCluster.Spec.Template.Metadata.Annotations[etcd.AnnotationKeyRestartedAt] = time.Now().Format(time.RFC3339)
			_, err = client.EtcdV1alpha2().EtcdClusters(ns).Update(context.Background(), etcdCluster, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			return nil
		},
	}
	forceUpdateCmd.Flags().String("namespace", "Namespace").Var(&namespaceFlag).Shorthand("n")
	etcdClusterCmd.AddCommand(forceUpdateCmd)

	rootCmd.AddCommand(etcdClusterCmd)
}
