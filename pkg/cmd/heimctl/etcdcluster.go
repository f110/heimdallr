package heimctl

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	clientset "go.f110.dev/heimdallr/pkg/k8s/client/versioned"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func EtcdCluster(rootCmd *cobra.Command) {
	etcdClusterCmd := &cobra.Command{
		Use:   "etcdcluster",
		Short: "Manage the EtcdCluster",
	}

	namespaceFlag := ""
	forceUpdateCmd := &cobra.Command{
		Use:   "force-update cluster-name",
		Short: "Rolling update forcibly",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Usage()
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
	forceUpdateCmd.Flags().StringVarP(&namespaceFlag, "namespace", "n", "", "Namespace")
	etcdClusterCmd.AddCommand(forceUpdateCmd)

	rootCmd.AddCommand(etcdClusterCmd)
}
