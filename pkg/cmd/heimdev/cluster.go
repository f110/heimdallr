package heimdev

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/k8s/kind"
)

const (
	defaultClusterName = "heimdallr"
)

func getKubeConfig(kubeConfig string) string {
	if kubeConfig == "" {
		if v := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); v != "" {
			// Running on bazel
			kubeConfig = filepath.Join(v, ".kubeconfig")
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				return ""
			}
			kubeConfig = filepath.Join(cwd, ".kubeconfig")
		}
	}

	return kubeConfig
}

func setupCluster(kindPath, name, k8sVersion string, workerNum int, kubeConfig string) error {
	kubeConfig = getKubeConfig(kubeConfig)
	kindCluster, err := kind.NewCluster(kindPath, name, kubeConfig)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if exists, err := kindCluster.IsExist(name); err != nil {
		return xerrors.Errorf(": %w", err)
	} else if exists {
		return xerrors.New("Cluster already exists. abort.")
	}

	if err := kindCluster.Create(k8sVersion, workerNum); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 3*time.Minute)
	if err := kindCluster.WaitReady(ctx); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cancelFunc()
	log.Printf("Complete creating cluster")

	restCfg, err := kindCluster.RESTConfig()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := kind.InstallCertManager(restCfg); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func deleteCluster(kindPath, name, kubeConfig string) error {
	kubeConfig = getKubeConfig(kubeConfig)
	kindCluster, err := kind.NewCluster(kindPath, name, kubeConfig)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if exists, err := kindCluster.IsExist(name); err != nil {
		return xerrors.Errorf(": %w", err)
	} else if !exists {
		return nil
	}

	if err := kindCluster.Delete(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func Cluster(rootCmd *cobra.Command) {
	kindPath := ""
	clusterName := ""
	k8sVersion := ""
	kubeConfig := ""
	workerNum := 3

	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage the cluster for development",
	}

	create := &cobra.Command{
		Use:   "create",
		Short: "Create the cluster for develop the operator",
		RunE: func(_ *cobra.Command, _ []string) error {
			return setupCluster(kindPath, clusterName, k8sVersion, workerNum, kubeConfig)
		},
	}
	create.Flags().StringVarP(&clusterName, "name", "n", defaultClusterName, "Cluster name")
	create.Flags().StringVar(&kindPath, "kind", "", "kind command path")
	create.Flags().StringVar(&k8sVersion, "k8s-version", "", "Kubernetes version")
	create.Flags().StringVar(&kubeConfig, "kubeconfig", "", "Path to the kubeconfig file. If not specified, will be used default file of kubectl")
	create.Flags().IntVar(&workerNum, "worker-num", 3, "The number of k8s workers")
	clusterCmd.AddCommand(create)

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete the cluster",
		RunE: func(_ *cobra.Command, _ []string) error {
			return deleteCluster(kindPath, clusterName, kubeConfig)
		},
	}
	del.Flags().StringVarP(&clusterName, "name", "n", defaultClusterName, "Cluster name")
	del.Flags().StringVar(&kindPath, "kind", "", "kind command path")
	del.Flags().StringVar(&kubeConfig, "kubeconfig", "", "Path to the kubeconfig file. If not specified, will be used default file of kubectl")
	clusterCmd.AddCommand(del)

	rootCmd.AddCommand(clusterCmd)
}
