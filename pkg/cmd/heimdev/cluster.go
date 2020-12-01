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

func setupCluster(kindPath, name, k8sVersion, kubeConfig string) error {
	if kubeConfig == "" {
		if v := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); v != "" {
			// Running on bazel
			kubeConfig = filepath.Join(v, ".kubeconfig")
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			kubeConfig = filepath.Join(cwd, ".kubeconfig")
		}
	}
	kindCluster, err := kind.NewCluster(kindPath, name, kubeConfig)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if exists, err := kindCluster.IsExist(name); err != nil {
		return xerrors.Errorf(": %w", err)
	} else if exists {
		return xerrors.New("Cluster already exists. abort.")
	}

	if err := kindCluster.Create(k8sVersion, 3); err != nil {
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

func Cluster(rootCmd *cobra.Command) {
	kindPath := ""
	clusterName := ""
	k8sVersion := ""
	kubeConfig := ""

	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage the cluster for development",
	}

	setup := &cobra.Command{
		Use:   "setup",
		Short: "Create and setup the cluster for develop the operator",
		RunE: func(_ *cobra.Command, _ []string) error {
			return setupCluster(kindPath, clusterName, k8sVersion, kubeConfig)
		},
	}
	setup.Flags().StringVarP(&clusterName, "name", "n", "", "Cluster name")
	setup.Flags().StringVar(&kindPath, "kind", "", "kind command path")
	setup.Flags().StringVar(&k8sVersion, "k8s-version", "", "Kubernetes version")
	setup.Flags().StringVar(&kubeConfig, "kubeconfig", "", "Path to the kubeconfig file. If not specified, will be used default file of kubectl")
	clusterCmd.AddCommand(setup)

	rootCmd.AddCommand(clusterCmd)
}
