package heimdev

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.f110.dev/heimdallr/pkg/k8s"
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

func setupCluster(kindPath, name, k8sVersion string, workerNum int, kubeConfig, crdFile string) error {
	kubeConfig = getKubeConfig(kubeConfig)
	kindCluster, err := kind.NewCluster(kindPath, name, kubeConfig)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	exists, err := kindCluster.IsExist(name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if !exists {
		if err := kindCluster.Create(k8sVersion, workerNum); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		ctx, cancelFunc := context.WithTimeout(context.Background(), 3*time.Minute)
		if err := kindCluster.WaitReady(ctx); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		cancelFunc()
		log.Printf("Complete creating cluster")
	}

	restCfg, err := kindCluster.RESTConfig()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	log.Print("Install cert-manager")
	if err := kind.InstallCertManager(restCfg, "heimdev"); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	log.Print("Install minio")
	if err := kind.InstallMinIO(restCfg, "heimdev"); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	crds, err := k8s.ReadCRDFile(crdFile)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := k8s.EnsureCRD(restCfg, crds, 3*time.Minute); err != nil {
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

func runController(kindPath, name, manifestFile, controllerImage, sidecarImage, namespace string) error {
	kindCluster, err := kind.NewCluster(kindPath, name, "")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if exist, err := kindCluster.IsExist(name); err != nil {
		return xerrors.Errorf(": %w", err)
	} else if !exist {
		return xerrors.New("Cluster does not exist. You create the cluster first.")
	}

	containerImages := []*kind.ContainerImageFile{
		{
			File:       controllerImage,
			Repository: "ghcr.io/f110/heimdallr/operator",
			Tag:        "latest",
		},
		{
			File:       sidecarImage,
			Repository: "ghcr.io/f110/heimdallr/discovery-sidecar",
			Tag:        "latest",
		},
	}
	if err := kindCluster.LoadImageFiles(containerImages...); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	log.Printf("Apply manifest: %s", manifestFile)
	if err := kindCluster.Apply(manifestFile, "heimdev"); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	client, err := kindCluster.Clientset()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	pods, err := client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	for _, v := range pods.Items {
		log.Printf("Delete Pod: %s", v.Name)
		err := client.CoreV1().Pods(namespace).Delete(context.Background(), v.Name, metav1.DeleteOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	if err := waitForReadyPod(ctx, client, namespace, "heimdallr-operator"); err != nil {
		cancel()
		return xerrors.Errorf(": %w", err)
	}
	cancel()

	pods, err = client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if len(pods.Items) < 1 {
		return xerrors.New("could not found controller pod")
	}
	if err := tailLog(context.Background(), client, namespace, pods.Items[0].Name); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func logOperator(kindPath, name, namespace string) error {
	kindCluster, err := kind.NewCluster(kindPath, name, "")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	client, err := kindCluster.Clientset()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	pods, err := client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if len(pods.Items) < 1 {
		return xerrors.New("could not found controller pod")
	}
	if err := tailLog(context.Background(), client, "heimdallr", pods.Items[0].Name); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func loadImages(kindPath, name string, images []string) error {
	kindCluster, err := kind.NewCluster(kindPath, name, "")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if exist, err := kindCluster.IsExist(name); err != nil {
		return xerrors.Errorf(": %w", err)
	} else if !exist {
		return xerrors.New("Cluster does not exist. You create the cluster first.")
	}

	containerImages := make([]*kind.ContainerImageFile, 0)
	for _, v := range images {
		s := strings.SplitN(v, "=", 2)
		t := strings.SplitN(s[0], ":", 2)
		containerImages = append(containerImages, &kind.ContainerImageFile{
			File:       s[1],
			Repository: t[0],
			Tag:        t[1],
		})
	}
	if err := kindCluster.LoadImageFiles(containerImages...); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func waitForReadyPod(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ticker.C:
			deploy, err := client.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if deploy.Status.ObservedGeneration != deploy.Generation {
				continue
			}

			if deploy.Status.ReadyReplicas != *deploy.Spec.Replicas {
				continue
			}

			return nil
		case <-ctx.Done():
			return xerrors.New("time out:")
		}
	}
}

func tailLog(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	req := client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{Follow: true})
	s, err := req.Stream(ctx)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	_, err = io.Copy(os.Stdout, s)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

type commandOptions struct {
	KindPath    string
	ClusterName string
}

func Cluster(rootCmd *cobra.Command) {
	k8sVersion := ""
	kubeConfig := ""
	crdFile := ""
	workerNum := 3
	opts := &commandOptions{}

	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage the cluster for development",
	}

	create := &cobra.Command{
		Use:   "create",
		Short: "Create the cluster for develop the operator",
		RunE: func(_ *cobra.Command, _ []string) error {
			return setupCluster(opts.KindPath, opts.ClusterName, k8sVersion, workerNum, kubeConfig, crdFile)
		},
	}
	commonFlags(create.Flags(), opts)
	create.Flags().StringVar(&k8sVersion, "k8s-version", "", "Kubernetes version")
	create.Flags().StringVar(&kubeConfig, "kubeconfig", "", "Path to the kubeconfig file. If not specified, will be used default file of kubectl")
	create.Flags().StringVar(&crdFile, "crd", "", "Applying manifest file after create the cluster")
	create.Flags().IntVar(&workerNum, "worker-num", 3, "The number of k8s workers")
	clusterCmd.AddCommand(create)

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete the cluster",
		RunE: func(_ *cobra.Command, _ []string) error {
			return deleteCluster(opts.KindPath, opts.ClusterName, kubeConfig)
		},
	}
	commonFlags(del.Flags(), opts)
	del.Flags().StringVar(&kubeConfig, "kubeconfig", "", "Path to the kubeconfig file. If not specified, will be used default file of kubectl")
	clusterCmd.AddCommand(del)

	manifestFile := ""
	controllerImage := ""
	sidecarImage := ""
	namespace := ""
	runOperator := &cobra.Command{
		Use:   "run-operator",
		Short: "Run the operator",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runController(opts.KindPath, opts.ClusterName, manifestFile, controllerImage, sidecarImage, namespace)
		},
	}
	commonFlags(runOperator.Flags(), opts)
	runOperator.Flags().StringVar(&manifestFile, "manifest", "", "A manifest file for the controller")
	runOperator.Flags().StringVar(&controllerImage, "controller-image", "", "A path of file of controller")
	runOperator.Flags().StringVar(&sidecarImage, "sidecar-image", "", "A path of file of sidecar")
	runOperator.Flags().StringVarP(&namespace, "namespace", "n", "heimdallr", "The namespace of operator")
	clusterCmd.AddCommand(runOperator)

	logs := &cobra.Command{
		Use:   "log-operator",
		Short: "Print the log of operator",
		RunE: func(_ *cobra.Command, _ []string) error {
			return logOperator(opts.KindPath, opts.ClusterName, "heimdallr")
		},
	}
	commonFlags(logs.Flags(), opts)
	clusterCmd.AddCommand(logs)

	images := make([]string, 0)
	load := &cobra.Command{
		Use:   "load",
		Short: "Load container images",
		RunE: func(_ *cobra.Command, _ []string) error {
			return loadImages(opts.KindPath, opts.ClusterName, images)
		},
	}
	commonFlags(load.Flags(), opts)
	load.Flags().StringSliceVar(
		&images,
		"images",
		[]string{},
		`Loading images. each arguments will required name and path.
A separator between name and path is equal mark.
(e,g, --images ghcr.io/f110/heimdallr:latest=./image.tar)`,
	)
	clusterCmd.AddCommand(load)

	rootCmd.AddCommand(clusterCmd)
}

func commonFlags(fs *pflag.FlagSet, opts *commandOptions) {
	fs.StringVar(&opts.ClusterName, "name", defaultClusterName, "Cluster name")
	fs.StringVar(&opts.KindPath, "kind", "", "kind command path")
}
