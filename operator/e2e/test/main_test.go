package test

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"testing"

	_ "github.com/smartystreets/goconvey/convey"
	"golang.org/x/xerrors"
	"k8s.io/klog/v2"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/operator/pkg/controllers"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/k8s"
	"go.f110.dev/heimdallr/pkg/k8s/kind"
	"go.f110.dev/heimdallr/pkg/logger"
)

func init() {
	framework.Flags(flag.CommandLine)
}

func setupSuite(id string) (*kind.Cluster, error) {
	k8sCluster, err := kind.NewCluster(framework.Config.KindFile, "e2e-"+id, "")
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := k8sCluster.Create(framework.Config.ClusterVersion, 3); err != nil {
		log.Fatalf("Could not create a cluster: %v", err)
	}
	kubeConfig := k8sCluster.KubeConfig()
	log.Printf("KubeConfig: %s", kubeConfig)

	cfg, err := k8sCluster.RESTConfig()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	RESTConfig = cfg

	if err := k8sCluster.WaitReady(context.TODO()); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if framework.Config.ProxyImageFile != "" ||
		framework.Config.RPCImageFile != "" ||
		framework.Config.DashboardImageFile != "" ||
		framework.Config.OperatorImageFile != "" ||
		framework.Config.SidecarImageFile != "" {
		images := []*kind.ContainerImageFile{
			{
				File:       framework.Config.ProxyImageFile,
				Repository: controllers.ProxyImageRepository,
				Tag:        "e2e",
			},
			{
				File:       framework.Config.RPCImageFile,
				Repository: controllers.RPCServerImageRepository,
				Tag:        "e2e",
			},
			{
				File:       framework.Config.DashboardImageFile,
				Repository: controllers.DashboardImageRepository,
				Tag:        "e2e",
			},
			{
				File:       framework.Config.OperatorImageFile,
				Repository: "quay.io/f110/heimdallr-operator",
				Tag:        "e2e",
			},
			{
				File:       framework.Config.SidecarImageFile,
				Repository: "quay.io/f110/heimdallr-discovery-sidecar",
				Tag:        framework.Config.BuildVersion,
			},
		}
		if err := k8sCluster.LoadImageFiles(images...); err != nil {
			log.Fatal(err)
		}

		framework.Config.ProxyVersion = "e2e"
	}

	if err := kind.InstallCertManager(cfg, "operator-e2e"); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := kind.InstallMinIO(cfg, "operator-e2e"); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	if err := k8sCluster.Apply(framework.Config.AllInOneManifest, "e2e"); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	crds, err := k8s.ReadCRDFile(framework.Config.AllInOneManifest)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := k8s.WaitForReadyWebhook(cfg, crds); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return k8sCluster, nil
}

func TestMain(m *testing.M) {
	flag.Parse()

	rand.Seed(framework.Config.RandomSeed)
	id := e2eutil.MakeId()

	logLevel := "fatal"
	if framework.Config.Verbose {
		logLevel = "debug"
	}
	if err := logger.OverrideKlog(&configv2.Logger{Level: logLevel}); err != nil {
		panic(err)
		return
	}
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	klog.InitFlags(fs)
	if err := fs.Parse([]string{"-stderrthreshold=FATAL", fmt.Sprintf("-logtostderr=%v", framework.Config.Verbose)}); err != nil {
		log.Fatal(err)
	}
	klog.SetOutput(ioutil.Discard)

	log.Printf("%+v", framework.Config)

	var k8sCluster *kind.Cluster
	framework.BeforeSuite(func() {
		if v, err := setupSuite(id); err != nil {
			log.Fatalf("%+v", err)
		} else {
			k8sCluster = v
		}
	})

	framework.AfterSuite(func() {
		if k8sCluster != nil && !framework.Config.Retain {
			if err := k8sCluster.Delete(); err != nil {
				log.Fatalf("Could not delete a cluster: %v", err)
			}
		}
	})

	framework.RunSpec(m)
}
