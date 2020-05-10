package main

import (
	"bytes"
	"context"
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsClientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog"

	"github.com/f110/lagrangian-proxy/operator/e2e/e2eutil"
	"github.com/f110/lagrangian-proxy/operator/e2e/test"
	"github.com/f110/lagrangian-proxy/operator/pkg/controllers"
)

var (
	CRDDir = flag.String("crd", "", "CRD files")
)

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	rand.Seed(ginkgo.GinkgoRandomSeed())
	id := e2eutil.MakeId()
	kubeConfig := ""

	crdFiles := make([][]byte, 0)
	filepath.Walk(*CRDDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("%s: %v", path, err)
			return err
		}
		if info.IsDir() {
			return nil
		}

		f, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		crdFiles = append(crdFiles, f)

		return nil
	})

	crd := make([]*apiextensionsv1.CustomResourceDefinition, 0)
	sch := runtime.NewScheme()
	_ = apiextensionsv1.AddToScheme(sch)
	codecs := serializer.NewCodecFactory(sch)
	for _, v := range crdFiles {
		obj, _, err := codecs.UniversalDeserializer().Decode(v, nil, nil)
		if err != nil {
			log.Fatal(err)
		}
		c, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			log.Printf("%v is not CustomResourceDefinition", obj)
			continue
		}
		crd = append(crd, c)
	}

	ginkgo.BeforeSuite(func() {
		k, err := e2eutil.CreateCluster(id)
		if err != nil {
			log.Fatalf("Could not create a cluster: %v", err)
		}
		kubeConfig = k

		cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			log.Fatalf("Could not build config: %v", err)
		}
		kubeClient, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if err := e2eutil.WaitForReady(context.TODO(), kubeClient); err != nil {
			log.Fatal(err)
		}

		// Create CustomResourceDefinition
		apiextensionsClient, err := apiextensionsClientset.NewForConfig(cfg)
		if err != nil {
			log.Fatal(err)
		}
		for _, v := range crd {
			_, err = apiextensionsClient.CustomResourceDefinitions().Create(v)
			if err != nil {
				log.Fatal(err)
			}
		}
		test.Config = cfg

		lock, err := resourcelock.New(
			resourcelock.LeasesResourceLock,
			"default",
			"e2e",
			kubeClient.CoreV1(),
			kubeClient.CoordinationV1(),
			resourcelock.ResourceLockConfig{Identity: id},
		)
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			leaderelection.RunOrDie(context.TODO(), leaderelection.LeaderElectionConfig{
				Lock:            lock,
				ReleaseOnCancel: true,
				LeaseDuration:   30 * time.Second,
				RenewDeadline:   15 * time.Second,
				RetryPeriod:     5 * time.Second,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: func(ctx context.Context) {
						c, err := controllers.NewEtcdController(ctx, kubeClient, cfg, "cluster.local", true)
						if err != nil {
							os.Exit(1)
						}

						c.Run(ctx, 1)
					},
					OnStoppedLeading: func() {},
					OnNewLeader: func(identity string) {
						if identity == id {
							return
						}
					},
				},
			})
		}()
	})
	ginkgo.AfterSuite(func() {
		if kubeConfig != "" {
			os.Remove(kubeConfig)
		}

		err := e2eutil.DeleteCluster(id)
		if err != nil {
			log.Fatalf("Could not delete a cluster: %v", err)
		}
	})

	defer ginkgo.GinkgoRecover()

	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	klog.InitFlags(fs)
	if err := fs.Parse([]string{"-stderrthreshold=FATAL", "-logtostderr=false"}); err != nil {
		log.Fatal(err)
	}
	klog.SetOutput(new(bytes.Buffer))
	ginkgo.RunSpecs(ginkgo.GinkgoT(), "Operator e2e Suite")
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
