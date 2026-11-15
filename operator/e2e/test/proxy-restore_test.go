package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/kind"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

func TestProxyRestoreDatastore(t *testing.T) {
	f := framework.New(t, RESTConfig)
	defer f.Execute()

	f.Describe("Proxy whose datastore is restored from the backup", func(s *btesting.Scenario) {
		const (
			testUserId     = "e2e@f110.dev"
			restoredUserId = "restored@f110.dev"
		)
		var setupTime time.Time
		var restoredUserCert *tls.Certificate
		s.BeforeAll(func(_ context.Context, m *btesting.Matcher) {
			f.Proxy.Setup(m, testUserId,
				proxy.EtcdBackup(60, 5),
				proxy.EtcdBackupToMinIO(
					kind.MinIOBucketName,
					"proxy-restore",
					false,
					"minio",
					metav1.NamespaceDefault,
					&proxyv1alpha2.AWSCredentialSelector{
						Name:               "minio-token",
						Namespace:          metav1.NamespaceDefault,
						AccessKeyIDKey:     "accesskey",
						SecretAccessKeyKey: "secretkey",
					},
				),
			)
			setupTime = time.Now()
		})

		s.Step("waiting for backed up", func(s *btesting.Scenario) {
			s.Subject(func(_ context.Context, m *btesting.Matcher) {
				m.Must(e2eutil.WaitForBackup(f.Client(), f.Proxy.Datastore(m), setupTime))
			})

			s.It("should succeed backup", func(_ context.Context, m *btesting.Matcher) {
				m.True(f.Proxy.Datastore(m).Status.Backup.Succeeded)
			})
		})

		// The revision that the proxy has seen goes ahead of the backup.
		// After restoring, the revision is the future for etcd.
		s.Step("update users after the backup", func(s *btesting.Scenario) {
			s.Subject(func(ctx context.Context, m *btesting.Matcher) {
				rpcClient := f.Proxy.RPCClient(m)
				for i := range 20 {
					id := fmt.Sprintf("dummy-%d@f110.dev", i)
					m.Must(rpcClient.AddUser(ctx, id, "admin"))
					m.Must(rpcClient.DeleteUser(ctx, id, ""))
				}
			})

			s.It("should not have the dummy user", func(ctx context.Context, m *btesting.Matcher) {
				users, err := f.Proxy.RPCClient(m).ListAllUser(ctx)
				m.Must(err)
				found := false
				for _, v := range users {
					if v.Id == "dummy-0@f110.dev" {
						found = true
					}
				}
				m.False(found)
			})
		})

		s.Step("destroy the datastore", func(s *btesting.Scenario) {
			var restoreStartTime time.Time
			s.Subject(func(ctx context.Context, m *btesting.Matcher) {
				ec := f.Proxy.Datastore(m)
				restoreStartTime = time.Now()
				pods := make([]*corev1.Pod, 0, len(ec.Status.Members))
				for _, v := range ec.Status.Members {
					pod, err := f.CoreClient().CoreV1().Pods(ec.Namespace).Get(ctx, v.PodName, metav1.GetOptions{})
					m.Must(err)
					pods = append(pods, pod)
				}
				for _, v := range pods {
					m.Must(e2eutil.KillContainers(ctx, v))
				}
				m.Must(e2eutil.WaitForRestore(f.Client(), ec, restoreStartTime))
				m.Must(e2eutil.WaitForStatusOfEtcdClusterBecome(f.Client(), ec, etcdv1alpha2.EtcdClusterPhaseRunning, 10*time.Minute))
			})

			s.It("should restore completed", func(_ context.Context, m *btesting.Matcher) {
				ec := f.Proxy.Datastore(m)
				m.NotNil(ec.Status.Restored)
				m.True(ec.Status.Restored.Completed)
			})
		})

		s.Step("add the user after restoring", func(s *btesting.Scenario) {
			s.Subject(func(ctx context.Context, m *btesting.Matcher) {
				rpcClient := f.Proxy.RPCClient(m)
				m.Must(rpcClient.AddUser(ctx, restoredUserId, "admin"))
				cert, err := e2eutil.SetupClientCert(ctx, rpcClient, restoredUserId)
				m.Must(err)
				restoredUserCert = cert
			})

			s.It("should issue the client certificate", func(_ context.Context, m *btesting.Matcher) {
				m.NotNil(restoredUserCert)
			})
		})

		s.Step("send a request as the added user", func(s *btesting.Scenario) {
			s.Subject(func(_ context.Context, m *btesting.Matcher) {
				deadline := time.Now().Add(3 * time.Minute)
				for {
					f.Proxy.AgentWithCert(restoredUserCert).Get(m, f.Proxy.Backend, nil)
					if m.LastResponse().StatusCode == http.StatusOK || time.Now().After(deadline) {
						break
					}
					time.Sleep(10 * time.Second)
				}
			})

			s.It("should return status OK", func(_ context.Context, m *btesting.Matcher) {
				m.StatusCode(http.StatusOK)
			})
		})
	})
}
