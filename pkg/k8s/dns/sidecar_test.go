package dns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestSidecar_handleQuery(t *testing.T) {
	coreClient := k8sfake.NewSimpleClientset()
	sharedInformerFactory := informers.NewSharedInformerFactory(coreClient, 0)
	sharedInformerFactory.Core().V1().Pods().Informer().GetIndexer().Add(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceDefault,
			Name:      "test",
		},
		Status: corev1.PodStatus{
			PodIP: "172.17.0.3",
			PodIPs: []corev1.PodIP{
				{IP: "172.17.0.3"},
			},
		},
	})

	s, err := NewSidecar("", sharedInformerFactory, metav1.NamespaceDefault, "cluster.local", 10)
	require.NoError(t, err)
	err = s.load()
	require.NoError(t, err)

	t.Run("Resolve", func(t *testing.T) {
		cases := []struct {
			Query  string
			Answer string
		}{
			{
				Query:  "172-17-0-3.default.pod.cluster.local.",
				Answer: "172-17-0-3.default.pod.cluster.local.\t10\tIN\tA\t172.17.0.3",
			},
			{
				Query:  "172-17-0-3.default.pod",
				Answer: "172-17-0-3.default.pod\t10\tIN\tA\t172.17.0.3",
			},
		}

		for _, tt := range cases {
			rec := &ResponseRecorder{}
			s.handleQuery(
				rec,
				&dns.Msg{
					Question: []dns.Question{
						{Name: tt.Query, Qtype: dns.TypeA, Qclass: dns.ClassINET},
					},
				},
			)

			require.True(t, rec.msg.Response)
			require.Len(t, rec.msg.Answer, 1)
			assert.Equal(t, tt.Answer, rec.msg.Answer[0].String())
		}
	})

	t.Run("ReverseResolve", func(t *testing.T) {
		cases := []struct {
			Query  string
			Answer string
		}{
			{
				Query:  "3.0.17.172.in-addr.arpa.",
				Answer: "3.0.17.172.in-addr.arpa.\t10\tIN\tPTR\t172-17-0-3.default.pod.cluster.local.",
			},
		}

		for _, tt := range cases {
			rec := &ResponseRecorder{}
			s.handleQuery(
				rec,
				&dns.Msg{
					Question: []dns.Question{
						{Name: tt.Query, Qtype: dns.TypePTR, Qclass: dns.ClassINET},
					},
				},
			)

			require.True(t, rec.msg.Response)
			require.Len(t, rec.msg.Answer, 1)
			assert.Equal(t, tt.Answer, rec.msg.Answer[0].String())
		}
	})
}

type ResponseRecorder struct {
	msg *dns.Msg
}

func (r *ResponseRecorder) LocalAddr() net.Addr {
	panic("implement me")
}

func (r *ResponseRecorder) RemoteAddr() net.Addr {
	panic("implement me")
}

func (r *ResponseRecorder) WriteMsg(msg *dns.Msg) error {
	r.msg = msg
	return nil
}

func (r *ResponseRecorder) Write(bytes []byte) (int, error) {
	panic("implement me")
}

func (r *ResponseRecorder) Close() error {
	panic("implement me")
}

func (r *ResponseRecorder) TsigStatus() error {
	panic("implement me")
}

func (r *ResponseRecorder) TsigTimersOnly(b bool) {
	panic("implement me")
}

func (r *ResponseRecorder) Hijack() {
	panic("implement me")
}
