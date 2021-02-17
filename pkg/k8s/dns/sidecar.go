package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"go.f110.dev/heimdallr/pkg/logger"
)

type Sidecar struct {
	s *dns.Server

	clusterDomain string
	ttl           uint32

	mu     sync.RWMutex
	toIP   map[string]net.IP
	fromIP map[string]string

	watchCancel context.CancelFunc
}

func NewSidecar(ctx context.Context, addr string, client kubernetes.Interface, namespace, clusterDomain string, ttl int) (*Sidecar, error) {
	s := &Sidecar{
		clusterDomain: clusterDomain,
		ttl:           uint32(ttl),
		toIP:          make(map[string]net.IP),
		fromIP:        make(map[string]string),
		s: &dns.Server{
			Addr: addr,
			Net:  "udp",
		},
	}

	podList, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	for _, v := range podList.Items {
		if len(v.Status.PodIPs) == 0 {
			continue
		}

		for _, i := range v.Status.PodIPs {
			ip := net.ParseIP(i.IP)

			ptr := net.IPv4(ip[15], ip[14], ip[13], ip[12])
			s.fromIP[ptr.String()] = fmt.Sprintf("%s.%s.pod.%s.", strings.ReplaceAll(i.IP, ".", "-"), v.Namespace, s.clusterDomain)
			s.toIP[fmt.Sprintf("%s/%s", v.Namespace, strings.ReplaceAll(ip.String(), ".", "-"))] = ip
		}
	}
	w, err := client.CoreV1().Pods(namespace).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	go s.watch(w)

	mux := dns.NewServeMux()
	s.s.Handler = mux
	mux.HandleFunc("ready.local.", s.handleReadiness)
	mux.HandleFunc(".", s.handleQuery)

	return s, nil
}

func (s *Sidecar) handleQuery(w dns.ResponseWriter, msg *dns.Msg) {
	ans := make([]dns.RR, 0)
	for _, q := range msg.Question {
		logger.Log.Debug(q.String())

		switch q.Qtype {
		case dns.TypeA:
			canonicalName := dns.CanonicalName(q.Name)
			idx := strings.Index(canonicalName, ".")
			ipAddr := canonicalName[:idx]
			ns := canonicalName[idx+1 : idx+1+strings.Index(canonicalName[idx+1:], ".")]

			s.mu.RLock()
			if ip, ok := s.toIP[fmt.Sprintf("%s/%s", ns, ipAddr)]; ok {
				ans = append(ans, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Class:  q.Qclass,
						Rrtype: q.Qtype,
						Ttl:    s.ttl,
					},
					A: ip,
				})
			}
			s.mu.RUnlock()
		case dns.TypePTR:
			n := strings.SplitN(q.Name, ".", 5)
			s.mu.RLock()
			if ptr, ok := s.fromIP[strings.Join(n[:4], ".")]; ok {
				ans = append(ans, &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Class:  q.Qclass,
						Rrtype: q.Qtype,
						Ttl:    s.ttl,
					},
					Ptr: ptr,
				})
			}
			s.mu.RUnlock()
		}
	}

	res := new(dns.Msg)
	res.SetReply(msg)
	res.Answer = ans
	w.WriteMsg(res)
}

func (s *Sidecar) handleReadiness(w dns.ResponseWriter, msg *dns.Msg) {
	if len(msg.Question) == 0 {
		logger.Log.Debug("Not have question", zap.Uint16("id", msg.Id))
		return
	}

	res := new(dns.Msg)
	res.SetReply(msg)
	ans := make([]dns.RR, 0)
	for _, q := range msg.Question {
		switch q.Qtype {
		case dns.TypeA:
			ans = append(ans, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Class:  q.Qclass,
					Rrtype: q.Qtype,
					Ttl:    5,
				},
				A: net.IPv4(127, 0, 1, 1),
			})
		case dns.TypeAAAA:
			ans = append(ans, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Class:  q.Qclass,
					Rrtype: q.Qtype,
				},
			})
		default:
			logger.Log.Debug("Unhandled query type", zap.Uint16("type", q.Qtype))
		}
	}
	res.Answer = ans

	w.WriteMsg(res)
}

func (s *Sidecar) watch(ch watch.Interface) {
	ctx, cancel := context.WithCancel(context.Background())
	s.watchCancel = cancel
	for {
		select {
		case event := <-ch.ResultChan():
			logger.Log.Debug("Got new event", zap.String("type", string(event.Type)))
			if event.Object == nil {
				logger.Log.Debug("Skip event because Object is nil")
				continue
			}

			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				logger.Log.Debug("Skip event because Object is not Pod", logger.TypeOf("type", event.Object))
				continue
			}
			if pod.Status.PodIP == "" {
				logger.Log.Debug("Skip event because Pod doesn't have PodIP")
				continue
			}

			switch event.Type {
			case watch.Added, watch.Modified:
				for _, i := range pod.Status.PodIPs {
					ip := net.ParseIP(i.IP)

					ptr := net.IPv4(ip[15], ip[14], ip[13], ip[12])
					s.mu.Lock()
					s.fromIP[ptr.String()] = fmt.Sprintf("%s.%s.pod.%s.", strings.ReplaceAll(i.IP, ".", "-"), pod.Namespace, s.clusterDomain)
					s.toIP[fmt.Sprintf("%s/%s", pod.Namespace, strings.ReplaceAll(ip.String(), ".", "-"))] = ip
					s.mu.Unlock()
				}
			case watch.Deleted:
				for _, i := range pod.Status.PodIPs {
					ip := net.ParseIP(i.IP)

					ptr := net.IPv4(ip[15], ip[14], ip[13], ip[12])
					s.mu.Lock()
					delete(s.fromIP, ptr.String())
					delete(s.toIP, fmt.Sprintf("%s/%s", pod.Namespace, strings.ReplaceAll(ip.String(), ".", "-")))
					s.mu.Unlock()
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Sidecar) Start() error {
	return s.s.ListenAndServe()
}

func (s *Sidecar) Shutdown(ctx context.Context) error {
	if s.watchCancel != nil {
		s.watchCancel()
	}
	return s.s.ShutdownContext(ctx)
}
