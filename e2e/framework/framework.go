package framework

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"

	"go.f110.dev/heimdallr/pkg/netutil"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

var (
	format   *string
	junit    *string
	step     *bool
	verbose  *bool
	e2eDebug *bool

	stdout = os.Stdout
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	format = flag.String("e2e.format", "", "Output format. (json, doc)")
	junit = flag.String("e2e.junit", "", "JUnit output file path")
	step = flag.Bool("e2e.step", false, "Step execution")
	verbose = flag.Bool("e2e.verbose", false, "Verbose output. include stdout and stderr of all child processes.")
	e2eDebug = flag.Bool("e2e.debug", false, "Debug e2e framework")
}

type Framework struct {
	*btesting.BehaviorDriven

	Proxy  *Proxy
	Agents *Agents
	DNS    *dns.Server
}

func New(t *testing.T) *Framework {
	p, err := NewProxy(t)
	if err != nil {
		t.Fatalf("Failed setup proxy: %v", err)
	}

	dnsPort, err := netutil.FindUnusedPort()
	if err != nil {
		t.Fatal("Failed find unused port")
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, msg *dns.Msg) {
		res := new(dns.Msg)
		res.SetReply(msg)

		ans := make([]dns.RR, 0)
		for _, q := range msg.Question {
			switch q.Qtype {
			case dns.TypeA:
				ans = append(ans, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: q.Qtype,
						Class:  q.Qclass,
						Ttl:    10,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
			}
		}
		res.Answer = ans

		w.WriteMsg(res)
	})
	dnsServer := &dns.Server{
		Addr:    fmt.Sprintf(":%d", dnsPort),
		Net:     "udp",
		Handler: mux,
	}
	go dnsServer.ListenAndServe()

	return &Framework{
		BehaviorDriven: btesting.New(t, *junit, *step),
		Proxy:          p,
		Agents:         NewAgents(p.Domain, p.CA, p.sessionStore, p.rpcPort, p.signPrivateKey),
		DNS:            dnsServer,
	}
}

func (f *Framework) Execute() {
	f.BehaviorDriven.Execute(*format)
}
