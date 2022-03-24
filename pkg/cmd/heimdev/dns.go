package heimdev

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"

	"go.f110.dev/heimdallr/pkg/cmd"
)

func dnsServer(port int) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, msg *dns.Msg) {
		res := new(dns.Msg)
		res.SetReply(msg)

		ans := make([]dns.RR, 0)
		for _, q := range msg.Question {
			log.Print(q.String())
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
	server := &dns.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Net:     "udp",
		Handler: mux,
	}
	server.ListenAndServe()

	return nil
}

func DNS(rootCmd *cmd.Command) {
	port := 5000
	dnsCmd := &cmd.Command{
		Use: "dns",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return dnsServer(port)
		},
	}
	dnsCmd.Flags().Int("port", "Listen port").Var(&port).Default(5000)

	rootCmd.AddCommand(dnsCmd)
}
