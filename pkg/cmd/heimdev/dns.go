package heimdev

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
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

func DNS(rootCmd *cobra.Command) {
	port := 5000
	dnsCmd := &cobra.Command{
		Use: "dns",
		RunE: func(cmd *cobra.Command, args []string) error {
			return dnsServer(port)
		},
	}
	dnsCmd.Flags().IntVar(&port, "port", port, "Listen port")

	rootCmd.AddCommand(dnsCmd)
}
