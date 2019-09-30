package internalapi

import (
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/server"
	"github.com/f110/lagrangian-proxy/pkg/stat"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "lagrangian"

type Collector struct {
	descActiveSocketCount *prometheus.Desc
	descActiveAgentCount  *prometheus.Desc
}

func NewCollector() *Collector {
	return &Collector{
		descActiveSocketCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "socket", "active_count"),
			"number of active connection of socket proxy",
			nil,
			nil,
		),
		descActiveAgentCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "agent", "active_count"),
			"number of active agents",
			nil,
			nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descActiveSocketCount
	ch <- c.descActiveAgentCount
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.descActiveSocketCount, prometheus.GaugeValue, float64(stat.Value.ActiveSocketProxyConn()))
	ch <- prometheus.MustNewConstMetric(c.descActiveAgentCount, prometheus.GaugeValue, float64(stat.Value.ActiveAgent()))
}

type Server struct{}

var _ server.ChildServer = &Server{}

func NewServer() *Server {
	prometheus.MustRegister(NewCollector())
	return &Server{}
}

func (s *Server) Route(router *httprouter.Router) {
	router.GET("/internal/metrics", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		promhttp.Handler().ServeHTTP(w, req)
	})
}
