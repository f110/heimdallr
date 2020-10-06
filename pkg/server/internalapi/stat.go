package internalapi

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.f110.dev/heimdallr/pkg/server"
	"go.f110.dev/heimdallr/pkg/stat"
)

const namespace = "heimdallr"

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

type Server struct {
	r *prometheus.Registry
}

var _ server.ChildServer = &Server{}

func New() *Server {
	r := prometheus.NewRegistry()
	r.MustRegister(NewCollector())
	r.MustRegister(prometheus.NewGoCollector())
	return &Server{r: r}
}

func (s *Server) Route(router *httprouter.Router) {
	handler := promhttp.InstrumentMetricHandler(s.r, promhttp.HandlerFor(s.r, promhttp.HandlerOpts{}))
	router.GET("/internal/metrics", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		handler.ServeHTTP(w, req)
	})
}
