package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
)

const namespace = "lag_operator"

type Collector struct {
	client client.Client

	descProxyCreated *prometheus.Desc
}

func NewCollector(client client.Client) *Collector {
	return &Collector{
		client: client,

		descProxyCreated: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "proxy_created"),
			"Proxy creation timestamp",
			[]string{"name", "namespace"},
			nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descProxyCreated
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	proxies := &proxyv1.ProxyList{}
	err := c.client.List(context.Background(), proxies)
	if err != nil {
		controllerruntime.Log.Error(err, "Could not fetch proxy list")
	}

	for _, v := range proxies.Items {
		ch <- prometheus.MustNewConstMetric(c.descProxyCreated, prometheus.GaugeValue, float64(v.ObjectMeta.CreationTimestamp.Unix()), v.Name, v.Namespace)
	}
}
