package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
)

const namespace = "lag_operator"

type Collector struct {
	client clientset.Interface

	descProxyCreated *prometheus.Desc
}

func NewCollector(client clientset.Interface) *Collector {
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
	proxies, err := c.client.ProxyV1().Proxies("").List(metav1.ListOptions{LabelSelector: labels.Everything().String()})
	if err != nil {
		// controllerruntime.Log.Error(err, "Could not fetch proxy list")
		return
	}

	for _, v := range proxies.Items {
		ch <- prometheus.MustNewConstMetric(c.descProxyCreated, prometheus.GaugeValue, float64(v.ObjectMeta.CreationTimestamp.Unix()), v.Name, v.Namespace)
	}
}
