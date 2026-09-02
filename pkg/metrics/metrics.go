package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg       *prometheus.Registry
	documents *prometheus.CounterVec
	records   *prometheus.CounterVec
	fallbacks prometheus.Counter
	retries   prometheus.Counter
	expansion prometheus.Counter
	decorated prometheus.Counter
	decFailed prometheus.Counter
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	documents := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sluice_documents_total",
	}, []string{"outcome"})
	records := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sluice_records_emitted_total",
	}, []string{"kind"})
	fallbacks := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sluice_valid_time_fallbacks_total",
	})
	retries := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sluice_sink_retries_total",
	})
	expansion := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sluice_expansion_documents_total",
	})
	decorated := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sluice_documents_decorated_total",
	})
	decFailed := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sluice_documents_decorate_failed_total",
	})
	// safe: fresh registry, no possible duplicate
	reg.MustRegister(documents, records, fallbacks, retries, expansion, decorated, decFailed)
	return &Metrics{
		reg:       reg,
		documents: documents,
		records:   records,
		fallbacks: fallbacks,
		retries:   retries,
		expansion: expansion,
		decorated: decorated,
		decFailed: decFailed,
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

func (m *Metrics) DocumentIngested() {
	m.documents.WithLabelValues("ingested").Inc()
}

func (m *Metrics) DocumentSkipped() {
	m.documents.WithLabelValues("skipped").Inc()
}

func (m *Metrics) DocumentFailed() {
	m.documents.WithLabelValues("failed").Inc()
}

func (m *Metrics) RecordsEmitted(nodes, edges int64) {
	m.records.WithLabelValues("node").Add(float64(nodes))
	m.records.WithLabelValues("edge").Add(float64(edges))
}

func (m *Metrics) FallbacksCounted(n int) {
	m.fallbacks.Add(float64(n))
}

func (m *Metrics) SinkRetry() {
	m.retries.Inc()
}

func (m *Metrics) ExpansionDocuments(n int) {
	m.expansion.Add(float64(n))
}

func (m *Metrics) DocumentDecorated() {
	m.decorated.Inc()
}

func (m *Metrics) DocumentDecorateFailed() {
	m.decFailed.Inc()
}
