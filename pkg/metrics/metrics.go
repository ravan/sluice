// Package metrics is the Prometheus side of pipeline.Observer: it turns the
// pipeline's run events into counters and serves them over /metrics.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ravan/sluice/pkg/enrich"
)

// Metrics is one daemon's counter set, held in a private registry so a second
// Metrics in the same process (a test) does not collide with the first.
type Metrics struct {
	reg        *prometheus.Registry
	documents  *prometheus.CounterVec
	records    *prometheus.CounterVec
	fallbacks  prometheus.Counter
	retries    prometheus.Counter
	expansion  prometheus.Counter
	decorated  prometheus.Counter
	decFailed  prometheus.Counter
	claims     prometheus.Counter
	enrichFail *prometheus.CounterVec
}

// New registers a fresh counter set.
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
	claims := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sluice_claims_total",
	})
	enrichFail := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sluice_enrich_failures_total",
	}, []string{"source"})
	// safe: fresh registry, no possible duplicate
	reg.MustRegister(documents, records, fallbacks, retries, expansion, decorated, decFailed, claims, enrichFail)
	return &Metrics{
		reg:        reg,
		documents:  documents,
		records:    records,
		fallbacks:  fallbacks,
		retries:    retries,
		expansion:  expansion,
		decorated:  decorated,
		decFailed:  decFailed,
		claims:     claims,
		enrichFail: enrichFail,
	}
}

// Handler serves this Metrics alone, never the process-wide default registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// DocumentIngested counts one document whose records reached the sink.
func (m *Metrics) DocumentIngested() {
	m.documents.WithLabelValues("ingested").Inc()
}

// DocumentSkipped counts one document that did not survive processing or parsing.
func (m *Metrics) DocumentSkipped() {
	m.documents.WithLabelValues("skipped").Inc()
}

// DocumentFailed counts one document the sink rejected.
func (m *Metrics) DocumentFailed() {
	m.documents.WithLabelValues("failed").Inc()
}

// RecordsEmitted counts the records of one accepted sink call.
func (m *Metrics) RecordsEmitted(nodes, edges int64) {
	m.records.WithLabelValues("node").Add(float64(nodes))
	m.records.WithLabelValues("edge").Add(float64(edges))
}

// FallbacksCounted counts assertions whose timestamp fell back to ingest time.
func (m *Metrics) FallbacksCounted(n int) {
	m.fallbacks.Add(float64(n))
}

// SinkRetry counts one retried ingest attempt. It is wired to the Varve
// client OnRetry hook, not to pipeline.Observer.
func (m *Metrics) SinkRetry() {
	m.retries.Inc()
}

// ExpansionDocuments counts documents deps.dev expansion added to a run.
func (m *Metrics) ExpansionDocuments(n int) {
	m.expansion.Add(float64(n))
}

// DocumentDecorated counts one document that passed every decorator.
func (m *Metrics) DocumentDecorated() {
	m.decorated.Inc()
}

// DocumentDecorateFailed counts one document a decorator rejected.
func (m *Metrics) DocumentDecorateFailed() {
	m.decFailed.Inc()
}

// ClaimsEmitted counts the enrichment claims folded into one document.
func (m *Metrics) ClaimsEmitted(n int) {
	m.claims.Add(float64(n))
}

// EnrichFailed counts one failed enrichment call. The document is still
// ingested, so this never coincides with DocumentFailed.
func (m *Metrics) EnrichFailed(source enrich.Source) {
	m.enrichFail.WithLabelValues(string(source)).Inc()
}
