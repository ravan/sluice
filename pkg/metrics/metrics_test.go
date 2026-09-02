package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCountersIncrement(t *testing.T) {
	m := New()

	m.DocumentIngested()
	m.DocumentIngested()
	m.DocumentSkipped()
	m.DocumentFailed()
	m.RecordsEmitted(9, 6)
	m.FallbacksCounted(3)
	m.SinkRetry()
	m.SinkRetry()

	if got := testutil.ToFloat64(m.documents.WithLabelValues("ingested")); got != 2 {
		t.Errorf("documents ingested = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.documents.WithLabelValues("skipped")); got != 1 {
		t.Errorf("documents skipped = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.documents.WithLabelValues("failed")); got != 1 {
		t.Errorf("documents failed = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.records.WithLabelValues("node")); got != 9 {
		t.Errorf("records node = %v, want 9", got)
	}
	if got := testutil.ToFloat64(m.records.WithLabelValues("edge")); got != 6 {
		t.Errorf("records edge = %v, want 6", got)
	}
	if got := testutil.ToFloat64(m.fallbacks); got != 3 {
		t.Errorf("fallbacks = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.retries); got != 2 {
		t.Errorf("retries = %v, want 2", got)
	}
}

func TestExpansionCounter(t *testing.T) {
	m := New()

	m.ExpansionDocuments(2)
	m.ExpansionDocuments(3)

	if got := testutil.ToFloat64(m.expansion); got != 5 {
		t.Errorf("expansion = %v, want 5", got)
	}
}

func TestHandlerServesExpansion(t *testing.T) {
	m := New()
	m.ExpansionDocuments(1)

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if !strings.Contains(string(body), "sluice_expansion_documents_total") {
		t.Errorf("body missing metric name sluice_expansion_documents_total; got:\n%s", string(body))
	}
}

func TestHandlerServesPrometheusText(t *testing.T) {
	m := New()
	m.DocumentIngested()

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)

	if !strings.Contains(text, "sluice_documents_total") {
		t.Errorf("body missing metric name sluice_documents_total; got:\n%s", text)
	}
	if !strings.Contains(text, `outcome="ingested"`) {
		t.Errorf("body missing outcome=\"ingested\"; got:\n%s", text)
	}
}

func TestDecoratorCounters(t *testing.T) {
	m := New()
	m.DocumentDecorated()
	m.DocumentDecorated()
	m.DocumentDecorateFailed()

	if got := testutil.ToFloat64(m.decorated); got != 2 {
		t.Errorf("decorated = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.decFailed); got != 1 {
		t.Errorf("decorate failed = %v, want 1", got)
	}

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	for _, name := range []string{"sluice_documents_decorated_total", "sluice_documents_decorate_failed_total"} {
		if !strings.Contains(string(body), name) {
			t.Errorf("body missing metric name %s", name)
		}
	}
}
