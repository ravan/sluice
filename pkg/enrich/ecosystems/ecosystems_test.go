package ecosystems

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

var testNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func testPkgNode(id, purl string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:     varve.NodeID(id),
		Labels: []varve.NodeLabel{assemble.LabelPkgVersion},
		Props:  []varve.Prop{{Key: assemble.PropPurl, Value: varve.Str(purl)}},
	}
}

func testStream() varve.Stream {
	return varve.Stream{Nodes: []varve.NodeRecord{
		testPkgNode("pkg:lodash", "pkg:npm/lodash@4.17.21"),
		testPkgNode("pkg:express", "pkg:npm/express@4.19.2"),
	}}
}

// stub answers the lookup path from testdata, recording the purls it was asked.
func stub(t *testing.T, seen *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		purl := r.URL.Query().Get("purl")
		*seen = append(*seen, purl)
		name := "lookup-empty.json"
		if strings.Contains(purl, "lodash") {
			name = "lookup-lodash.json"
		}
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ecosystems", name))
		if err != nil {
			t.Errorf("reading fixture: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, werr := w.Write(body); werr != nil {
			t.Errorf("writing response: %v", werr)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnrich(t *testing.T) {
	var seen []string
	srv := stub(t, &seen)
	e, err := New(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Source(); got != enrich.SourceEcosystems {
		t.Fatalf("Source() = %q, want %q", got, enrich.SourceEcosystems)
	}
	got, err := e.Enrich(context.Background(), enrich.Input{Records: testStream(), Now: testNow})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	want := []enrich.Claim{{
		Source:    enrich.SourceEcosystems,
		Subject:   "pkg:lodash",
		Fact:      enrich.FactSupplier,
		Value:     "Lodash Utilities",
		Ref:       "https://github.com/lodash/lodash",
		ValidFrom: testNow,
		FetchedAt: testNow,
	}}
	if len(got) != len(want) {
		t.Fatalf("Enrich() returned %d claims, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("claim %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	wantSeen := []string{"pkg:npm/express@4.19.2", "pkg:npm/lodash@4.17.21"}
	if !reflect.DeepEqual(seen, wantSeen) {
		t.Errorf("the server was asked %v, want %v", seen, wantSeen)
	}
}

func TestEnrichReportsABadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	e, err := New(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.Enrich(context.Background(), enrich.Input{Records: testStream(), Now: testNow}); !errors.Is(err, ErrStatus) {
		t.Errorf("Enrich error = %v, want errors.Is(ErrStatus)", err)
	}
}

func TestEnrichSkipsARecordWithNoOwnerName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`[{"repository_url": "https://example.test/x", "repo_metadata": {"owner_record": {"name": ""}}}]`)); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	e, err := New(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := e.Enrich(context.Background(), enrich.Input{Records: testStream(), Now: testNow})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Enrich() returned %d claims for a record with no owner name, want 0", len(got))
	}
}
