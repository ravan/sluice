package pipeline_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/guacsec/guac/pkg/version"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/pipeline"
)

type failedScanTransport struct{}

func (failedScanTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("scanner unavailable")
}

func TestScannerFailureSurvivesInReceipt(t *testing.T) {
	saved := version.UATransport
	version.UATransport = failedScanTransport{}
	defer func() { version.UATransport = saved }()
	dir := t.TempDir()
	copyFixture(t, dir, "a.json")
	sink := &fakeSink{}
	rec, err := runOneShotPolicy(t, dir, sink, enrich.Policy{Sources: []enrich.Source{enrich.SourceOSV}}, pipeline.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if sink.calls != 1 || len(rec.EnrichFailed) != 1 || rec.EnrichFailed[0].Source != enrich.SourceOSV || rec.EnrichFailed[0].Digest == "" {
		t.Fatalf("missing scanner failure or base ingest: %+v calls=%d", rec, sink.calls)
	}
}
