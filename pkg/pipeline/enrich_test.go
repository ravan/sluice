package pipeline_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/varve"
)

type fakeEnricher struct {
	source enrich.Source
	claims []enrich.Claim
	err    error
	inputs []enrich.Input
	log    *[]enrich.Source
}

func (f *fakeEnricher) Source() enrich.Source { return f.source }

func (f *fakeEnricher) Enrich(_ context.Context, in enrich.Input) ([]enrich.Claim, error) {
	f.inputs = append(f.inputs, in)
	if f.log != nil {
		*f.log = append(*f.log, f.source)
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

type fakeObserver struct {
	enrichFailed map[string]int
	claims       int
}

func newFakeObserver() *fakeObserver { return &fakeObserver{enrichFailed: map[string]int{}} }

func (o *fakeObserver) DocumentIngested()                 {}
func (o *fakeObserver) DocumentSkipped()                  {}
func (o *fakeObserver) DocumentFailed()                   {}
func (o *fakeObserver) RecordsEmitted(_, _ int64)         {}
func (o *fakeObserver) FallbacksCounted(_ int)            {}
func (o *fakeObserver) ExpansionDocuments(_ int)          {}
func (o *fakeObserver) DocumentDecorated()                {}
func (o *fakeObserver) DocumentDecorateFailed()           {}
func (o *fakeObserver) ClaimsEmitted(n int)               { o.claims += n }
func (o *fakeObserver) EnrichFailed(source enrich.Source) { o.enrichFailed[string(source)]++ }

func testClaim(source enrich.Source, fact enrich.Fact, value string) enrich.Claim {
	return enrich.Claim{
		Source:    source,
		Subject:   "vuln:cve/cve-2026-12345",
		Fact:      fact,
		Value:     value,
		ValidFrom: pipeTestNow,
		FetchedAt: pipeTestNow,
	}
}

func claimNodes(s varve.Stream) []varve.NodeRecord {
	var out []varve.NodeRecord
	for _, n := range s.Nodes {
		for _, l := range n.Labels {
			if l == enrich.LabelClaim {
				out = append(out, n)
			}
		}
	}
	return out
}

func fixtureDigest(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestEnrichRunsOnlyWhatThePolicyAllows(t *testing.T) {
	euvdFake := &fakeEnricher{source: enrich.SourceEUVD, claims: []enrich.Claim{testClaim(enrich.SourceEUVD, "cvss", "8.1")}}
	osvFake := &fakeEnricher{source: enrich.SourceOSV, claims: []enrich.Claim{testClaim(enrich.SourceOSV, "affected", "pkg:v:a")}}
	fake := &fakeSink{responses: []response{{}}}

	rec, err := runOneShotPolicy(t, fixtureDir, fake,
		enrich.Policy{Sources: []enrich.Source{enrich.SourceEUVD}},
		pipeline.Deps{Enrichers: []enrich.Enricher{euvdFake, osvFake}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := claimNodes(fake.streams[0]); len(got) != 1 {
		t.Errorf("sunk stream has %d Claim nodes, want 1", len(got))
	}
	if rec.Claims != 1 {
		t.Errorf("Receipt.Claims = %d, want 1", rec.Claims)
	}
	if len(osvFake.inputs) != 0 {
		t.Errorf("the osv enricher was called %d times, want 0", len(osvFake.inputs))
	}
}

func TestEnrichRunsInPolicyOrderAndFeedsForward(t *testing.T) {
	var order []enrich.Source
	first := testClaim(enrich.SourceEUVD, "cvss", "8.1")
	euvdFake := &fakeEnricher{source: enrich.SourceEUVD, claims: []enrich.Claim{first}, log: &order}
	vcFake := &fakeEnricher{source: enrich.SourceVulnerableCode, claims: []enrich.Claim{testClaim(enrich.SourceVulnerableCode, "affected", "pkg:v:a")}, log: &order}
	fake := &fakeSink{responses: []response{{}}}

	if _, err := runOneShotPolicy(t, fixtureDir, fake,
		enrich.Policy{Sources: []enrich.Source{enrich.SourceEUVD, enrich.SourceVulnerableCode}},
		pipeline.Deps{Enrichers: []enrich.Enricher{vcFake, euvdFake}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []enrich.Source{enrich.SourceEUVD, enrich.SourceVulnerableCode}
	if len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Fatalf("call order = %v, want %v", order, want)
	}
	if len(vcFake.inputs) != 1 {
		t.Fatalf("the vulnerablecode enricher was called %d times, want 1", len(vcFake.inputs))
	}
	var seen bool
	for _, n := range claimNodes(vcFake.inputs[0].Records) {
		if n.ID == first.ID() {
			seen = true
		}
	}
	if !seen {
		t.Errorf("the vulnerablecode enricher's input does not hold the euvd claim node %q", first.ID())
	}
}

func TestEnrichFailureIsCountedNotFatal(t *testing.T) {
	plain := &fakeSink{responses: []response{{}}}
	base, err := runOneShotPolicy(t, fixtureDir, plain, enrich.Policy{}, pipeline.Deps{})
	if err != nil {
		t.Fatalf("Run without enrichers: %v", err)
	}
	baseNodes := len(plain.streams[0].Nodes)

	boom := errors.New("euvd is down")
	euvdFake := &fakeEnricher{source: enrich.SourceEUVD, err: boom}
	obs := newFakeObserver()
	fake := &fakeSink{responses: []response{{}}}

	rec, err := runOneShotPolicy(t, fixtureDir, fake,
		enrich.Policy{Sources: []enrich.Source{enrich.SourceEUVD}},
		pipeline.Deps{Enrichers: []enrich.Enricher{euvdFake}, Observer: obs})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.Documents != base.Documents || rec.Decorated != base.Decorated {
		t.Errorf("receipt = {Documents %d, Decorated %d}, want {%d, %d}", rec.Documents, rec.Decorated, base.Documents, base.Decorated)
	}
	if got := len(fake.streams[0].Nodes); got != baseNodes {
		t.Errorf("sunk stream has %d nodes, want %d", got, baseNodes)
	}
	if len(rec.EnrichFailed) != 1 {
		t.Fatalf("EnrichFailed = %+v, want exactly one entry", rec.EnrichFailed)
	}
	e := rec.EnrichFailed[0]
	if e.Source != enrich.SourceEUVD {
		t.Errorf("EnrichFailed[0].Source = %q, want %q", e.Source, enrich.SourceEUVD)
	}
	if want := fixtureDigest(t, "small-spdx.json"); e.Digest != want {
		t.Errorf("EnrichFailed[0].Digest = %q, want %q", e.Digest, want)
	}
	if !errors.Is(e, boom) {
		t.Errorf("EnrichFailed[0] = %v, want errors.Is(boom)", e)
	}
	if obs.enrichFailed["euvd"] != 1 {
		t.Errorf("observer saw EnrichFailed(euvd) %d times, want 1", obs.enrichFailed["euvd"])
	}
	for _, want := range []string{"enrich_failed=1", "enrich failed euvd"} {
		if !strings.Contains(rec.String(), want) {
			t.Errorf("Receipt.String() = %q, want it to contain %q", rec.String(), want)
		}
	}
}

func TestEnrichReportsASourceWithNoEnricher(t *testing.T) {
	cases := []struct {
		name         string
		source       enrich.Source
		wantFailures int
	}{
		{"euvd has no enricher", enrich.SourceEUVD, 1},
		{"osv runs in the scanner, not the enricher", enrich.SourceOSV, 0},
		{"federatedcode is a host job's replay", enrich.SourceFederatedCode, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := newFakeObserver()
			fake := &fakeSink{responses: []response{{}}}

			rec, err := runOneShotPolicy(t, fixtureDir, fake,
				enrich.Policy{Sources: []enrich.Source{tc.source}},
				pipeline.Deps{Observer: obs})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if rec.Documents != 1 {
				t.Errorf("Documents = %d, want 1: a missing enricher never drops a document", rec.Documents)
			}
			if len(rec.EnrichFailed) != tc.wantFailures {
				t.Fatalf("EnrichFailed = %+v, want %d entries", rec.EnrichFailed, tc.wantFailures)
			}
			if tc.wantFailures == 0 {
				return
			}
			e := rec.EnrichFailed[0]
			if e.Source != tc.source {
				t.Errorf("EnrichFailed[0].Source = %q, want %q", e.Source, tc.source)
			}
			if !errors.Is(e, pipeline.ErrNoEnricher) {
				t.Errorf("EnrichFailed[0] = %v, want errors.Is(ErrNoEnricher)", e)
			}
			if obs.enrichFailed[string(tc.source)] != 1 {
				t.Errorf("observer saw EnrichFailed(%s) %d times, want 1", tc.source, obs.enrichFailed[string(tc.source)])
			}
		})
	}
}

func TestEnrichStaysSilentWhenThePolicyItselfBlocksTheSource(t *testing.T) {
	fake := &fakeSink{responses: []response{{}}}

	rec, err := runOneShotPolicy(t, fixtureDir, fake,
		enrich.Policy{Sources: []enrich.Source{enrich.SourceOSV}, EUOnly: true},
		pipeline.Deps{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rec.EnrichFailed) != 0 {
		t.Errorf("EnrichFailed = %+v, want empty: the cap refusing a source is the feature, not a fault", rec.EnrichFailed)
	}
}

func TestEnricherSeesTheDocumentBytes(t *testing.T) {
	euvdFake := &fakeEnricher{source: enrich.SourceEUVD}
	fake := &fakeSink{responses: []response{{}}}

	if _, err := runOneShotPolicy(t, fixtureDir, fake,
		enrich.Policy{Sources: []enrich.Source{enrich.SourceEUVD}},
		pipeline.Deps{Enrichers: []enrich.Enricher{euvdFake}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(euvdFake.inputs) != 1 {
		t.Fatalf("the euvd enricher was called %d times, want 1", len(euvdFake.inputs))
	}
	want, err := os.ReadFile(filepath.Join(fixtureDir, "small-spdx.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if !bytes.Equal(euvdFake.inputs[0].Document, want) {
		t.Errorf("Input.Document is %d bytes, want the document's own %d bytes", len(euvdFake.inputs[0].Document), len(want))
	}
}
