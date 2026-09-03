package vulnerablecode

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

var now = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

const (
	lodashPurl  = "pkg:npm/lodash@4.17.21"
	expressPurl = "pkg:npm/express@4.19.2"
	theCVE      = "CVE-2026-2950"
)

// server records what the enricher asked and answers from the recorded bodies.
type server struct {
	*httptest.Server
	purls  []string
	agents []string
	status int
}

func start(t *testing.T) *server {
	t.Helper()
	s := &server{status: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.purls = append(s.purls, r.URL.Query().Get("purl"))
		s.agents = append(s.agents, r.Header.Get("User-Agent"))
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			return
		}
		name := "affected-by-empty.json"
		if strings.Contains(r.URL.Query().Get("purl"), "lodash") {
			name = "affected-by-lodash-4.17.21.json"
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vulnerablecode", name))
		if err != nil {
			t.Errorf("read fixture %s: %v", name, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

func stream() varve.Stream {
	return varve.Stream{Nodes: []varve.NodeRecord{
		pkgNode(lodashPurl),
		pkgNode(expressPurl),
		{
			ID:     assemble.VulnID("cve", theCVE),
			Labels: []varve.NodeLabel{assemble.LabelVulnerability},
			Props: []varve.Prop{
				{Key: assemble.PropType, Value: varve.Str("cve")},
				{Key: assemble.PropVulnID, Value: varve.Str(theCVE)},
			},
		},
	}}
}

func pkgNode(purl string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:     varve.NodeID("pv:" + purl),
		Labels: []varve.NodeLabel{assemble.LabelPkgVersion},
		Props:  []varve.Prop{{Key: assemble.PropPurl, Value: varve.Str(purl)}},
	}
}

func enrichAll(t *testing.T, s *server, in varve.Stream) []enrich.Claim {
	t.Helper()
	e, err := New(s.URL, s.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims, err := e.Enrich(context.Background(), enrich.Input{Digest: "sha256:abc", Records: in, Now: now})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	return claims
}

// pick returns the claims about subject with fact, in the order emitted.
func pick(claims []enrich.Claim, subject varve.NodeID, fact enrich.Fact) []enrich.Claim {
	var out []enrich.Claim
	for _, c := range claims {
		if c.Subject == subject && c.Fact == fact {
			out = append(out, c)
		}
	}
	return out
}

func TestSource(t *testing.T) {
	e, err := New(DefaultURL, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.Source(); got != enrich.SourceVulnerableCode {
		t.Errorf("Source() = %q, want %q", got, enrich.SourceVulnerableCode)
	}
}

func TestEnrichAsksOncePerPackage(t *testing.T) {
	s := start(t)
	enrichAll(t, s, stream())

	want := []string{expressPurl, lodashPurl}
	if len(s.purls) != len(want) {
		t.Fatalf("purls asked = %v, want %v", s.purls, want)
	}
	for i := range want {
		if s.purls[i] != want[i] {
			t.Fatalf("purls asked = %v, want %v", s.purls, want)
		}
	}
	for i, a := range s.agents {
		if a != UserAgent {
			t.Errorf("request %d User-Agent = %q, want %q", i, a, UserAgent)
		}
	}
}

func TestEnrichPackageFacingClaims(t *testing.T) {
	claims := enrichAll(t, start(t), stream())
	pkg := varve.NodeID("pv:" + lodashPurl)

	affected := pick(claims, pkg, enrich.FactAffected)
	want := []string{
		"npm/lodash/CVE-2026-2950", "GHSA-f23m-r3pf-42rh", "npm/lodash/CVE-2026-4800",
		"npm/lodash/CVE-2025-13465", "GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg",
	}
	if len(affected) != len(want) {
		t.Fatalf("affected claims = %d, want %d", len(affected), len(want))
	}
	for i, w := range want {
		if affected[i].Value != w {
			t.Errorf("affected claim %d value = %q, want %q", i, affected[i].Value, w)
		}
	}
	if got := affected[0].Ref; got != "gitlab/npm/lodash/CVE-2026-2950" {
		t.Errorf("affected[0].Ref = %q, want the advisory_uid", got)
	}
	cve := assemble.VulnID("cve", theCVE)
	if len(affected[0].Also) != 1 || affected[0].Also[0] != cve {
		t.Errorf("affected[0].Also = %v, want exactly [%s]", affected[0].Also, cve)
	}
	if len(affected[5].Also) != 0 {
		t.Errorf("affected[5].Also = %v, want none: no node in the stream aliases it", affected[5].Also)
	}
	if len(pick(claims, pkg, enrich.FactCVSS)) != 0 {
		t.Error("the package-facing claim set holds only affected")
	}
}

func TestEnrichHangsNothingOffAnAbsentNode(t *testing.T) {
	claims := enrichAll(t, start(t), stream())
	known := map[varve.NodeID]bool{}
	for _, n := range stream().Nodes {
		known[n.ID] = true
	}
	for _, c := range claims {
		if !known[c.Subject] {
			t.Errorf("claim %s/%s is subject to %q, which the stream does not carry", c.Fact, c.Value, c.Subject)
		}
		for _, a := range c.Also {
			if !known[a] {
				t.Errorf("claim %s/%s is also about %q, which the stream does not carry", c.Fact, c.Value, a)
			}
		}
	}
}

func TestEnrichSeverityRule(t *testing.T) {
	claims := enrichAll(t, start(t), stream())
	cve := assemble.VulnID("cve", theCVE)

	// npm/lodash/CVE-2026-2950 carries one cvssv3.1 severity with an empty
	// value, so it states no score at all (D6).
	for _, f := range []enrich.Fact{enrich.FactCVSS, enrich.FactCVSSVersion, enrich.FactCVSSVector} {
		for _, c := range pick(claims, cve, f) {
			if c.Ref == "gitlab/npm/lodash/CVE-2026-2950" {
				t.Errorf("advisory with an empty severity value states %s = %q", f, c.Value)
			}
		}
	}

	want := map[enrich.Fact]string{
		enrich.FactCVSS:        "6.5",
		enrich.FactCVSSVersion: "3.1",
		enrich.FactCVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
	}
	for f, w := range want {
		got := pick(claims, cve, f)
		if len(got) != 1 {
			t.Fatalf("%s claims about %s = %d, want 1", f, cve, len(got))
		}
		if got[0].Value != w {
			t.Errorf("%s = %q, want %q", f, got[0].Value, w)
		}
		if got[0].Ref != "github_osv/GHSA-f23m-r3pf-42rh" {
			t.Errorf("%s Ref = %q, want the advisory_uid", f, got[0].Ref)
		}
	}
}

func TestEnrichSkipsAnAdvisoryWhoseAliasIsAbsent(t *testing.T) {
	claims := enrichAll(t, start(t), stream())
	for _, c := range claims {
		if c.Ref == "github_osv/GHSA-xxjr-mmjv-4gpg" && c.Fact != enrich.FactAffected {
			t.Errorf("GHSA-xxjr-mmjv-4gpg states %s about %s, but its only alias has no node", c.Fact, c.Subject)
		}
	}
}

func TestEnrichFixedBy(t *testing.T) {
	claims := enrichAll(t, start(t), stream())
	cve := assemble.VulnID("cve", theCVE)

	var got []string
	for _, c := range pick(claims, cve, enrich.FactFixedBy) {
		if c.Ref == "github_osv/GHSA-f23m-r3pf-42rh" {
			got = append(got, c.Value)
		}
	}
	want := []string{
		"pkg:npm/lodash@4.18.0", "pkg:npm/lodash-amd@4.18.0",
		"pkg:npm/lodash-es@4.18.0", "pkg:npm/lodash.unset@4.18.0",
	}
	if len(got) != len(want) {
		t.Fatalf("fixed_by = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fixed_by = %v, want %v", got, want)
		}
	}
}

func TestEnrichStampsTheClockAndNotTheJurisdiction(t *testing.T) {
	claims := enrichAll(t, start(t), stream())
	if len(claims) == 0 {
		t.Fatal("no claims")
	}
	for i, c := range claims {
		if !c.ValidFrom.Equal(now) || !c.FetchedAt.Equal(now) {
			t.Errorf("claim %d clocks = %s / %s, want both %s", i, c.ValidFrom, c.FetchedAt, now)
		}
		if c.Jurisdiction != "" {
			t.Errorf("claim %d jurisdiction = %q, want the zero value: the pipeline stamps it", i, c.Jurisdiction)
		}
		if c.Source != enrich.SourceVulnerableCode {
			t.Errorf("claim %d source = %q, want %q", i, c.Source, enrich.SourceVulnerableCode)
		}
	}
}

func TestEnrichNoPackages(t *testing.T) {
	s := start(t)
	claims := enrichAll(t, s, varve.Stream{})
	if len(claims) != 0 || len(s.purls) != 0 {
		t.Errorf("Enrich on a stream with no package = %d claims after %d requests, want 0 and 0", len(claims), len(s.purls))
	}
}

func TestEnrichStatusError(t *testing.T) {
	s := start(t)
	s.status = http.StatusServiceUnavailable
	e, err := New(s.URL, s.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims, err := e.Enrich(context.Background(), enrich.Input{Records: stream(), Now: now})
	if !errors.Is(err, ErrStatus) {
		t.Fatalf("Enrich error = %v, want errors.Is(ErrStatus)", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("Enrich error = %q, want it to name the status", err)
	}
	if len(claims) != 0 {
		t.Errorf("Enrich returned %d claims with an error, want 0", len(claims))
	}
}

func TestEnrichCancelled(t *testing.T) {
	s := start(t)
	e, err := New(s.URL, s.Client())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	claims, err := e.Enrich(ctx, enrich.Input{Records: stream(), Now: now})
	if err == nil {
		t.Fatal("Enrich on a cancelled context returned no error")
	}
	if len(claims) != 0 {
		t.Errorf("Enrich returned %d claims with an error, want 0", len(claims))
	}
}

func TestNewBadURL(t *testing.T) {
	if _, err := New("http://[::1", nil); err == nil {
		t.Fatal("New with a bad url returned no error")
	}
}
