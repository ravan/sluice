package enrich

import (
	"slices"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/varve"
)

func TestDerive(t *testing.T) {
	validFrom := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	scanned := "2026-09-03T10:00:00Z"
	fetched := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)

	node := func(label varve.NodeLabel, props ...varve.Prop) varve.NodeRecord {
		return varve.NodeRecord{
			ID:        varve.NodeID("n:" + string(label)),
			Labels:    []varve.NodeLabel{label},
			Props:     props,
			ValidFrom: validFrom,
		}
	}
	str := func(k, v string) varve.Prop { return varve.Prop{Key: k, Value: varve.Str(v)} }

	certifyVuln := node(assemble.LabelCertifyVuln,
		str("subjectId", "pkg:v:a"),
		str("objectId", "vuln:cve/cve-2024-3094"),
		str("collector", "osv_certifier"),
		str("timeScanned", scanned),
		str("documentRef", "sha256:abc"),
	)
	certifyVulnClaim := Claim{
		Source:    SourceOSV,
		Subject:   "pkg:v:a",
		Also:      []varve.NodeID{"vuln:cve/cve-2024-3094"},
		Fact:      "affected",
		Value:     "vuln:cve/cve-2024-3094",
		Ref:       "sha256:abc",
		ValidFrom: validFrom,
		FetchedAt: fetched,
	}

	fileCollected := node(assemble.LabelCertifyVuln,
		str("subjectId", "pkg:v:a"),
		str("objectId", "vuln:cve/cve-2024-3094"),
		str("collector", "FileCollector"),
		str("timeScanned", scanned),
		str("documentRef", "sha256:abc"),
	)

	certifyLegal := node(assemble.LabelCertifyLegal,
		str("subjectId", "pkg:v:a"),
		str("declaredLicense", "MIT"),
		str("collector", "clearlydefined"),
		str("timeScanned", scanned),
	)
	declaredClaim := Claim{
		Source:    SourceClearlyDefined,
		Subject:   "pkg:v:a",
		Fact:      "declared_license",
		Value:     "MIT",
		ValidFrom: validFrom,
		FetchedAt: fetched,
	}
	certifyLegalBoth := node(assemble.LabelCertifyLegal,
		str("subjectId", "pkg:v:a"),
		str("declaredLicense", "MIT"),
		str("discoveredLicense", "Apache-2.0"),
		str("collector", "clearlydefined"),
		str("timeScanned", scanned),
	)
	discoveredClaim := Claim{
		Source:    SourceClearlyDefined,
		Subject:   "pkg:v:a",
		Fact:      "discovered_license",
		Value:     "Apache-2.0",
		ValidFrom: validFrom,
		FetchedAt: fetched,
	}

	eol := node(assemble.LabelHasMetadata,
		str("subjectId", "pkg:v:a"),
		str("key", "endoflife"),
		str("value", "product:x,cycle:1"),
		str("collector", "GUAC"),
		str("timestamp", scanned),
	)
	eolClaim := Claim{
		Source:    SourceEOL,
		Subject:   "pkg:v:a",
		Fact:      "endoflife",
		Value:     "product:x,cycle:1",
		ValidFrom: validFrom,
		FetchedAt: fetched,
	}
	otherMetadata := node(assemble.LabelHasMetadata,
		str("subjectId", "pkg:v:a"),
		str("key", "other"),
		str("value", "product:x,cycle:1"),
		str("collector", "GUAC"),
		str("timestamp", scanned),
	)

	scorecard := node(assemble.LabelCertifyScorecard,
		str("subjectId", "src:n:git/github.com/x/y@@c"),
		varve.Prop{Key: "aggregateScore", Value: varve.Float(7.5)},
		str("collector", "ingest_depsdev_scanner"),
		str("timeScanned", scanned),
	)
	scorecardClaim := Claim{
		Source:    SourceDepsDev,
		Subject:   "src:n:git/github.com/x/y@@c",
		Fact:      "scorecard",
		Value:     "7.5",
		ValidFrom: validFrom,
		FetchedAt: fetched,
	}

	hasSourceAt := node(assemble.LabelHasSourceAt,
		str("subjectId", "pkg:v:a"),
		str("collector", "ingest_depsdev_scanner"),
		str("timeScanned", scanned),
	)

	tests := []struct {
		name  string
		nodes []varve.NodeRecord
		want  []Claim
	}{
		{"certify vuln from the osv certifier", []varve.NodeRecord{certifyVuln}, []Claim{certifyVulnClaim}},
		{"certify vuln from a file collector", []varve.NodeRecord{fileCollected}, nil},
		{"certify legal declared only", []varve.NodeRecord{certifyLegal}, []Claim{declaredClaim}},
		{"certify legal declared and discovered", []varve.NodeRecord{certifyLegalBoth}, []Claim{declaredClaim, discoveredClaim}},
		{"has metadata endoflife", []varve.NodeRecord{eol}, []Claim{eolClaim}},
		{"has metadata other key", []varve.NodeRecord{otherMetadata}, nil},
		{"certify scorecard", []varve.NodeRecord{scorecard}, []Claim{scorecardClaim}},
		{"has source at", []varve.NodeRecord{hasSourceAt}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Derive(varve.Stream{Nodes: tt.nodes})
			want := slices.Clone(tt.want)
			slices.SortFunc(want, cmpID)
			assertClaims(t, got, want)
		})
	}

	t.Run("every node in one stream", func(t *testing.T) {
		all := varve.Stream{Nodes: []varve.NodeRecord{
			certifyVuln, fileCollected, certifyLegalBoth, eol, otherMetadata, scorecard, hasSourceAt,
		}}
		want := []Claim{certifyVulnClaim, declaredClaim, discoveredClaim, eolClaim, scorecardClaim}
		slices.SortFunc(want, cmpID)
		got := Derive(all)
		assertClaims(t, got, want)
		for i := 1; i < len(got); i++ {
			if got[i-1].ID() > got[i].ID() {
				t.Errorf("claim %d id %q sorts after %q, want the claims ordered by ID", i, got[i-1].ID(), got[i].ID())
			}
		}
	})
}

func cmpID(a, b Claim) int {
	switch {
	case a.ID() < b.ID():
		return -1
	case a.ID() > b.ID():
		return 1
	}
	return 0
}

func assertClaims(t *testing.T, got, want []Claim) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Derive() returned %d claims %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Source != w.Source || g.Subject != w.Subject {
			t.Errorf("claim %d = {%s %s}, want {%s %s}", i, g.Source, g.Subject, w.Source, w.Subject)
		}
		if !slices.Equal(g.Also, w.Also) {
			t.Errorf("claim %d Also = %v, want %v", i, g.Also, w.Also)
		}
		if g.Fact != w.Fact || g.Value != w.Value || g.Ref != w.Ref {
			t.Errorf("claim %d = fact %q value %q ref %q, want fact %q value %q ref %q", i, g.Fact, g.Value, g.Ref, w.Fact, w.Value, w.Ref)
		}
		if !g.ValidFrom.Equal(w.ValidFrom) {
			t.Errorf("claim %d ValidFrom = %v, want %v", i, g.ValidFrom, w.ValidFrom)
		}
		if !g.FetchedAt.Equal(w.FetchedAt) {
			t.Errorf("claim %d FetchedAt = %v, want %v", i, g.FetchedAt, w.FetchedAt)
		}
	}
}

func TestCleanOSVScanHasNoAffectedClaim(t *testing.T) {
	n := varve.NodeRecord{ID: "scan", Labels: []varve.NodeLabel{assemble.LabelCertifyVuln}, Props: []varve.Prop{
		{Key: assemble.PropSubjectID, Value: varve.Str("pkg:v:a")},
		{Key: assemble.PropCollector, Value: varve.Str("osv_certifier")},
		{Key: assemble.PropObjectID, Value: varve.Str(string(assemble.VulnID("NoVuln", "ignored")))},
	}}
	if got := Derive(varve.Stream{Nodes: []varve.NodeRecord{n}}); len(got) != 0 {
		t.Fatalf("clean scan produced claims: %#v", got)
	}
	n.Props[2].Value = varve.Str("vuln:osv/cve-2024-1234")
	if got := Derive(varve.Stream{Nodes: []varve.NodeRecord{n}}); len(got) != 1 || got[0].Fact != FactAffected {
		t.Fatalf("real finding lost: %#v", got)
	}
}
