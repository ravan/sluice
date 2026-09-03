package enrich

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/varve"
)

func TestClaimID(t *testing.T) {
	base := Claim{
		Source:    SourceEUVD,
		Subject:   "vuln:cve/cve-2026-12345",
		Fact:      "cvss",
		Value:     "8.1",
		FetchedAt: time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC),
	}
	other := base
	other.FetchedAt = time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	other.Ref = "EUVD-2026-10001"
	other.Also = []varve.NodeID{"pkg:v:a"}

	if base.ID() != other.ID() {
		t.Errorf("ID() = %q and %q, want the two equal", base.ID(), other.ID())
	}
	if !strings.HasPrefix(string(base.ID()), "Claim:") {
		t.Errorf("ID() = %q, want the prefix %q", base.ID(), "Claim:")
	}
	changed := base
	changed.Value = "9.8"
	if changed.ID() == base.ID() {
		t.Errorf("ID() = %q for both values, want a different id per value", base.ID())
	}
}

func TestClaimRecords(t *testing.T) {
	validFrom := time.Date(2026, 9, 2, 18, 30, 0, 0, time.UTC)
	c := Claim{
		Source:       SourceEUVD,
		Jurisdiction: EU,
		Subject:      "vuln:cve/cve-2026-12345",
		Also:         []varve.NodeID{"pkg:v:a"},
		Fact:         "cvss",
		Value:        "8.1",
		Ref:          "EUVD-2026-10001",
		ValidFrom:    validFrom,
		FetchedAt:    time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC),
	}

	s := c.Records()
	if len(s.Nodes) != 1 {
		t.Fatalf("Records() has %d nodes, want 1", len(s.Nodes))
	}
	n := s.Nodes[0]
	if len(n.Labels) != 1 || n.Labels[0] != LabelClaim {
		t.Errorf("node labels = %v, want [%s]", n.Labels, LabelClaim)
	}
	if n.ID != c.ID() {
		t.Errorf("node id = %q, want %q", n.ID, c.ID())
	}
	if !n.ValidFrom.Equal(validFrom) {
		t.Errorf("node ValidFrom = %v, want %v", n.ValidFrom, validFrom)
	}
	want := map[string]string{
		"source":              "euvd",
		"source_jurisdiction": "eu",
		"fetched_at":          "2026-09-03T10:00:00Z",
		"fact":                "cvss",
		"value":               "8.1",
		"ref":                 "EUVD-2026-10001",
		"subject_id":          "vuln:cve/cve-2026-12345",
	}
	got := propMap(t, n.Props)
	if len(got) != len(want) {
		t.Fatalf("props = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("prop %q = %q, want %q", k, got[k], v)
		}
	}

	if len(s.Edges) != 2 {
		t.Fatalf("Records() has %d edges, want 2", len(s.Edges))
	}
	for i, dst := range []varve.NodeID{c.Subject, "pkg:v:a"} {
		e := s.Edges[i]
		if e.Label != EdgeAbout || e.Src != c.ID() || e.Dst != dst {
			t.Errorf("edge %d = %s -[%s]-> %s, want %s -[%s]-> %s", i, e.Src, e.Label, e.Dst, c.ID(), EdgeAbout, dst)
		}
		if e.ID != assemble.EdgeIDFor(c.ID(), EdgeAbout, dst) {
			t.Errorf("edge %d id = %q, want %q", i, e.ID, assemble.EdgeIDFor(c.ID(), EdgeAbout, dst))
		}
		if !e.ValidFrom.Equal(validFrom) {
			t.Errorf("edge %d ValidFrom = %v, want %v", i, e.ValidFrom, validFrom)
		}
	}

	c.Ref = ""
	if _, ok := propMap(t, c.Records().Nodes[0].Props)["ref"]; ok {
		t.Errorf("props hold a ref key for an empty Ref, want it omitted")
	}
}

func propMap(t *testing.T, props []varve.Prop) map[string]string {
	t.Helper()
	m := make(map[string]string, len(props))
	for _, p := range props {
		s, ok := p.Value.(varve.Str)
		if !ok {
			t.Fatalf("prop %q value = %#v, want a varve.Str", p.Key, p.Value)
		}
		m[p.Key] = string(s)
	}
	return m
}

func TestParseFact(t *testing.T) {
	cases := []struct {
		name    string
		want    Fact
		wantErr bool
	}{
		{name: "cvss", want: FactCVSS},
		{name: "advisory_id", want: FactAdvisoryID},
		{name: "fixed_by", want: FactFixedBy},
		{name: "severity", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFact(tc.name)
			if tc.wantErr {
				if !errors.Is(err, ErrUnknownFact) {
					t.Fatalf("ParseFact(%q) error = %v, want errors.Is(ErrUnknownFact)", tc.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFact(%q): %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("ParseFact(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
