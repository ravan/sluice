package enrich

import (
	"errors"
	"strings"
	"testing"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/varve"
)

func TestParsePolicy(t *testing.T) {
	cases := []struct {
		name     string
		sources  []string
		euOnly   bool
		want     Policy
		wantErr  bool
		unknown  bool
		contains string
	}{
		{name: "two known sources", sources: []string{"euvd", "osv"}, want: Policy{Sources: []Source{SourceEUVD, SourceOSV}}},
		{name: "unknown source", sources: []string{"nvd"}, wantErr: true, unknown: true, contains: "nvd"},
		{name: "duplicate source", sources: []string{"osv", "osv"}, wantErr: true},
		{name: "nil sources eu only", sources: nil, euOnly: true, want: Policy{EUOnly: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePolicy(tc.sources, tc.euOnly)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePolicy(%v) error = nil, want an error", tc.sources)
				}
				if tc.unknown && !errors.Is(err, ErrUnknownSource) {
					t.Errorf("ParsePolicy error = %v, want errors.Is(ErrUnknownSource)", err)
				}
				if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
					t.Errorf("ParsePolicy error = %q, want it to contain %q", err, tc.contains)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePolicy(%v): %v", tc.sources, err)
			}
			if got.EUOnly != tc.want.EUOnly || len(got.Sources) != len(tc.want.Sources) {
				t.Fatalf("ParsePolicy(%v) = %+v, want %+v", tc.sources, got, tc.want)
			}
			for i, s := range tc.want.Sources {
				if got.Sources[i] != s {
					t.Fatalf("ParsePolicy(%v) = %+v, want %+v", tc.sources, got, tc.want)
				}
			}
		})
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		source Source
		want   bool
	}{
		{"listed euvd", Policy{Sources: []Source{SourceEUVD, SourceOSV}}, SourceEUVD, true},
		{"listed osv", Policy{Sources: []Source{SourceEUVD, SourceOSV}}, SourceOSV, true},
		{"unlisted eol", Policy{Sources: []Source{SourceEUVD, SourceOSV}}, SourceEOL, false},
		{"eu only keeps euvd", Policy{Sources: []Source{SourceEUVD, SourceOSV}, EUOnly: true}, SourceEUVD, true},
		{"eu only drops osv", Policy{Sources: []Source{SourceEUVD, SourceOSV}, EUOnly: true}, SourceOSV, false},
		{"eu only drops a source with no jurisdiction", Policy{Sources: []Source{SourceVulnerableCode}, EUOnly: true}, SourceVulnerableCode, false},
		{"no cap keeps a source with no jurisdiction", Policy{Sources: []Source{SourceVulnerableCode}}, SourceVulnerableCode, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Allows(tc.source); got != tc.want {
				t.Errorf("Allows(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

func TestScanFlags(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		want   guacseam.ScanFlags
	}{
		{"osv and eol", Policy{Sources: []Source{SourceOSV, SourceEOL}}, guacseam.ScanFlags{Vulns: true, EOL: true}},
		{"eu only silences every scanner", Policy{Sources: []Source{SourceOSV, SourceEOL}, EUOnly: true}, guacseam.ScanFlags{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.ScanFlags(); got != tc.want {
				t.Errorf("ScanFlags() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestVulnNames(t *testing.T) {
	s := varve.Stream{Nodes: []varve.NodeRecord{
		vulnNode("cve", "cve-2026-12345"),
		vulnNode("cve", "cve-2026-12345"),
		vulnNode("ghsa", "ghsa-x"),
		vulnNode("euvd", "euvd-2026-10001"),
		vulnNode("novuln", ""),
	}}
	want := []string{"cve-2026-12345", "euvd-2026-10001"}
	got := VulnNames(s)
	if len(got) != len(want) {
		t.Fatalf("VulnNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("VulnNames() = %v, want %v", got, want)
		}
	}
}

func vulnNode(typ, id string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:     assemble.VulnID(typ, id),
		Labels: []varve.NodeLabel{assemble.LabelVulnerability},
		Props: []varve.Prop{
			{Key: "type", Value: varve.Str(typ)},
			{Key: "vulnID", Value: varve.Str(id)},
		},
	}
}
