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
		name       string
		sources    []string
		euOnly     bool
		hosted     map[Source]Jurisdiction
		want       Policy
		wantErr    bool
		unknown    bool
		unknownJur bool
		contains   string
	}{
		{name: "two known sources", sources: []string{"euvd", "osv"}, want: Policy{Sources: []Source{SourceEUVD, SourceOSV}}},
		{name: "unknown source", sources: []string{"nvd"}, wantErr: true, unknown: true, contains: "nvd"},
		{name: "duplicate source", sources: []string{"osv", "osv"}, wantErr: true},
		{name: "nil sources eu only", sources: nil, euOnly: true, want: Policy{EUOnly: true}},
		{
			name: "hosted names a listed source", sources: []string{"vulnerablecode"},
			hosted: map[Source]Jurisdiction{SourceVulnerableCode: EU},
			want:   Policy{Sources: []Source{SourceVulnerableCode}, Hosted: map[Source]Jurisdiction{SourceVulnerableCode: EU}},
		},
		{
			name: "hosted names a source outside Sources", sources: []string{"euvd"},
			hosted: map[Source]Jurisdiction{Source("nvd"): EU},
			// A source hosted but not listed is a typo, not a silent no-op.
			wantErr: true, unknown: true, contains: "nvd",
		},
		{
			name: "hosted names an unknown jurisdiction", sources: []string{"vulnerablecode"},
			hosted:  map[Source]Jurisdiction{SourceVulnerableCode: Jurisdiction("moon")},
			wantErr: true, unknownJur: true, contains: "moon",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePolicy(tc.sources, tc.euOnly, tc.hosted)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePolicy(%v) error = nil, want an error", tc.sources)
				}
				if tc.unknown && !errors.Is(err, ErrUnknownSource) {
					t.Errorf("ParsePolicy error = %v, want errors.Is(ErrUnknownSource)", err)
				}
				if tc.unknownJur && !errors.Is(err, ErrUnknownJurisdiction) {
					t.Errorf("ParsePolicy error = %v, want errors.Is(ErrUnknownJurisdiction)", err)
				}
				if tc.unknownJur && !strings.Contains(err.Error(), string(SourceVulnerableCode)) {
					t.Errorf("ParsePolicy error = %q, want it to name the source", err)
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
			for s, j := range tc.want.Hosted {
				if got.JurisdictionOf(s) != j {
					t.Errorf("JurisdictionOf(%q) = %q, want %q", s, got.JurisdictionOf(s), j)
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
		{
			"eu only drops a hosted us source",
			Policy{Sources: []Source{SourceVulnerableCode}, EUOnly: true, Hosted: map[Source]Jurisdiction{SourceVulnerableCode: US}},
			SourceVulnerableCode, false,
		},
		{
			"eu only keeps a hosted eu source",
			Policy{Sources: []Source{SourceVulnerableCode}, EUOnly: true, Hosted: map[Source]Jurisdiction{SourceVulnerableCode: EU}},
			SourceVulnerableCode, true,
		},
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

func TestJurisdictionOf(t *testing.T) {
	p := Policy{Hosted: map[Source]Jurisdiction{SourceVulnerableCode: EU, SourceOSV: EU}}
	cases := []struct {
		source Source
		want   Jurisdiction
	}{
		{SourceVulnerableCode, EU},
		{SourceOSV, EU}, // Hosted wins over the package table
		{SourceEUVD, EU},
		{SourceEOL, US},
		{Source("nvd"), Other},
	}
	for _, tc := range cases {
		t.Run(string(tc.source), func(t *testing.T) {
			if got := p.JurisdictionOf(tc.source); got != tc.want {
				t.Errorf("JurisdictionOf(%q) = %q, want %q", tc.source, got, tc.want)
			}
		})
	}
	if got := (Policy{}).JurisdictionOf(SourceVulnerableCode); got != Other {
		t.Errorf("JurisdictionOf(vulnerablecode) with no Hosted = %q, want %q", got, Other)
	}
}

func TestStamp(t *testing.T) {
	p := Policy{Hosted: map[Source]Jurisdiction{SourceVulnerableCode: EU}}
	claims := []Claim{
		{Source: SourceEUVD},
		{Source: SourceOSV},
		{Source: SourceVulnerableCode},
	}
	want := []Jurisdiction{EU, US, EU}
	got := p.Stamp(claims)
	if len(got) != len(want) {
		t.Fatalf("Stamp() returned %d claims, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Jurisdiction() != w {
			t.Errorf("claim %d jurisdiction = %q, want %q", i, got[i].Jurisdiction(), w)
		}
	}
}

func TestParseJurisdiction(t *testing.T) {
	cases := []struct {
		name    string
		want    Jurisdiction
		wantErr bool
	}{
		{name: "eu", want: EU},
		{name: "us", want: US},
		{name: "other", want: Other},
		{name: "moon", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseJurisdiction(tc.name)
			if tc.wantErr {
				if !errors.Is(err, ErrUnknownJurisdiction) {
					t.Fatalf("ParseJurisdiction(%q) error = %v, want errors.Is(ErrUnknownJurisdiction)", tc.name, err)
				}
				if !strings.Contains(err.Error(), tc.name) {
					t.Errorf("ParseJurisdiction error = %q, want it to name %q", err, tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseJurisdiction(%q): %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("ParseJurisdiction(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestVulnNodes(t *testing.T) {
	cve := vulnNode("cve", "CVE-2026-12345")
	ghsa := vulnNode("ghsa", "GHSA-aaaa-bbbb-cccc")
	s := varve.Stream{Nodes: []varve.NodeRecord{cve, ghsa, pkgNode("pkg:npm/lodash@4.17.21"), vulnNode("cve", "")}}

	got := VulnNodes(s)
	want := map[string]varve.NodeID{
		"cve-2026-12345":      cve.ID,
		"ghsa-aaaa-bbbb-cccc": ghsa.ID,
	}
	if len(got) != len(want) {
		t.Fatalf("VulnNodes() = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("VulnNodes()[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestPkgPurls(t *testing.T) {
	s := varve.Stream{Nodes: []varve.NodeRecord{
		pkgNode("pkg:npm/lodash@4.17.21"),
		pkgNode("pkg:npm/express@4.19.2"),
		pkgNode("pkg:npm/lodash@4.17.21"),
		{ID: "pv:none", Labels: []varve.NodeLabel{assemble.LabelPkgVersion}},
		{ID: "pn:lodash", Labels: []varve.NodeLabel{assemble.LabelPkgName}, Props: []varve.Prop{
			{Key: assemble.PropPurl, Value: varve.Str("pkg:npm/lodash")},
		}},
	}}
	want := []string{"pkg:npm/express@4.19.2", "pkg:npm/lodash@4.17.21"}
	got := PkgPurls(s)
	if len(got) != len(want) {
		t.Fatalf("PkgPurls() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PkgPurls() = %v, want %v", got, want)
		}
	}
}

func pkgNode(purl string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:     varve.NodeID("pv:" + purl),
		Labels: []varve.NodeLabel{assemble.LabelPkgVersion},
		Props:  []varve.Prop{{Key: assemble.PropPurl, Value: varve.Str(purl)}},
	}
}
