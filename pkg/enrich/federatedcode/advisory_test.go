package federatedcode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/sluice/pkg/enrich"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "federatedcode", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestParsePackageEntries(t *testing.T) {
	entries, err := ParsePackageEntries(fixture(t, "vulnerabilities-npm-lodash.yml"))
	if err != nil {
		t.Fatalf("ParsePackageEntries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	first := entries[0]
	if first.Purl != "pkg:npm/lodash@0.1.0" {
		t.Errorf("purl = %q, want pkg:npm/lodash@0.1.0", first.Purl)
	}
	if len(first.AffectedBy) != 8 {
		t.Errorf("affected_by = %d, want 8", len(first.AffectedBy))
	}
	if first.AffectedBy[0] != "VCID-4wn8-fck1-aaaq" {
		t.Errorf("affected_by[0] = %q, want VCID-4wn8-fck1-aaaq", first.AffectedBy[0])
	}
	if len(first.Fixing) != 0 {
		t.Errorf("fixing = %v, want empty", first.Fixing)
	}
}

func TestParseAdvisory(t *testing.T) {
	a, err := ParseAdvisory(fixture(t, "VCID-4wn8-fck1-aaaq.yml"))
	if err != nil {
		t.Fatalf("ParseAdvisory: %v", err)
	}
	if a.VulnerabilityID != "VCID-4wn8-fck1-aaaq" {
		t.Errorf("vulnerability_id = %q", a.VulnerabilityID)
	}
	want := []string{"CVE-2018-3721", "GHSA-fvqr-27wr-82fm"}
	if len(a.Aliases) != len(want) {
		t.Fatalf("aliases = %v, want %v", a.Aliases, want)
	}
	for i, w := range want {
		if a.Aliases[i] != w {
			t.Errorf("aliases[%d] = %q, want %q", i, a.Aliases[i], w)
		}
	}
	if !strings.HasPrefix(a.Summary, "lodash node module suffers") {
		t.Errorf("summary = %q", a.Summary)
	}
	if len(a.Severities) != 4 {
		t.Fatalf("severities = %d, want 4", len(a.Severities))
	}
	if got := a.Severities[2]; got.ScoringSystem != "cvssv3" || got.Score != "2.9" {
		t.Errorf("severities[2] = %+v, want cvssv3 2.9", got)
	}
	if len(a.References) != 3 {
		t.Fatalf("references = %d, want 3", len(a.References))
	}
	const firstRef = "http://people.canonical.com/~ubuntu-security/cve/2018/CVE-2018-3721.html"
	if a.References[0].URL != firstRef {
		t.Errorf("references[0] = %q, want %q", a.References[0].URL, firstRef)
	}
}

func TestAdvisoryFacts(t *testing.T) {
	a, err := ParseAdvisory(fixture(t, "VCID-4wn8-fck1-aaaq.yml"))
	if err != nil {
		t.Fatalf("ParseAdvisory: %v", err)
	}
	facts := a.Facts()
	want := []enrich.FactValue{
		{Fact: enrich.FactAdvisoryID, Value: "VCID-4wn8-fck1-aaaq"},
		{Fact: enrich.FactDescription, Value: a.Summary},
		{Fact: enrich.FactCVSS, Value: "2.9"},
		{Fact: enrich.FactCVSSVersion, Value: "3"},
		{Fact: enrich.FactCVSSVector, Value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"},
		{Fact: enrich.FactEPSS, Value: "0.00103"},
	}
	for _, r := range a.References {
		want = append(want, enrich.FactValue{Fact: enrich.FactReference, Value: r.URL})
	}
	if len(facts) != len(want) {
		t.Fatalf("facts = %d, want %d: %+v", len(facts), len(want), facts)
	}
	for i, w := range want {
		if facts[i] != w {
			t.Errorf("facts[%d] = %+v, want %+v", i, facts[i], w)
		}
	}
	if !strings.HasPrefix(facts[1].Value, "lodash node module suffers") {
		t.Errorf("description = %q", facts[1].Value)
	}
}

func TestAdvisoryFactsNoScores(t *testing.T) {
	a := Advisory{
		VulnerabilityID: "VCID-1111-2222-3333",
		Summary:         "a summary",
		Severities:      []Severity{{Score: "Medium", ScoringSystem: "generic_textual"}},
	}
	for _, f := range a.Facts() {
		switch f.Fact {
		case enrich.FactCVSS, enrich.FactCVSSVersion, enrich.FactCVSSVector, enrich.FactEPSS:
			t.Errorf("unwanted fact %+v", f)
		}
	}
}
