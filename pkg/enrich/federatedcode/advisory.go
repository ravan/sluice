package federatedcode

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/ravan/sluice/pkg/enrich"
)

// PackageEntry is one entry of a vulnerabilities.yml file: what the repository
// states about one exact package version.
type PackageEntry struct {
	Purl       string   `yaml:"purl"`
	AffectedBy []string `yaml:"affected_by_vulnerabilities"`
	Fixing     []string `yaml:"fixing_vulnerabilities"`
}

// Advisory is one aboutcode-vulnerabilities file: what the repository states
// about one VCID.
type Advisory struct {
	VulnerabilityID string      `yaml:"vulnerability_id"`
	Aliases         []string    `yaml:"aliases"`
	Summary         string      `yaml:"summary"`
	Severities      []Severity  `yaml:"severities"`
	References      []Reference `yaml:"references"`
}

// Severity is one scored entry of an Advisory, in the field names the YAML
// uses. enrich.Severity is what the claims are written from.
type Severity struct {
	Score           string `yaml:"score"`
	ScoringSystem   string `yaml:"scoring_system"`
	ScoringElements string `yaml:"scoring_elements"`
}

// Reference is one link an Advisory carries.
type Reference struct {
	URL string `yaml:"url"`
}

// ParsePackageEntries reads a vulnerabilities.yml file.
func ParsePackageEntries(b []byte) ([]PackageEntry, error) {
	var entries []PackageEntry
	if err := yaml.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("federatedcode: package entries: %w", err)
	}
	return entries, nil
}

// ParseAdvisory reads one aboutcode-vulnerabilities file.
func ParseAdvisory(b []byte) (Advisory, error) {
	var a Advisory
	if err := yaml.Unmarshal(b, &a); err != nil {
		return Advisory{}, fmt.Errorf("federatedcode: advisory: %w", err)
	}
	return a, nil
}

// Facts is what the advisory states about the vulnerability itself, in the
// order the claims are written. An empty value is not a fact.
func (a Advisory) Facts() []enrich.FactValue {
	facts := []enrich.FactValue{
		{Fact: enrich.FactAdvisoryID, Value: a.VulnerabilityID},
		{Fact: enrich.FactDescription, Value: a.Summary},
	}
	sevs := make([]enrich.Severity, len(a.Severities))
	for i, s := range a.Severities {
		sevs[i] = enrich.Severity{System: s.ScoringSystem, Score: s.Score, Elements: s.ScoringElements}
	}
	if s, ok := enrich.CVSS(sevs); ok {
		facts = append(facts,
			enrich.FactValue{Fact: enrich.FactCVSS, Value: s.Score},
			enrich.FactValue{Fact: enrich.FactCVSSVersion, Value: s.Version()},
			enrich.FactValue{Fact: enrich.FactCVSSVector, Value: s.Elements},
		)
	}
	if s, ok := enrich.EPSS(sevs); ok {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactEPSS, Value: s.Score})
	}
	for _, r := range a.References {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactReference, Value: r.URL})
	}

	kept := make([]enrich.FactValue, 0, len(facts))
	for _, f := range facts {
		if f.Value != "" {
			kept = append(kept, f)
		}
	}
	return kept
}
