package federatedcode

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/ravan/sluice/pkg/enrich"
)

// PackageEntry is one entry of a vulnerabilities.yml file: what the repository
// states about one exact package version. Advisory is one
// aboutcode-vulnerabilities file, Severity one of its scored entries.
type PackageEntry struct {
	Purl       string   `yaml:"purl"`
	AffectedBy []string `yaml:"affected_by_vulnerabilities"`
	Fixing     []string `yaml:"fixing_vulnerabilities"`
}

type Advisory struct {
	VulnerabilityID string      `yaml:"vulnerability_id"`
	Aliases         []string    `yaml:"aliases"`
	Summary         string      `yaml:"summary"`
	Severities      []Severity  `yaml:"severities"`
	References      []Reference `yaml:"references"`
}

type Severity struct {
	Score           string `yaml:"score"`
	ScoringSystem   string `yaml:"scoring_system"`
	ScoringElements string `yaml:"scoring_elements"`
}

type Reference struct {
	URL string `yaml:"url"`
}

func ParsePackageEntries(b []byte) ([]PackageEntry, error) {
	var entries []PackageEntry
	if err := yaml.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("federatedcode: package entries: %w", err)
	}
	return entries, nil
}

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
