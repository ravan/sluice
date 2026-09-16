// Package scanner reads what a scan document states about the vulnerabilities
// it found, and returns those statements as enrich.Claim records. It calls no
// host: the scanner already asked the databases, and the document carries what
// they said.
//
// Today it reads the cosign vulnerability attestation, whose predicate holds a
// whole Trivy report. The parser in pkg/guacseam/cosignvuln turns that report
// into graph nodes, but GUAC's vocabulary has nowhere to put a vulnerability's
// description, and its VulnMetadata keeps a score without the vector or the
// database that gave it. Every one of those facts is in the document, so this
// states them instead of letting them go.
//
// Each claim's Ref names the database the scanner credited — "ghsa", "nvd",
// "redhat" — so two databases that disagree about a score are two claims, and
// the reader can see which said which.
package scanner

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// PredicateType is the in-toto predicateType this reads, the same statement
// pkg/guacseam/cosignvuln parses into nodes.
const PredicateType = "https://cosign.sigstore.dev/attestation/vuln/v1"

// statementPrefix is shared by every in-toto statement version.
const statementPrefix = "https://in-toto.io/Statement"

// Enricher is the scanner source as the pipeline sees it.
type Enricher struct{}

// New builds the Enricher. It has nothing to configure.
func New() *Enricher { return &Enricher{} }

// Source names this enricher.
func (e *Enricher) Source() enrich.Source { return enrich.SourceScanner }

// statement is the part of the attestation this reads.
type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Scanner struct {
			Result report `json:"result"`
		} `json:"scanner"`
		Metadata struct {
			ScanStartedOn  string `json:"scanStartedOn"`
			ScanFinishedOn string `json:"scanFinishedOn"`
		} `json:"metadata"`
	} `json:"predicate"`
}

// report is the Trivy JSON report inside scanner.result.
type report struct {
	CreatedAt string   `json:"CreatedAt"`
	Results   []result `json:"Results"`
}

// result is one scanned target: the OS package set or one binary.
type result struct {
	Vulnerabilities []finding `json:"Vulnerabilities"`
}

// finding is the part of one Trivy DetectedVulnerability this states.
type finding struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	FixedVersion     string          `json:"FixedVersion"`
	PrimaryURL       string          `json:"PrimaryURL"`
	References       []string        `json:"References"`
	PublishedDate    string          `json:"PublishedDate"`
	LastModifiedDate string          `json:"LastModifiedDate"`
	CVSS             map[string]cvss `json:"CVSS"`
	DataSource       struct {
		ID string `json:"ID"`
	} `json:"DataSource"`
}

// cvss is one database's scores for a finding.
type cvss struct {
	V2Vector  string  `json:"V2Vector"`
	V3Vector  string  `json:"V3Vector"`
	V40Vector string  `json:"V40Vector"`
	V2Score   float64 `json:"V2Score"`
	V3Score   float64 `json:"V3Score"`
	V40Score  float64 `json:"V40Score"`
}

// Enrich states what the document says about every vulnerability the stream
// already carries a node for. A document that is not a scan attestation, or
// that is not JSON at all, states nothing and is not an error: every enricher
// sees every document.
func (e *Enricher) Enrich(_ context.Context, in enrich.Input) ([]enrich.Claim, error) {
	st, ok := decode(in.Document)
	if !ok {
		return nil, nil
	}
	nodes := enrich.VulnNodes(in.Records)
	fetched := scanTime(st)
	if fetched.IsZero() {
		fetched = in.Now
	}

	var out []enrich.Claim
	seen := map[string]bool{}
	for _, r := range st.Predicate.Scanner.Result.Results {
		for _, f := range r.Vulnerabilities {
			subject, ok := nodes[strings.ToLower(strings.TrimSpace(f.VulnerabilityID))]
			if !ok {
				// The stream carries no node for it, so an ABOUT edge would
				// dangle. The parser writes a node for every finding it could
				// make a package of, so this is the one it could not.
				continue
			}
			for _, c := range claimsFor(subject, f, fetched) {
				// One CVE is found in many of a document's targets, and the
				// scan repeats the whole record each time. The claim id would
				// fold them anyway; this keeps the returned list honest.
				key := string(c.Subject) + "\x00" + string(c.Fact) + "\x00" + c.Value
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// decode reads the statement, reporting whether the bytes are one of ours.
func decode(blob []byte) (*statement, bool) {
	var st statement
	if json.Unmarshal(blob, &st) != nil {
		return nil, false
	}
	if !strings.HasPrefix(st.Type, statementPrefix) || st.PredicateType != PredicateType {
		return nil, false
	}
	return &st, true
}

// scanTime is when the scanner ran, which is when it fetched these facts.
func scanTime(st *statement) time.Time {
	for _, s := range []string{
		st.Predicate.Metadata.ScanFinishedOn,
		st.Predicate.Metadata.ScanStartedOn,
		st.Predicate.Scanner.Result.CreatedAt,
	} {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// refFact is one fact paired with the database that stated it.
type refFact struct {
	fact  enrich.Fact
	value string
	ref   string
}

// claimsFor renders one finding. The order is fixed so two runs over the same
// document return the same list.
func claimsFor(subject varve.NodeID, f finding, fetched time.Time) []enrich.Claim {
	db := f.DataSource.ID
	var facts []refFact

	// Trivy's Title is the one-line summary and its Description is the
	// advisory in full. The description fact takes the summary when there is
	// one: it is what a reader wants under the name, and the full text is a
	// click away through the references.
	if d := strings.TrimSpace(f.Title); d != "" {
		facts = append(facts, refFact{enrich.FactDescription, d, db})
	} else if d := strings.TrimSpace(f.Description); d != "" {
		facts = append(facts, refFact{enrich.FactDescription, d, db})
	}

	for _, name := range sortedKeys(f.CVSS) {
		facts = append(facts, scoreFacts(name, f.CVSS[name])...)
	}

	if t, ok := parseDate(f.PublishedDate); ok {
		facts = append(facts, refFact{enrich.FactPublished, t.Format(time.RFC3339), db})
	}
	if t, ok := parseDate(f.LastModifiedDate); ok {
		facts = append(facts, refFact{enrich.FactUpdated, t.Format(time.RFC3339), db})
	}
	if v := strings.TrimSpace(f.FixedVersion); v != "" {
		facts = append(facts, refFact{enrich.FactFixedBy, v, db})
	}
	for _, url := range append([]string{f.PrimaryURL}, f.References...) {
		if url = strings.TrimSpace(url); url != "" {
			facts = append(facts, refFact{enrich.FactReference, url, db})
		}
	}

	validFrom := validFrom(f, fetched)
	claims := make([]enrich.Claim, 0, len(facts))
	for _, rf := range facts {
		claims = append(claims, enrich.Claim{
			Source:    enrich.SourceScanner,
			Subject:   subject,
			Fact:      rf.fact,
			Value:     rf.value,
			Ref:       rf.ref,
			ValidFrom: validFrom,
			FetchedAt: fetched,
		})
	}
	return claims
}

// validFrom is the date the advisory itself carries, and the scan time only
// when it carries none: a score published in 2020 was true in 2020, whatever
// day the image was built.
func validFrom(f finding, fetched time.Time) time.Time {
	for _, s := range []string{f.LastModifiedDate, f.PublishedDate} {
		if t, ok := parseDate(s); ok {
			return t
		}
	}
	return fetched
}

// parseDate reads one Trivy date as UTC. Trivy writes RFC 3339.
func parseDate(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// scoreFacts renders one database's scores: the newest scoring version it gave
// wins, because cvss is one fact and a reader comparing two databases wants
// them speaking the same version where they can.
func scoreFacts(db string, c cvss) []refFact {
	for _, v := range []struct {
		score   float64
		vector  string
		version string
	}{
		{c.V40Score, c.V40Vector, "4.0"},
		{c.V3Score, c.V3Vector, cvss3Version(c.V3Vector)},
		{c.V2Score, c.V2Vector, "2.0"},
	} {
		// Trivy leaves a score it has no value for at zero rather than
		// omitting the field, and 0.0 is itself a CVSS score meaning "no
		// impact". The two are indistinguishable here, so a zero is read as
		// absent: claiming a score no database gave is the worse mistake.
		if v.score <= 0 {
			continue
		}
		out := []refFact{{enrich.FactCVSS, strconv.FormatFloat(v.score, 'f', -1, 64), db}}
		if v.version != "" {
			out = append(out, refFact{enrich.FactCVSSVersion, v.version, db})
		}
		if v.vector != "" {
			out = append(out, refFact{enrich.FactCVSSVector, v.vector, db})
		}
		return out
	}
	return nil
}

// cvss3Version tells CVSS 3.1 from 3.0 by the vector prefix.
func cvss3Version(vector string) string {
	if strings.HasPrefix(vector, "CVSS:3.0/") {
		return "3.0"
	}
	return "3.1"
}

// sortedKeys names the databases in a stable order.
func sortedKeys(m map[string]cvss) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
