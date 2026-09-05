package enrich

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/varve"
)

// LabelClaim and EdgeAbout are the graph vocabulary enrichment adds.
const (
	LabelClaim varve.NodeLabel = "Claim"
	EdgeAbout  varve.EdgeLabel = "ABOUT"
)

// The property-key vocabulary of a Claim node, the counterpart to assemble's
// prop constants: a consumer querying enrichment filters on these names.
const (
	PropSource             = "source"
	PropSourceJurisdiction = "source_jurisdiction"
	PropFetchedAt          = "fetched_at"
	PropFact               = "fact"
	PropValue              = "value"
	PropRef                = "ref"
	PropSubjectID          = "subject_id"
)

// Fact names what a claim states about its subject. It is part of the claim's
// identity, so an unlisted name would silently mint a second node rather than
// replay onto the existing one (ADR 0031).
type Fact string

// Facts derived from a document's own scanner evidence.
const (
	FactAffected          Fact = "affected"
	FactDeclaredLicense   Fact = "declared_license"
	FactDiscoveredLicense Fact = "discovered_license"
	FactEndOfLife         Fact = "endoflife"
	FactScorecard         Fact = "scorecard"
)

// Facts an external vulnerability source states about a vulnerability.
const (
	FactEUVDID      Fact = "euvd_id"
	FactCVSS        Fact = "cvss"
	FactCVSSVersion Fact = "cvss_version"
	FactCVSSVector  Fact = "cvss_vector"
	FactEPSS        Fact = "epss"
	FactDescription Fact = "description"
	FactPublished   Fact = "published"
	FactUpdated     Fact = "updated"
	FactReference   Fact = "reference"
	FactAdvisoryID  Fact = "advisory_id"
	FactFixedBy     Fact = "fixed_by"
)

// FactValue is one fact paired with the value a source states for it. An
// enricher builds these before it knows the subject they hang off.
type FactValue struct {
	Fact  Fact
	Value string
}

// Facts is the allow-list ParseFact checks a wire name against.
var Facts = []Fact{
	FactAffected, FactDeclaredLicense, FactDiscoveredLicense, FactEndOfLife, FactScorecard,
	FactEUVDID, FactCVSS, FactCVSSVersion, FactCVSSVector, FactEPSS,
	FactDescription, FactPublished, FactUpdated, FactReference,
	FactAdvisoryID, FactFixedBy,
}

// ErrUnknownFact is returned when a name falls outside Facts.
var ErrUnknownFact = errors.New("enrich: unknown fact")

// ParseFact validates a fact name read back off the wire or out of config.
func ParseFact(name string) (Fact, error) {
	f := Fact(name)
	if !slices.Contains(Facts, f) {
		return "", fmt.Errorf("%w: %q", ErrUnknownFact, name)
	}
	return f, nil
}

// Claim is one fact from one source about one subject (ADR 0031). It names no
// jurisdiction: where a source's host sits is the install's answer, not the
// enricher's, so a Claim reaches the graph only through Policy.Stamp.
type Claim struct {
	Source    Source
	Subject   varve.NodeID   // part of the identity
	Also      []varve.NodeID // further ABOUT targets, not part of the identity
	Fact      Fact
	Value     string
	Ref       string    // an EUVD id, a scanner documentRef; "" writes no prop
	ValidFrom time.Time // the source's date for the fact, else FetchedAt
	FetchedAt time.Time
}

// StampedClaim is a Claim the policy has placed in a jurisdiction. Policy.Stamp
// is the only way to build one, and it is the only form that renders records.
type StampedClaim struct {
	Claim
	jurisdiction Jurisdiction
}

// Jurisdiction is where the policy says this claim's source sits.
func (c StampedClaim) Jurisdiction() Jurisdiction { return c.jurisdiction }

// ID derives the claim's identity from source, subject, fact and value, so a
// re-fetch of the same fact replays onto the same node.
func (c Claim) ID() varve.NodeID {
	return assemble.EvidenceID(LabelClaim, string(c.Source), string(c.Subject), string(c.Fact), c.Value)
}

// Records renders the claim as one node plus one ABOUT edge per subject.
func (c StampedClaim) Records() varve.Stream {
	id := c.ID()
	props := keepSet([]varve.Prop{
		{Key: PropSource, Value: varve.Str(string(c.Source))},
		{Key: PropSourceJurisdiction, Value: varve.Str(string(c.jurisdiction))},
		{Key: PropFetchedAt, Value: varve.Str(fmtTime(c.FetchedAt))},
		{Key: PropFact, Value: varve.Str(string(c.Fact))},
		{Key: PropValue, Value: varve.Str(c.Value)},
		{Key: PropRef, Value: varve.Str(c.Ref)},
		{Key: PropSubjectID, Value: varve.Str(string(c.Subject))},
	})
	s := varve.Stream{Nodes: []varve.NodeRecord{{
		ID:        id,
		Labels:    []varve.NodeLabel{LabelClaim},
		Props:     props,
		ValidFrom: c.ValidFrom,
	}}}
	for _, dst := range append([]varve.NodeID{c.Subject}, c.Also...) {
		if dst == "" {
			continue
		}
		s.Edges = append(s.Edges, varve.EdgeRecord{
			ID:        assemble.EdgeIDFor(id, EdgeAbout, dst),
			Label:     EdgeAbout,
			Src:       id,
			Dst:       dst,
			ValidFrom: c.ValidFrom,
		})
	}
	return s
}

// keepSet drops empty-string props, as assemble does for every other node.
func keepSet(props []varve.Prop) []varve.Prop {
	kept := make([]varve.Prop, 0, len(props))
	for _, p := range props {
		if s, ok := p.Value.AsString(); ok && s == "" {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// fmtTime renders a timestamp the way assemble writes every other one.
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
