package enrich

import (
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/varve"
)

// LabelClaim and EdgeAbout are the graph vocabulary enrichment adds.
const (
	LabelClaim varve.NodeLabel = "Claim"
	EdgeAbout  varve.EdgeLabel = "ABOUT"
)

// Claim is one fact from one source about one subject (ADR 0031).
type Claim struct {
	Source       Source
	Jurisdiction Jurisdiction
	Subject      varve.NodeID   // part of the identity
	Also         []varve.NodeID // further ABOUT targets, not part of the identity
	Fact, Value  string
	Ref          string    // an EUVD id, a scanner documentRef; "" writes no prop
	ValidFrom    time.Time // the source's date for the fact, else FetchedAt
	FetchedAt    time.Time
}

// ID derives the claim's identity from source, subject, fact and value, so a
// re-fetch of the same fact replays onto the same node.
func (c Claim) ID() varve.NodeID {
	return assemble.EvidenceID(string(LabelClaim), string(c.Source), string(c.Subject), c.Fact, c.Value)
}

// Records renders the claim as one node plus one ABOUT edge per subject.
func (c Claim) Records() varve.Stream {
	id := c.ID()
	props := keepSet([]varve.Prop{
		{Key: "source", Value: varve.Str(string(c.Source))},
		{Key: "source_jurisdiction", Value: varve.Str(string(c.Jurisdiction))},
		{Key: "fetched_at", Value: varve.Str(fmtTime(c.FetchedAt))},
		{Key: "fact", Value: varve.Str(c.Fact)},
		{Key: "value", Value: varve.Str(c.Value)},
		{Key: "ref", Value: varve.Str(c.Ref)},
		{Key: "subject_id", Value: varve.Str(string(c.Subject))},
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
		if s, ok := p.Value.(varve.Str); ok && s == "" {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// fmtTime renders a timestamp the way assemble writes every other one.
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
