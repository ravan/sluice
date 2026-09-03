package enrich

import (
	"slices"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/varve"
)

// scannerKey identifies a scanner by the node label it writes and the
// collector it stamps on that node.
type scannerKey struct {
	label     varve.NodeLabel
	collector string
}

// scanner is how one scanner's evidence node reads as claims.
type scanner struct {
	source  Source
	timeKey string
	extract func(props []varve.Prop) ([]FactValue, []varve.NodeID)
}

// scanners is the (label, collector) table of plan D5.
var scanners = map[scannerKey]scanner{
	{assemble.LabelCertifyVuln, "osv_certifier"}:               {SourceOSV, assemble.PropTimeScanned, vulnFacts},
	{assemble.LabelCertifyLegal, "clearlydefined"}:             {SourceClearlyDefined, assemble.PropTimeScanned, legalFacts},
	{assemble.LabelHasMetadata, "GUAC"}:                        {SourceEOL, assemble.PropTimestamp, eolFacts},
	{assemble.LabelCertifyScorecard, "ingest_depsdev_scanner"}: {SourceDepsDev, assemble.PropTimeScanned, scorecardFacts},
}

func vulnFacts(props []varve.Prop) ([]FactValue, []varve.NodeID) {
	object, ok := propStr(props, assemble.PropObjectID)
	if !ok || object == "" {
		return nil, nil
	}
	return []FactValue{{FactAffected, object}}, []varve.NodeID{varve.NodeID(object)}
}

func legalFacts(props []varve.Prop) ([]FactValue, []varve.NodeID) {
	var facts []FactValue
	for _, pair := range []struct {
		key  string
		fact Fact
	}{
		{assemble.PropDeclaredLicense, FactDeclaredLicense},
		{assemble.PropDiscoveredLicense, FactDiscoveredLicense},
	} {
		if v, ok := propStr(props, pair.key); ok && v != "" {
			facts = append(facts, FactValue{pair.fact, v})
		}
	}
	return facts, nil
}

func eolFacts(props []varve.Prop) ([]FactValue, []varve.NodeID) {
	if key, _ := propStr(props, assemble.PropKey); key != "endoflife" {
		return nil, nil
	}
	v, ok := propStr(props, assemble.PropValue)
	if !ok || v == "" {
		return nil, nil
	}
	return []FactValue{{FactEndOfLife, v}}, nil
}

func scorecardFacts(props []varve.Prop) ([]FactValue, []varve.NodeID) {
	v, ok := propStr(props, assemble.PropAggregateScore)
	if !ok || v == "" {
		return nil, nil
	}
	return []FactValue{{FactScorecard, v}}, nil
}

// Derive reads the claims a scanner's evidence nodes state, ordered by ID.
func Derive(s varve.Stream) []Claim {
	var out []Claim
	for _, n := range s.Nodes {
		out = append(out, nodeClaims(n)...)
	}
	slices.SortFunc(out, func(a, b Claim) int {
		switch {
		case a.ID() < b.ID():
			return -1
		case a.ID() > b.ID():
			return 1
		}
		return 0
	})
	return out
}

// nodeClaims reads the claims one evidence node states.
func nodeClaims(n varve.NodeRecord) []Claim {
	collector, ok := propStr(n.Props, assemble.PropCollector)
	if !ok {
		return nil
	}
	subject, ok := propStr(n.Props, assemble.PropSubjectID)
	if !ok || subject == "" {
		return nil
	}
	ref, _ := propStr(n.Props, assemble.PropDocumentRef)

	var out []Claim
	for _, label := range n.Labels {
		sc, known := scanners[scannerKey{label, collector}]
		if !known {
			continue
		}
		facts, also := sc.extract(n.Props)
		stamp, _ := propStr(n.Props, sc.timeKey)
		fetched, _ := time.Parse(time.RFC3339, stamp)
		for _, f := range facts {
			out = append(out, Claim{
				Source:       sc.source,
				Jurisdiction: Jurisdictions[sc.source],
				Subject:      varve.NodeID(subject),
				Also:         also,
				Fact:         f.Fact,
				Value:        f.Value,
				Ref:          ref,
				ValidFrom:    n.ValidFrom,
				FetchedAt:    fetched,
			})
		}
	}
	return out
}
