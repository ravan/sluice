package enrich

import (
	"slices"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/varve"
)

// factValue is one fact a scanner node states, with the value it states.
type factValue struct{ fact, value string }

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
	extract func(props []varve.Prop) ([]factValue, []varve.NodeID)
}

// scanners is the (label, collector) table of plan D5.
var scanners = map[scannerKey]scanner{
	{assemble.LabelCertifyVuln, "osv_certifier"}:               {SourceOSV, "timeScanned", vulnFacts},
	{assemble.LabelCertifyLegal, "clearlydefined"}:             {SourceClearlyDefined, "timeScanned", legalFacts},
	{assemble.LabelHasMetadata, "GUAC"}:                        {SourceEOL, "timestamp", eolFacts},
	{assemble.LabelCertifyScorecard, "ingest_depsdev_scanner"}: {SourceDepsDev, "timeScanned", scorecardFacts},
}

func vulnFacts(props []varve.Prop) ([]factValue, []varve.NodeID) {
	object, ok := propStr(props, "objectId")
	if !ok || object == "" {
		return nil, nil
	}
	return []factValue{{"affected", object}}, []varve.NodeID{varve.NodeID(object)}
}

func legalFacts(props []varve.Prop) ([]factValue, []varve.NodeID) {
	var facts []factValue
	for _, pair := range []struct{ key, fact string }{
		{"declaredLicense", "declared_license"},
		{"discoveredLicense", "discovered_license"},
	} {
		if v, ok := propStr(props, pair.key); ok && v != "" {
			facts = append(facts, factValue{pair.fact, v})
		}
	}
	return facts, nil
}

func eolFacts(props []varve.Prop) ([]factValue, []varve.NodeID) {
	if key, _ := propStr(props, "key"); key != "endoflife" {
		return nil, nil
	}
	v, ok := propStr(props, "value")
	if !ok || v == "" {
		return nil, nil
	}
	return []factValue{{"endoflife", v}}, nil
}

func scorecardFacts(props []varve.Prop) ([]factValue, []varve.NodeID) {
	v, ok := propStr(props, "aggregateScore")
	if !ok || v == "" {
		return nil, nil
	}
	return []factValue{{"scorecard", v}}, nil
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
	collector, ok := propStr(n.Props, "collector")
	if !ok {
		return nil
	}
	subject, ok := propStr(n.Props, "subjectId")
	if !ok || subject == "" {
		return nil
	}
	ref, _ := propStr(n.Props, "documentRef")

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
				Fact:         f.fact,
				Value:        f.value,
				Ref:          ref,
				ValidFrom:    n.ValidFrom,
				FetchedAt:    fetched,
			})
		}
	}
	return out
}
