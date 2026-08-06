package assemble

import (
	"strconv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/internal/varve"
)

func (b *builder) mapHasSlsa(slsas []assembler.HasSlsaIngest) {
	for _, h := range slsas {
		if h.HasSlsa == nil {
			continue
		}
		sl := h.HasSlsa
		b.beginAssertion(sl.FinishedOn)
		subjID := b.addArtifact(h.Artifact)
		bldID := b.addBuilder(h.Builder)
		materials := make([]varve.NodeID, 0, len(h.Materials))
		for i := range h.Materials {
			materials = append(materials, b.addArtifact(&h.Materials[i]))
		}
		pairs := make([]KVPair, 0, len(sl.SlsaPredicate))
		for _, p := range sl.SlsaPredicate {
			pairs = append(pairs, KVPair{Key: p.Key, Value: p.Value})
		}
		predicates := encodeKV(pairs)
		started := fmtTimePtr(sl.StartedOn)
		finished := fmtTimePtr(sl.FinishedOn)
		builtFrom := joinIDs(materials)
		evID := EvidenceID(string(LabelHasSlsa), string(subjID), string(bldID), builtFrom,
			sl.BuildType, sl.SlsaVersion, started, finished, sl.Origin, sl.Collector, sl.DocumentRef, predicates)
		b.addNode(evID, LabelHasSlsa, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "builtById", Value: varve.Str(string(bldID))},
			{Key: "builtFrom", Value: varve.Str(builtFrom)},
			{Key: "buildType", Value: varve.Str(sl.BuildType)},
			{Key: "slsaVersion", Value: varve.Str(sl.SlsaVersion)},
			{Key: "startedOn", Value: varve.Str(started)},
			{Key: "finishedOn", Value: varve.Str(finished)},
			{Key: "origin", Value: varve.Str(sl.Origin)},
			{Key: "collector", Value: varve.Str(sl.Collector)},
			{Key: "documentRef", Value: varve.Str(sl.DocumentRef)},
			{Key: "predicates", Value: varve.Str(predicates)},
		})
		b.addEdge(subjID, EdgeHasSlsaSubject, evID)
		b.addEdge(evID, EdgeHasSlsaBuiltBy, bldID)
		for _, m := range materials {
			b.addEdge(evID, EdgeHasSlsaMaterial, m)
		}
	}
}

func (b *builder) mapCertifyScorecard(cards []assembler.CertifyScorecardIngest) {
	for _, c := range cards {
		if c.Scorecard == nil {
			continue
		}
		sc := c.Scorecard
		b.beginAssertion(&sc.TimeScanned)
		srcID := b.addSource(c.Source)
		pairs := make([]KVPair, 0, len(sc.Checks))
		for _, ck := range sc.Checks {
			pairs = append(pairs, KVPair{Key: ck.Check, Value: strconv.Itoa(ck.Score)})
		}
		checks := encodeKV(pairs)
		aggr := formatFloat(sc.AggregateScore)
		evID := EvidenceID(string(LabelCertifyScorecard), string(srcID),
			sc.ScorecardVersion, sc.ScorecardCommit, fmtTime(sc.TimeScanned), aggr,
			sc.Origin, sc.Collector, sc.DocumentRef, checks)
		b.addNode(evID, LabelCertifyScorecard, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(srcID))},
			{Key: "aggregateScore", Value: varve.Float(sc.AggregateScore)},
			{Key: "timeScanned", Value: varve.Str(fmtTime(sc.TimeScanned))},
			{Key: "scorecardVersion", Value: varve.Str(sc.ScorecardVersion)},
			{Key: "scorecardCommit", Value: varve.Str(sc.ScorecardCommit)},
			{Key: "origin", Value: varve.Str(sc.Origin)},
			{Key: "collector", Value: varve.Str(sc.Collector)},
			{Key: "documentRef", Value: varve.Str(sc.DocumentRef)},
			{Key: "checks", Value: varve.Str(checks)},
		})
		b.addEdge(srcID, EdgeCertifyScorecardSubject, evID)
	}
}

func (b *builder) mapCertifyLegal(legals []assembler.CertifyLegalIngest) {
	for _, c := range legals {
		if c.CertifyLegal == nil {
			continue
		}
		cl := c.CertifyLegal
		b.beginAssertion(&cl.TimeScanned)
		subjID := b.pkgOrSrcSubject(c.Pkg, c.Src)
		declared := make([]varve.NodeID, 0, len(c.Declared))
		for _, l := range c.Declared {
			declared = append(declared, b.addLicense(l))
		}
		discovered := make([]varve.NodeID, 0, len(c.Discovered))
		for _, l := range c.Discovered {
			discovered = append(discovered, b.addLicense(l))
		}
		declaredJoin := joinIDs(declared)
		discoveredJoin := joinIDs(discovered)
		evID := EvidenceID(string(LabelCertifyLegal), string(subjID),
			cl.DeclaredLicense, cl.DiscoveredLicense, cl.Attribution, cl.Justification, fmtTime(cl.TimeScanned),
			cl.Origin, cl.Collector, cl.DocumentRef, declaredJoin, discoveredJoin)
		b.addNode(evID, LabelCertifyLegal, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "declaredLicense", Value: varve.Str(cl.DeclaredLicense)},
			{Key: "discoveredLicense", Value: varve.Str(cl.DiscoveredLicense)},
			{Key: "attribution", Value: varve.Str(cl.Attribution)},
			{Key: "justification", Value: varve.Str(cl.Justification)},
			{Key: "timeScanned", Value: varve.Str(fmtTime(cl.TimeScanned))},
			{Key: "origin", Value: varve.Str(cl.Origin)},
			{Key: "collector", Value: varve.Str(cl.Collector)},
			{Key: "documentRef", Value: varve.Str(cl.DocumentRef)},
			{Key: "declaredLicenses", Value: varve.Str(declaredJoin)},
			{Key: "discoveredLicenses", Value: varve.Str(discoveredJoin)},
		})
		b.addEdge(subjID, EdgeCertifyLegalSubject, evID)
		for _, lic := range declared {
			b.addEdge(evID, EdgeCertifyLegalDeclaredLicense, lic)
		}
		for _, lic := range discovered {
			b.addEdge(evID, EdgeCertifyLegalDiscoveredLicense, lic)
		}
	}
}
