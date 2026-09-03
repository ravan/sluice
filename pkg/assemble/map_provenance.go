// Provenance evidence: where a subject was built, from what, and how the
// build scored.

package assemble

import (
	"strconv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/pkg/varve"
)

func (b *builder) mapHasSourceAt(hs []assembler.HasSourceAtIngest) {
	for _, h := range hs {
		if h.HasSourceAt == nil {
			continue
		}
		hsa := h.HasSourceAt
		b.beginAssertion(&hsa.KnownSince)
		subjID, _ := b.pkgSubjectID(h.Pkg, h.PkgMatchFlag)
		srcID := b.addSource(h.Src)
		evID := EvidenceID(LabelHasSourceAt, string(subjID), string(srcID),
			fmtTime(hsa.KnownSince), hsa.Justification, hsa.Origin, hsa.Collector, hsa.DocumentRef)
		b.addNode(evID, LabelHasSourceAt, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropObjectID, Value: varve.Str(string(srcID))},
			{Key: PropKnownSince, Value: varve.Str(fmtTime(hsa.KnownSince))},
			{Key: PropJustification, Value: varve.Str(hsa.Justification)},
			{Key: PropOrigin, Value: varve.Str(hsa.Origin)},
			{Key: PropCollector, Value: varve.Str(hsa.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(hsa.DocumentRef)},
		})
		b.addEdge(subjID, EdgeHasSourceAtSubject, evID)
		b.addEdge(evID, EdgeHasSourceAtSource, srcID)
	}
}

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
		evID := EvidenceID(LabelHasSlsa, string(subjID), string(bldID), builtFrom,
			sl.BuildType, sl.SlsaVersion, started, finished, sl.Origin, sl.Collector, sl.DocumentRef, predicates)
		b.addNode(evID, LabelHasSlsa, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropBuiltByID, Value: varve.Str(string(bldID))},
			{Key: PropBuiltFrom, Value: varve.Str(builtFrom)},
			{Key: PropBuildType, Value: varve.Str(sl.BuildType)},
			{Key: PropSlsaVersion, Value: varve.Str(sl.SlsaVersion)},
			{Key: PropStartedOn, Value: varve.Str(started)},
			{Key: PropFinishedOn, Value: varve.Str(finished)},
			{Key: PropOrigin, Value: varve.Str(sl.Origin)},
			{Key: PropCollector, Value: varve.Str(sl.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(sl.DocumentRef)},
			{Key: PropPredicates, Value: varve.Str(predicates)},
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
		evID := EvidenceID(LabelCertifyScorecard, string(srcID),
			sc.ScorecardVersion, sc.ScorecardCommit, fmtTime(sc.TimeScanned), aggr,
			sc.Origin, sc.Collector, sc.DocumentRef, checks)
		b.addNode(evID, LabelCertifyScorecard, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(srcID))},
			{Key: PropAggregateScore, Value: varve.Float(sc.AggregateScore)},
			{Key: PropTimeScanned, Value: varve.Str(fmtTime(sc.TimeScanned))},
			{Key: PropScorecardVersion, Value: varve.Str(sc.ScorecardVersion)},
			{Key: PropScorecardCommit, Value: varve.Str(sc.ScorecardCommit)},
			{Key: PropOrigin, Value: varve.Str(sc.Origin)},
			{Key: PropCollector, Value: varve.Str(sc.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(sc.DocumentRef)},
			{Key: PropChecks, Value: varve.Str(checks)},
		})
		b.addEdge(srcID, EdgeCertifyScorecardSubject, evID)
	}
}
