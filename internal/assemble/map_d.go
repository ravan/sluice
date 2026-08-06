package assemble

import (
	"strconv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/internal/varve"
)

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func (b *builder) mapHashEqual(eqs []assembler.HashEqualIngest) {
	for _, h := range eqs {
		if h.HashEqual == nil {
			continue
		}
		b.beginAssertion(nil)
		a1 := b.addArtifact(h.Artifact)
		a2 := b.addArtifact(h.EqualArtifact)
		members := sortedIDs([]varve.NodeID{a1, a2})
		joined := joinIDs(members)
		he := h.HashEqual
		evID := EvidenceID(string(LabelHashEqual), joined, he.Justification, he.Origin, he.Collector, he.DocumentRef)
		b.addNode(evID, LabelHashEqual, []varve.Prop{
			{Key: "members", Value: varve.Str(joined)},
			{Key: "justification", Value: varve.Str(he.Justification)},
			{Key: "origin", Value: varve.Str(he.Origin)},
			{Key: "collector", Value: varve.Str(he.Collector)},
			{Key: "documentRef", Value: varve.Str(he.DocumentRef)},
		})
		for _, m := range members {
			b.addEdge(evID, EdgeHashEqualArtifact, m)
		}
	}
}

func (b *builder) mapPkgEqual(eqs []assembler.PkgEqualIngest) {
	for _, p := range eqs {
		if p.PkgEqual == nil {
			continue
		}
		b.beginAssertion(nil)
		_, p1 := b.addPackage(p.Pkg)
		_, p2 := b.addPackage(p.EqualPkg)
		members := sortedIDs([]varve.NodeID{p1, p2})
		joined := joinIDs(members)
		pe := p.PkgEqual
		evID := EvidenceID(string(LabelPkgEqual), joined, pe.Justification, pe.Origin, pe.Collector, pe.DocumentRef)
		b.addNode(evID, LabelPkgEqual, []varve.Prop{
			{Key: "members", Value: varve.Str(joined)},
			{Key: "justification", Value: varve.Str(pe.Justification)},
			{Key: "origin", Value: varve.Str(pe.Origin)},
			{Key: "collector", Value: varve.Str(pe.Collector)},
			{Key: "documentRef", Value: varve.Str(pe.DocumentRef)},
		})
		for _, m := range members {
			b.addEdge(evID, EdgePkgEqualPackage, m)
		}
	}
}

func (b *builder) mapVulnEqual(eqs []assembler.VulnEqualIngest) {
	for _, v := range eqs {
		if v.VulnEqual == nil {
			continue
		}
		b.beginAssertion(nil)
		v1 := b.addVulnerability(v.Vulnerability)
		v2 := b.addVulnerability(v.EqualVulnerability)
		members := sortedIDs([]varve.NodeID{v1, v2})
		joined := joinIDs(members)
		ve := v.VulnEqual
		evID := EvidenceID(string(LabelVulnEqual), joined, ve.Justification, ve.Origin, ve.Collector, ve.DocumentRef)
		b.addNode(evID, LabelVulnEqual, []varve.Prop{
			{Key: "members", Value: varve.Str(joined)},
			{Key: "justification", Value: varve.Str(ve.Justification)},
			{Key: "origin", Value: varve.Str(ve.Origin)},
			{Key: "collector", Value: varve.Str(ve.Collector)},
			{Key: "documentRef", Value: varve.Str(ve.DocumentRef)},
		})
		for _, m := range members {
			b.addEdge(evID, EdgeVulnEqualVulnerability, m)
		}
	}
}

func (b *builder) mapVulnMetadata(metas []assembler.VulnMetadataIngest) {
	for _, v := range metas {
		if v.VulnMetadata == nil {
			continue
		}
		vm := v.VulnMetadata
		b.beginAssertion(&vm.Timestamp)
		vulnID := b.addVulnerability(v.Vulnerability)
		evID := EvidenceID(string(LabelVulnMetadata), string(vulnID),
			string(vm.ScoreType), formatFloat(vm.ScoreValue), fmtTime(vm.Timestamp),
			vm.Origin, vm.Collector, vm.DocumentRef)
		b.addNode(evID, LabelVulnMetadata, []varve.Prop{
			{Key: "objectId", Value: varve.Str(string(vulnID))},
			{Key: "scoreType", Value: varve.Str(string(vm.ScoreType))},
			{Key: "scoreValue", Value: varve.Float(vm.ScoreValue)},
			{Key: "timestamp", Value: varve.Str(fmtTime(vm.Timestamp))},
			{Key: "origin", Value: varve.Str(vm.Origin)},
			{Key: "collector", Value: varve.Str(vm.Collector)},
			{Key: "documentRef", Value: varve.Str(vm.DocumentRef)},
		})
		b.addEdge(evID, EdgeVulnMetadataVulnerability, vulnID)
	}
}
