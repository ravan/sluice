// Identity-merge evidence: two nodes a source asserts are the same thing.

package assemble

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/pkg/varve"
)

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
		evID := EvidenceID(LabelHashEqual, joined, he.Justification, he.Origin, he.Collector, he.DocumentRef)
		b.addNode(evID, LabelHashEqual, []varve.Prop{
			{Key: PropMembers, Value: varve.Str(joined)},
			{Key: PropJustification, Value: varve.Str(he.Justification)},
			{Key: PropOrigin, Value: varve.Str(he.Origin)},
			{Key: PropCollector, Value: varve.Str(he.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(he.DocumentRef)},
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
		evID := EvidenceID(LabelPkgEqual, joined, pe.Justification, pe.Origin, pe.Collector, pe.DocumentRef)
		b.addNode(evID, LabelPkgEqual, []varve.Prop{
			{Key: PropMembers, Value: varve.Str(joined)},
			{Key: PropJustification, Value: varve.Str(pe.Justification)},
			{Key: PropOrigin, Value: varve.Str(pe.Origin)},
			{Key: PropCollector, Value: varve.Str(pe.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(pe.DocumentRef)},
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
		evID := EvidenceID(LabelVulnEqual, joined, ve.Justification, ve.Origin, ve.Collector, ve.DocumentRef)
		b.addNode(evID, LabelVulnEqual, []varve.Prop{
			{Key: PropMembers, Value: varve.Str(joined)},
			{Key: PropJustification, Value: varve.Str(ve.Justification)},
			{Key: PropOrigin, Value: varve.Str(ve.Origin)},
			{Key: PropCollector, Value: varve.Str(ve.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(ve.DocumentRef)},
		})
		for _, m := range members {
			b.addEdge(evID, EdgeVulnEqualVulnerability, m)
		}
	}
}
