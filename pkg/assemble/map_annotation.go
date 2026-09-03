// Human and tool annotations: judgements and contact details attached to a
// package, source, or artifact.

package assemble

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/pkg/varve"
)

func (b *builder) mapCertifyBad(bads []assembler.CertifyBadIngest) {
	for _, c := range bads {
		if c.CertifyBad == nil {
			continue
		}
		cb := c.CertifyBad
		b.beginAssertion(&cb.KnownSince)
		subjID, _ := b.psaSubject(c.Pkg, c.PkgMatchFlag, c.Src, c.Artifact)
		evID := EvidenceID(LabelCertifyBad, string(subjID),
			fmtTime(cb.KnownSince), cb.Justification, cb.Origin, cb.Collector, cb.DocumentRef)
		b.addNode(evID, LabelCertifyBad, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropJustification, Value: varve.Str(cb.Justification)},
			{Key: PropKnownSince, Value: varve.Str(fmtTime(cb.KnownSince))},
			{Key: PropOrigin, Value: varve.Str(cb.Origin)},
			{Key: PropCollector, Value: varve.Str(cb.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(cb.DocumentRef)},
		})
		b.addEdge(subjID, EdgeCertifyBadSubject, evID)
	}
}

func (b *builder) mapCertifyGood(goods []assembler.CertifyGoodIngest) {
	for _, c := range goods {
		if c.CertifyGood == nil {
			continue
		}
		cg := c.CertifyGood
		b.beginAssertion(&cg.KnownSince)
		subjID, _ := b.psaSubject(c.Pkg, c.PkgMatchFlag, c.Src, c.Artifact)
		evID := EvidenceID(LabelCertifyGood, string(subjID),
			fmtTime(cg.KnownSince), cg.Justification, cg.Origin, cg.Collector, cg.DocumentRef)
		b.addNode(evID, LabelCertifyGood, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropJustification, Value: varve.Str(cg.Justification)},
			{Key: PropKnownSince, Value: varve.Str(fmtTime(cg.KnownSince))},
			{Key: PropOrigin, Value: varve.Str(cg.Origin)},
			{Key: PropCollector, Value: varve.Str(cg.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(cg.DocumentRef)},
		})
		b.addEdge(subjID, EdgeCertifyGoodSubject, evID)
	}
}

func (b *builder) mapHasMetadata(metas []assembler.HasMetadataIngest) {
	for _, h := range metas {
		if h.HasMetadata == nil {
			continue
		}
		hm := h.HasMetadata
		b.beginAssertion(&hm.Timestamp)
		subjID, _ := b.psaSubject(h.Pkg, h.PkgMatchFlag, h.Src, h.Artifact)
		evID := EvidenceID(LabelHasMetadata, string(subjID),
			hm.Key, hm.Value, fmtTime(hm.Timestamp), hm.Justification, hm.Origin, hm.Collector, hm.DocumentRef)
		b.addNode(evID, LabelHasMetadata, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropKey, Value: varve.Str(hm.Key)},
			{Key: PropValue, Value: varve.Str(hm.Value)},
			{Key: PropTimestamp, Value: varve.Str(fmtTime(hm.Timestamp))},
			{Key: PropJustification, Value: varve.Str(hm.Justification)},
			{Key: PropOrigin, Value: varve.Str(hm.Origin)},
			{Key: PropCollector, Value: varve.Str(hm.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(hm.DocumentRef)},
		})
		b.addEdge(subjID, EdgeHasMetadataSubject, evID)
	}
}

func (b *builder) mapPointOfContact(pocs []assembler.PointOfContactIngest) {
	for _, p := range pocs {
		if p.PointOfContact == nil {
			continue
		}
		poc := p.PointOfContact
		b.beginAssertion(&poc.Since)
		subjID, _ := b.psaSubject(p.Pkg, p.PkgMatchFlag, p.Src, p.Artifact)
		evID := EvidenceID(LabelPointOfContact, string(subjID),
			poc.Email, poc.Info, fmtTime(poc.Since), poc.Justification, poc.Origin, poc.Collector, poc.DocumentRef)
		b.addNode(evID, LabelPointOfContact, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropEmail, Value: varve.Str(poc.Email)},
			{Key: PropInfo, Value: varve.Str(poc.Info)},
			{Key: PropSince, Value: varve.Str(fmtTime(poc.Since))},
			{Key: PropJustification, Value: varve.Str(poc.Justification)},
			{Key: PropOrigin, Value: varve.Str(poc.Origin)},
			{Key: PropCollector, Value: varve.Str(poc.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(poc.DocumentRef)},
		})
		b.addEdge(subjID, EdgePointOfContactSubject, evID)
	}
}
