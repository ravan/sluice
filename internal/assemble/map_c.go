package assemble

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/internal/varve"
)

func (b *builder) mapCertifyBad(bads []assembler.CertifyBadIngest) {
	for _, c := range bads {
		if c.CertifyBad == nil {
			continue
		}
		cb := c.CertifyBad
		b.beginAssertion(&cb.KnownSince)
		subjID, _ := b.psaSubject(c.Pkg, c.PkgMatchFlag, c.Src, c.Artifact)
		evID := EvidenceID(string(LabelCertifyBad), string(subjID),
			fmtTime(cb.KnownSince), cb.Justification, cb.Origin, cb.Collector, cb.DocumentRef)
		b.addNode(evID, LabelCertifyBad, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "justification", Value: varve.Str(cb.Justification)},
			{Key: "knownSince", Value: varve.Str(fmtTime(cb.KnownSince))},
			{Key: "origin", Value: varve.Str(cb.Origin)},
			{Key: "collector", Value: varve.Str(cb.Collector)},
			{Key: "documentRef", Value: varve.Str(cb.DocumentRef)},
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
		evID := EvidenceID(string(LabelCertifyGood), string(subjID),
			fmtTime(cg.KnownSince), cg.Justification, cg.Origin, cg.Collector, cg.DocumentRef)
		b.addNode(evID, LabelCertifyGood, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "justification", Value: varve.Str(cg.Justification)},
			{Key: "knownSince", Value: varve.Str(fmtTime(cg.KnownSince))},
			{Key: "origin", Value: varve.Str(cg.Origin)},
			{Key: "collector", Value: varve.Str(cg.Collector)},
			{Key: "documentRef", Value: varve.Str(cg.DocumentRef)},
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
		evID := EvidenceID(string(LabelHasMetadata), string(subjID),
			hm.Key, hm.Value, fmtTime(hm.Timestamp), hm.Justification, hm.Origin, hm.Collector, hm.DocumentRef)
		b.addNode(evID, LabelHasMetadata, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "key", Value: varve.Str(hm.Key)},
			{Key: "value", Value: varve.Str(hm.Value)},
			{Key: "timestamp", Value: varve.Str(fmtTime(hm.Timestamp))},
			{Key: "justification", Value: varve.Str(hm.Justification)},
			{Key: "origin", Value: varve.Str(hm.Origin)},
			{Key: "collector", Value: varve.Str(hm.Collector)},
			{Key: "documentRef", Value: varve.Str(hm.DocumentRef)},
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
		evID := EvidenceID(string(LabelPointOfContact), string(subjID),
			poc.Email, poc.Info, fmtTime(poc.Since), poc.Justification, poc.Origin, poc.Collector, poc.DocumentRef)
		b.addNode(evID, LabelPointOfContact, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "email", Value: varve.Str(poc.Email)},
			{Key: "info", Value: varve.Str(poc.Info)},
			{Key: "since", Value: varve.Str(fmtTime(poc.Since))},
			{Key: "justification", Value: varve.Str(poc.Justification)},
			{Key: "origin", Value: varve.Str(poc.Origin)},
			{Key: "collector", Value: varve.Str(poc.Collector)},
			{Key: "documentRef", Value: varve.Str(poc.DocumentRef)},
		})
		b.addEdge(subjID, EdgePointOfContactSubject, evID)
	}
}
