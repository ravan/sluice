package assemble

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/varve"
)

// pkgOrSrcSubject resolves the PkgVersion id (or SrcName id) of whichever
// subject is non-nil.
func (b *builder) pkgOrSrcSubject(pkg *generated.PkgInputSpec, src *generated.SourceInputSpec) varve.NodeID {
	if pkg != nil {
		_, versionID := b.addPackage(pkg)
		return versionID
	}
	return b.addSource(src)
}

// pkgOrArtSubject resolves the PkgVersion id (or Artifact id) of whichever
// subject is non-nil.
func (b *builder) pkgOrArtSubject(pkg *generated.PkgInputSpec, art *generated.ArtifactInputSpec) varve.NodeID {
	if pkg != nil {
		_, versionID := b.addPackage(pkg)
		return versionID
	}
	return b.addArtifact(art)
}

func toNodeIDs(ids []string) []varve.NodeID {
	out := make([]varve.NodeID, len(ids))
	for i, s := range ids {
		out[i] = varve.NodeID(s)
	}
	return out
}

func (b *builder) mapIsOccurrence(occs []assembler.IsOccurrenceIngest) {
	for _, o := range occs {
		if o.IsOccurrence == nil {
			continue
		}
		b.beginAssertion(nil)
		subjID := b.pkgOrSrcSubject(o.Pkg, o.Src)
		artID := b.addArtifact(o.Artifact)
		io := o.IsOccurrence
		evID := EvidenceID(string(LabelIsOccurrence), string(subjID), string(artID),
			io.Justification, io.Origin, io.Collector, io.DocumentRef)
		b.addNode(evID, LabelIsOccurrence, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "objectId", Value: varve.Str(string(artID))},
			{Key: "justification", Value: varve.Str(io.Justification)},
			{Key: "origin", Value: varve.Str(io.Origin)},
			{Key: "collector", Value: varve.Str(io.Collector)},
			{Key: "documentRef", Value: varve.Str(io.DocumentRef)},
		})
		b.addEdge(subjID, EdgeIsOccurrenceSubject, evID)
		b.addEdge(evID, EdgeIsOccurrenceArtifact, artID)
	}
}

func (b *builder) mapHasSBOM(sboms []assembler.HasSBOMIngest) {
	for _, s := range sboms {
		if s.HasSBOM == nil {
			continue
		}
		hb := s.HasSBOM
		b.beginAssertion(&hb.KnownSince)
		subjID := b.pkgOrArtSubject(s.Pkg, s.Artifact)
		var software, dependencies, occurrences string
		if s.Includes != nil {
			software = joinIDs(toNodeIDs(append(append([]string{}, s.Includes.Packages...), s.Includes.Artifacts...)))
			dependencies = joinIDs(toNodeIDs(s.Includes.Dependencies))
			occurrences = joinIDs(toNodeIDs(s.Includes.Occurrences))
		}
		evID := EvidenceID(string(LabelHasSBOM), string(subjID), hb.Uri, hb.Algorithm, hb.Digest,
			hb.DownloadLocation, fmtTime(hb.KnownSince), hb.Origin, hb.Collector, hb.DocumentRef)
		b.addNode(evID, LabelHasSBOM, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "uri", Value: varve.Str(hb.Uri)},
			{Key: "algorithm", Value: varve.Str(hb.Algorithm)},
			{Key: "digest", Value: varve.Str(hb.Digest)},
			{Key: "downloadLocation", Value: varve.Str(hb.DownloadLocation)},
			{Key: "knownSince", Value: varve.Str(fmtTime(hb.KnownSince))},
			{Key: "origin", Value: varve.Str(hb.Origin)},
			{Key: "collector", Value: varve.Str(hb.Collector)},
			{Key: "documentRef", Value: varve.Str(hb.DocumentRef)},
			{Key: "includedSoftware", Value: varve.Str(software)},
			{Key: "includedDependencies", Value: varve.Str(dependencies)},
			{Key: "includedOccurrences", Value: varve.Str(occurrences)},
		})
		b.addEdge(subjID, EdgeHasSbomSubject, evID)
	}
}

func (b *builder) mapVex(vexes []assembler.VexIngest) {
	for _, v := range vexes {
		if v.VexData == nil {
			continue
		}
		vx := v.VexData
		b.beginAssertion(&vx.KnownSince)
		subjID := b.pkgOrArtSubject(v.Pkg, v.Artifact)
		vulnID := b.addVulnerability(v.Vulnerability)
		evID := EvidenceID(string(LabelVex), string(subjID), string(vulnID),
			string(vx.Status), string(vx.VexJustification), vx.Statement, vx.StatusNotes,
			fmtTime(vx.KnownSince), vx.Origin, vx.Collector, vx.DocumentRef)
		b.addNode(evID, LabelVex, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "objectId", Value: varve.Str(string(vulnID))},
			{Key: "status", Value: varve.Str(string(vx.Status))},
			{Key: "vexJustification", Value: varve.Str(string(vx.VexJustification))},
			{Key: "statement", Value: varve.Str(vx.Statement)},
			{Key: "statusNotes", Value: varve.Str(vx.StatusNotes)},
			{Key: "knownSince", Value: varve.Str(fmtTime(vx.KnownSince))},
			{Key: "origin", Value: varve.Str(vx.Origin)},
			{Key: "collector", Value: varve.Str(vx.Collector)},
			{Key: "documentRef", Value: varve.Str(vx.DocumentRef)},
		})
		b.addEdge(subjID, EdgeVexSubject, evID)
		b.addEdge(evID, EdgeVexVulnerability, vulnID)
	}
}
