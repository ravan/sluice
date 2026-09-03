// Composition evidence: what a package declares, contains, or resolves to.

package assemble

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/pkg/varve"
)

func (b *builder) mapIsDependency(deps []assembler.IsDependencyIngest) {
	for _, d := range deps {
		if d.IsDependency == nil {
			continue
		}
		b.beginAssertion(nil)
		_, subjID := b.addPackage(d.Pkg)
		_, objID := b.addPackage(d.DepPkg)
		dep := d.IsDependency
		evID := EvidenceID(LabelIsDependency, string(subjID), string(objID),
			string(dep.DependencyType), dep.Justification, dep.Origin, dep.Collector, dep.DocumentRef)
		b.addNode(evID, LabelIsDependency, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropObjectID, Value: varve.Str(string(objID))},
			{Key: PropDependencyType, Value: varve.Str(string(dep.DependencyType))},
			{Key: PropJustification, Value: varve.Str(dep.Justification)},
			{Key: PropOrigin, Value: varve.Str(dep.Origin)},
			{Key: PropCollector, Value: varve.Str(dep.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(dep.DocumentRef)},
		})
		b.addEdge(subjID, EdgeIsDependencySubject, evID)
		b.addEdge(evID, EdgeIsDependencyObject, objID)
	}
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
		evID := EvidenceID(LabelIsOccurrence, string(subjID), string(artID),
			io.Justification, io.Origin, io.Collector, io.DocumentRef)
		b.addNode(evID, LabelIsOccurrence, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropObjectID, Value: varve.Str(string(artID))},
			{Key: PropJustification, Value: varve.Str(io.Justification)},
			{Key: PropOrigin, Value: varve.Str(io.Origin)},
			{Key: PropCollector, Value: varve.Str(io.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(io.DocumentRef)},
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
		evID := EvidenceID(LabelHasSBOM, string(subjID), hb.Uri, hb.Algorithm, hb.Digest,
			hb.DownloadLocation, fmtTime(hb.KnownSince), hb.Origin, hb.Collector, hb.DocumentRef)
		b.addNode(evID, LabelHasSBOM, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropURI, Value: varve.Str(hb.Uri)},
			{Key: PropAlgorithm, Value: varve.Str(hb.Algorithm)},
			{Key: PropDigest, Value: varve.Str(hb.Digest)},
			{Key: PropDownloadLocation, Value: varve.Str(hb.DownloadLocation)},
			{Key: PropKnownSince, Value: varve.Str(fmtTime(hb.KnownSince))},
			{Key: PropOrigin, Value: varve.Str(hb.Origin)},
			{Key: PropCollector, Value: varve.Str(hb.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(hb.DocumentRef)},
			{Key: PropIncludedSoftware, Value: varve.Str(software)},
			{Key: PropIncludedDependencies, Value: varve.Str(dependencies)},
			{Key: PropIncludedOccurrences, Value: varve.Str(occurrences)},
		})
		b.addEdge(subjID, EdgeHasSbomSubject, evID)
	}
}
