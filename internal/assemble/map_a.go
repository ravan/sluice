package assemble

import (
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/internal/varve"
)

// fmtTime renders a required timestamp as a plain RFC3339 string property
// (guarded valid time is S2). Always non-empty, always in the id hash.
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// fmtTimePtr renders an optional timestamp: "" when nil (omitted from props,
// "" in the id hash).
func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (b *builder) mapIsDependency(deps []assembler.IsDependencyIngest) {
	for _, d := range deps {
		if d.IsDependency == nil {
			continue
		}
		b.beginAssertion(nil)
		_, subjID := b.addPackage(d.Pkg)
		_, objID := b.addPackage(d.DepPkg)
		dep := d.IsDependency
		evID := EvidenceID(string(LabelIsDependency), string(subjID), string(objID),
			string(dep.DependencyType), dep.Justification, dep.Origin, dep.Collector, dep.DocumentRef)
		b.addNode(evID, LabelIsDependency, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "objectId", Value: varve.Str(string(objID))},
			{Key: "dependencyType", Value: varve.Str(string(dep.DependencyType))},
			{Key: "justification", Value: varve.Str(dep.Justification)},
			{Key: "origin", Value: varve.Str(dep.Origin)},
			{Key: "collector", Value: varve.Str(dep.Collector)},
			{Key: "documentRef", Value: varve.Str(dep.DocumentRef)},
		})
		b.addEdge(subjID, EdgeIsDependencySubject, evID)
		b.addEdge(evID, EdgeIsDependencyObject, objID)
	}
}

func (b *builder) mapCertifyVuln(certs []assembler.CertifyVulnIngest) {
	for _, c := range certs {
		if c.VulnData == nil {
			continue
		}
		vd := c.VulnData
		b.beginAssertion(&vd.TimeScanned)
		_, subjID := b.addPackage(c.Pkg)
		vulnID := b.addVulnerability(c.Vulnerability)
		evID := EvidenceID(string(LabelCertifyVuln), string(subjID), string(vulnID),
			fmtTime(vd.TimeScanned), vd.DbUri, vd.DbVersion, vd.ScannerUri, vd.ScannerVersion,
			vd.Origin, vd.Collector, vd.DocumentRef)
		b.addNode(evID, LabelCertifyVuln, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "objectId", Value: varve.Str(string(vulnID))},
			{Key: "timeScanned", Value: varve.Str(fmtTime(vd.TimeScanned))},
			{Key: "dbUri", Value: varve.Str(vd.DbUri)},
			{Key: "dbVersion", Value: varve.Str(vd.DbVersion)},
			{Key: "scannerUri", Value: varve.Str(vd.ScannerUri)},
			{Key: "scannerVersion", Value: varve.Str(vd.ScannerVersion)},
			{Key: "origin", Value: varve.Str(vd.Origin)},
			{Key: "collector", Value: varve.Str(vd.Collector)},
			{Key: "documentRef", Value: varve.Str(vd.DocumentRef)},
		})
		b.addEdge(subjID, EdgeCertifyVulnSubject, evID)
		b.addEdge(evID, EdgeCertifyVulnVulnerability, vulnID)
	}
}

func (b *builder) mapHasSourceAt(hs []assembler.HasSourceAtIngest) {
	for _, h := range hs {
		if h.HasSourceAt == nil {
			continue
		}
		hsa := h.HasSourceAt
		b.beginAssertion(&hsa.KnownSince)
		subjID, _ := b.pkgSubjectID(h.Pkg, h.PkgMatchFlag)
		srcID := b.addSource(h.Src)
		evID := EvidenceID(string(LabelHasSourceAt), string(subjID), string(srcID),
			fmtTime(hsa.KnownSince), hsa.Justification, hsa.Origin, hsa.Collector, hsa.DocumentRef)
		b.addNode(evID, LabelHasSourceAt, []varve.Prop{
			{Key: "subjectId", Value: varve.Str(string(subjID))},
			{Key: "objectId", Value: varve.Str(string(srcID))},
			{Key: "knownSince", Value: varve.Str(fmtTime(hsa.KnownSince))},
			{Key: "justification", Value: varve.Str(hsa.Justification)},
			{Key: "origin", Value: varve.Str(hsa.Origin)},
			{Key: "collector", Value: varve.Str(hsa.Collector)},
			{Key: "documentRef", Value: varve.Str(hsa.DocumentRef)},
		})
		b.addEdge(subjID, EdgeHasSourceAtSubject, evID)
		b.addEdge(evID, EdgeHasSourceAtSource, srcID)
	}
}
