package assemble

import (
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/internal/varve"
)

func countLabel(s varve.Stream, label varve.NodeLabel) int {
	n := 0
	for _, nd := range s.Nodes {
		for _, l := range nd.Labels {
			if l == label {
				n++
			}
		}
	}
	return n
}

func findEdge(s varve.Stream, id varve.EdgeID) (varve.EdgeRecord, bool) {
	for _, e := range s.Edges {
		if e.ID == id {
			return e, true
		}
	}
	return varve.EdgeRecord{}, false
}

func nodeLine(t *testing.T, n varve.NodeRecord) string {
	t.Helper()
	return ndjson(t, varve.Stream{Nodes: []varve.NodeRecord{n}})
}

func TestMapIsDependency(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	p2 := &generated.PkgInputSpec{Type: "npm", Namespace: nil, Name: "left-pad", Version: ptr("1.3.0")}
	preds := []assembler.IngestPredicates{{
		IsDependency: []assembler.IsDependencyIngest{{
			Pkg: p1, DepPkg: p2,
			IsDependency: &generated.IsDependencyInputSpec{DependencyType: "DIRECT", Justification: "dep"},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	objID := varve.NodeID("pkg:v:npm//left-pad/1.3.0++")
	evID := EvidenceID("IsDependency", string(subjID), string(objID), "DIRECT", "dep", "", "", "")

	if c := countLabel(got, LabelIsDependency); c != 1 {
		t.Fatalf("IsDependency node count = %d, want 1", c)
	}
	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no IsDependency node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	wantProps := []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "objectId", Value: varve.Str(string(objID))},
		{Key: "dependencyType", Value: varve.Str("DIRECT")},
		{Key: "justification", Value: varve.Str("dep")},
	}
	assertProps(t, n, wantProps)

	wantLine := `{"type":"node","labels":["IsDependency"],"props":{"_id":"` + string(evID) +
		`","subjectId":"` + string(subjID) + `","objectId":"` + string(objID) +
		`","dependencyType":"DIRECT","justification":"dep"},"valid_from":"2026-08-07T00:00:00Z"}` + "\n"
	if got := nodeLine(t, n); got != wantLine {
		t.Errorf("IsDependency node wire bytes\n got: %s\nwant: %s", got, wantLine)
	}

	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeIsDependencySubject, evID)); !ok {
		t.Errorf("missing IsDependencySubject edge %s -> %s", subjID, evID)
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeIsDependencyObject, objID)); !ok {
		t.Errorf("missing IsDependencyObject edge %s -> %s", evID, objID)
	}
	// p1/p2 identity present.
	if countLabel(got, LabelPkgVersion) != 2 || countLabel(got, LabelPkgName) != 2 {
		t.Errorf("package identity: %d PkgVersion / %d PkgName, want 2 / 2", countLabel(got, LabelPkgVersion), countLabel(got, LabelPkgName))
	}
}

func TestMapCertifyVuln(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	preds := []assembler.IngestPredicates{{
		CertifyVuln: []assembler.CertifyVulnIngest{{
			Pkg:           p1,
			Vulnerability: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "CVE-2021-44228"},
			VulnData: &generated.ScanMetadataInput{
				TimeScanned:    time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC),
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.1",
			},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	vulnID := varve.NodeID("vuln:osv/cve-2021-44228")
	evID := EvidenceID("CertifyVuln", string(subjID), string(vulnID),
		"2021-12-10T10:15:00Z", "", "", "osv.dev", "0.1", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no CertifyVuln node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	wantProps := []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "objectId", Value: varve.Str(string(vulnID))},
		{Key: "timeScanned", Value: varve.Str("2021-12-10T10:15:00Z")},
		{Key: "scannerUri", Value: varve.Str("osv.dev")},
		{Key: "scannerVersion", Value: varve.Str("0.1")},
	}
	assertProps(t, n, wantProps)

	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeCertifyVulnSubject, evID)); !ok {
		t.Errorf("missing CertifyVulnSubject edge")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeCertifyVulnVulnerability, vulnID)); !ok {
		t.Errorf("missing CertifyVulnVulnerability edge")
	}
}

func TestMapHasSourceAt(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	src := &generated.SourceInputSpec{Type: "git", Namespace: "github.com/x", Name: "y", Tag: ptr("v1"), Commit: ptr("abc")}
	preds := []assembler.IngestPredicates{{
		HasSourceAt: []assembler.HasSourceAtIngest{{
			Pkg:          p1,
			PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeAllVersions},
			Src:          src,
			HasSourceAt:  &generated.HasSourceAtInputSpec{KnownSince: time.Date(2022, 1, 2, 3, 4, 5, 0, time.UTC), Justification: "found"},
		}},
	}}
	got := streamAt(t, preds)

	nameID := varve.NodeID("pkg:n:golang/github.com/x/y")
	srcID := varve.NodeID("src:n:git/github.com/x/y@v1@abc")
	evID := EvidenceID("HasSourceAt", string(nameID), string(srcID),
		"2022-01-02T03:04:05Z", "found", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no HasSourceAt node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	wantProps := []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(nameID))},
		{Key: "objectId", Value: varve.Str(string(srcID))},
		{Key: "knownSince", Value: varve.Str("2022-01-02T03:04:05Z")},
		{Key: "justification", Value: varve.Str("found")},
	}
	assertProps(t, n, wantProps)

	// ALL_VERSIONS → subject edge starts at the PkgName id.
	if _, ok := findEdge(got, EdgeIDFor(nameID, EdgeHasSourceAtSubject, evID)); !ok {
		t.Errorf("missing HasSourceAtSubject edge from PkgName %s", nameID)
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeHasSourceAtSource, srcID)); !ok {
		t.Errorf("missing HasSourceAtSource edge to %s", srcID)
	}
}
