package assemble

import (
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/varve"
)

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

func TestMapIsOccurrencePackageSubject(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	preds := []assembler.IngestPredicates{{
		IsOccurrence: []assembler.IsOccurrenceIngest{{
			Pkg:          p1,
			Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha256", Digest: "abc"},
			IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "occ"},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	artID := varve.NodeID("art:sha256:abc")
	evID := EvidenceID("IsOccurrence", string(subjID), string(artID), "occ", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no IsOccurrence node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "objectId", Value: varve.Str(string(artID))},
		{Key: "justification", Value: varve.Str("occ")},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeIsOccurrenceSubject, evID)); !ok {
		t.Errorf("missing IsOccurrenceSubject edge from PkgVersion")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeIsOccurrenceArtifact, artID)); !ok {
		t.Errorf("missing IsOccurrenceArtifact edge")
	}
}

func TestMapIsOccurrenceSourceSubject(t *testing.T) {
	src := &generated.SourceInputSpec{Type: "git", Namespace: "github.com/x", Name: "y"}
	preds := []assembler.IngestPredicates{{
		IsOccurrence: []assembler.IsOccurrenceIngest{{
			Src:          src,
			Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha256", Digest: "def"},
			IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "srcocc"},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("src:n:git/github.com/x/y@@")
	artID := varve.NodeID("art:sha256:def")
	evID := EvidenceID("IsOccurrence", string(subjID), string(artID), "srcocc", "", "", "")

	if _, ok := findNode(got, evID); !ok {
		t.Fatalf("no IsOccurrence node with source subject; got:\n%s", ndjson(t, got))
	}
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeIsOccurrenceSubject, evID)); !ok {
		t.Errorf("missing IsOccurrenceSubject edge from SrcName %s", subjID)
	}
	if countLabel(got, LabelSrcName) != 1 {
		t.Errorf("SrcName count = %d, want 1", countLabel(got, LabelSrcName))
	}
}

func TestMapHasSBOM(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	ks := time.Date(2020, 11, 24, 1, 12, 27, 0, time.UTC)
	preds := []assembler.IngestPredicates{{
		HasSBOM: []assembler.HasSBOMIngest{{
			Pkg: p1,
			HasSBOM: &generated.HasSBOMInputSpec{
				Uri:              "http://sbom",
				Algorithm:        "sha256",
				Digest:           "xyz",
				DownloadLocation: "http://dl",
				KnownSince:       ks,
			},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	evID := EvidenceID("HasSBOM", string(subjID), "http://sbom", "sha256", "xyz", "http://dl",
		"2020-11-24T01:12:27Z", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no HasSBOM node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	// Empty Includes → all three included* props omitted.
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "uri", Value: varve.Str("http://sbom")},
		{Key: "algorithm", Value: varve.Str("sha256")},
		{Key: "digest", Value: varve.Str("xyz")},
		{Key: "downloadLocation", Value: varve.Str("http://dl")},
		{Key: "knownSince", Value: varve.Str("2020-11-24T01:12:27Z")},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeHasSbomSubject, evID)); !ok {
		t.Errorf("missing HasSbomSubject edge")
	}
	// No object edge for HasSBOM.
	if len(got.Edges) != 2 { // PkgHasVersion + HasSbomSubject
		t.Errorf("edge count = %d, want 2 (PkgHasVersion + HasSbomSubject)", len(got.Edges))
	}
}
