package assemble

import (
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/varve"
)

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

func TestMapVex(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	ks := time.Date(2021, 12, 15, 0, 0, 0, 0, time.UTC)
	preds := []assembler.IngestPredicates{{
		Vex: []assembler.VexIngest{{
			Pkg:           p1,
			Vulnerability: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "CVE-2021-44228"},
			VexData: &generated.VexStatementInputSpec{
				Status:           generated.VexStatusFixed,
				VexJustification: generated.VexJustificationComponentNotPresent,
				Statement:        "patched",
				KnownSince:       ks,
			},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	vulnID := varve.NodeID("vuln:osv/cve-2021-44228")
	evID := EvidenceID("Vex", string(subjID), string(vulnID), "FIXED", "COMPONENT_NOT_PRESENT",
		"patched", "", "2021-12-15T00:00:00Z", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no Vex node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "objectId", Value: varve.Str(string(vulnID))},
		{Key: "status", Value: varve.Str("FIXED")},
		{Key: "vexJustification", Value: varve.Str("COMPONENT_NOT_PRESENT")},
		{Key: "statement", Value: varve.Str("patched")},
		{Key: "knownSince", Value: varve.Str("2021-12-15T00:00:00Z")},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeVexSubject, evID)); !ok {
		t.Errorf("missing VexSubject edge")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeVexVulnerability, vulnID)); !ok {
		t.Errorf("missing VexVulnerability edge")
	}
}
