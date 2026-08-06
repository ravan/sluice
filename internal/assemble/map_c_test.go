package assemble

import (
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/internal/varve"
)

var fixedTime = time.Date(2023, 5, 6, 7, 8, 9, 0, time.UTC)

const fixedTimeStr = "2023-05-06T07:08:09Z"

func TestMapCertifyBadArtifactSubject(t *testing.T) {
	preds := []assembler.IngestPredicates{{
		CertifyBad: []assembler.CertifyBadIngest{{
			Artifact:   &generated.ArtifactInputSpec{Algorithm: "sha256", Digest: "bad"},
			CertifyBad: &generated.CertifyBadInputSpec{Justification: "malware", KnownSince: fixedTime},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("art:sha256:bad")
	evID := EvidenceID("CertifyBad", string(subjID), fixedTimeStr, "malware", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no CertifyBad node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "justification", Value: varve.Str("malware")},
		{Key: "knownSince", Value: varve.Str(fixedTimeStr)},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeCertifyBadSubject, evID)); !ok {
		t.Errorf("missing CertifyBadSubject edge from Artifact")
	}
	if countLabel(got, LabelArtifact) != 1 {
		t.Errorf("Artifact count = %d, want 1", countLabel(got, LabelArtifact))
	}
}

func TestMapCertifyGoodPackageSubject(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	preds := []assembler.IngestPredicates{{
		CertifyGood: []assembler.CertifyGoodIngest{{
			Pkg:         p1,
			CertifyGood: &generated.CertifyGoodInputSpec{Justification: "trusted", KnownSince: fixedTime},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	evID := EvidenceID("CertifyGood", string(subjID), fixedTimeStr, "trusted", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no CertifyGood node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "justification", Value: varve.Str("trusted")},
		{Key: "knownSince", Value: varve.Str(fixedTimeStr)},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeCertifyGoodSubject, evID)); !ok {
		t.Errorf("missing CertifyGoodSubject edge")
	}
}

func TestMapHasMetadataSourceSubject(t *testing.T) {
	src := &generated.SourceInputSpec{Type: "git", Namespace: "github.com/x", Name: "y"}
	preds := []assembler.IngestPredicates{{
		HasMetadata: []assembler.HasMetadataIngest{{
			Src:         src,
			HasMetadata: &generated.HasMetadataInputSpec{Key: "topic", Value: "security", Timestamp: fixedTime, Justification: "tag"},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("src:n:git/github.com/x/y@@")
	evID := EvidenceID("HasMetadata", string(subjID), "topic", "security", fixedTimeStr, "tag", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no HasMetadata node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "key", Value: varve.Str("topic")},
		{Key: "value", Value: varve.Str("security")},
		{Key: "timestamp", Value: varve.Str(fixedTimeStr)},
		{Key: "justification", Value: varve.Str("tag")},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeHasMetadataSubject, evID)); !ok {
		t.Errorf("missing HasMetadataSubject edge from SrcName")
	}
}

func TestMapPointOfContactPackageAllVersions(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	preds := []assembler.IngestPredicates{{
		PointOfContact: []assembler.PointOfContactIngest{{
			Pkg:            p1,
			PkgMatchFlag:   generated.MatchFlags{Pkg: generated.PkgMatchTypeAllVersions},
			PointOfContact: &generated.PointOfContactInputSpec{Email: "a@b", Info: "maintainer", Since: fixedTime, Justification: "owner"},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:n:golang/github.com/x/y")
	evID := EvidenceID("PointOfContact", string(subjID), "a@b", "maintainer", fixedTimeStr, "owner", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no PointOfContact node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "email", Value: varve.Str("a@b")},
		{Key: "info", Value: varve.Str("maintainer")},
		{Key: "since", Value: varve.Str(fixedTimeStr)},
		{Key: "justification", Value: varve.Str("owner")},
	})
	// ALL_VERSIONS → subject edge starts at PkgName.
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgePointOfContactSubject, evID)); !ok {
		t.Errorf("missing PointOfContactSubject edge from PkgName %s", subjID)
	}
}
