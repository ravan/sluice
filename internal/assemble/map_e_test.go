package assemble

import (
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/internal/varve"
)

func TestMapHasSlsa(t *testing.T) {
	preds := []assembler.IngestPredicates{{
		HasSlsa: []assembler.HasSlsaIngest{{
			Artifact:  &generated.ArtifactInputSpec{Algorithm: "sha256", Digest: "out"},
			Builder:   &generated.BuilderInputSpec{Uri: "https://ci"},
			Materials: []generated.ArtifactInputSpec{{Algorithm: "sha256", Digest: "mat1"}},
			HasSlsa: &generated.SLSAInputSpec{
				BuildType:     "github",
				SlsaVersion:   "v1",
				SlsaPredicate: []generated.SLSAPredicateInputSpec{{Key: "k", Value: "v"}},
			},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("art:sha256:out")
	bldID := varve.NodeID("bld:https://ci")
	matID := varve.NodeID("art:sha256:mat1")
	materials := joinIDs([]varve.NodeID{matID})
	predicates := "k\x1fv"
	evID := EvidenceID("HasSlsa", string(subjID), string(bldID), materials,
		"github", "v1", "", "", "", "", "", predicates)

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no HasSlsa node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "builtById", Value: varve.Str(string(bldID))},
		{Key: "builtFrom", Value: varve.Str(materials)},
		{Key: "buildType", Value: varve.Str("github")},
		{Key: "slsaVersion", Value: varve.Str("v1")},
		{Key: "predicates", Value: varve.Str(predicates)},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeHasSlsaSubject, evID)); !ok {
		t.Errorf("missing HasSlsaSubject edge")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeHasSlsaBuiltBy, bldID)); !ok {
		t.Errorf("missing HasSlsaBuiltBy edge")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeHasSlsaMaterial, matID)); !ok {
		t.Errorf("missing HasSlsaMaterial edge")
	}
	if countLabel(got, LabelBuilder) != 1 {
		t.Errorf("Builder count = %d, want 1", countLabel(got, LabelBuilder))
	}
}

func TestMapCertifyScorecard(t *testing.T) {
	preds := []assembler.IngestPredicates{{
		CertifyScorecard: []assembler.CertifyScorecardIngest{{
			Source: &generated.SourceInputSpec{Type: "git", Namespace: "github.com/x", Name: "y"},
			Scorecard: &generated.ScorecardInputSpec{
				Checks:           []generated.ScorecardCheckInputSpec{{Check: "Binary-Artifacts", Score: 10}},
				AggregateScore:   8.5,
				TimeScanned:      fixedTime,
				ScorecardVersion: "v4",
				ScorecardCommit:  "abc",
			},
		}},
	}}
	got := streamAt(t, preds)

	srcID := varve.NodeID("src:n:git/github.com/x/y@@")
	checks := "Binary-Artifacts\x1f10"
	evID := EvidenceID("CertifyScorecard", string(srcID), "v4", "abc", fixedTimeStr, "8.5", "", "", "", checks)

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no CertifyScorecard node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(srcID))},
		{Key: "aggregateScore", Value: varve.Float(8.5)},
		{Key: "timeScanned", Value: varve.Str(fixedTimeStr)},
		{Key: "scorecardVersion", Value: varve.Str("v4")},
		{Key: "scorecardCommit", Value: varve.Str("abc")},
		{Key: "checks", Value: varve.Str(checks)},
	})
	if _, ok := findEdge(got, EdgeIDFor(srcID, EdgeCertifyScorecardSubject, evID)); !ok {
		t.Errorf("missing CertifyScorecardSubject edge")
	}
	line := nodeLine(t, n)
	if !strings.Contains(line, `"aggregateScore":8.5`) {
		t.Errorf("aggregateScore not a bare float in %s", line)
	}
}

func TestMapCertifyLegal(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	preds := []assembler.IngestPredicates{{
		CertifyLegal: []assembler.CertifyLegalIngest{{
			Pkg:        p1,
			Declared:   []generated.LicenseInputSpec{{Name: "MIT"}},
			Discovered: []generated.LicenseInputSpec{{Name: "Apache-2.0"}},
			CertifyLegal: &generated.CertifyLegalInputSpec{
				DeclaredLicense:   "MIT",
				DiscoveredLicense: "Apache-2.0",
				Justification:     "scan",
				TimeScanned:       fixedTime,
			},
		}},
	}}
	got := streamAt(t, preds)

	subjID := varve.NodeID("pkg:v:golang/github.com/x/y/v1.0.0++")
	declared := joinIDs([]varve.NodeID{"lic:MIT"})
	discovered := joinIDs([]varve.NodeID{"lic:Apache-2.0"})
	evID := EvidenceID("CertifyLegal", string(subjID), "MIT", "Apache-2.0", "", "scan", fixedTimeStr,
		"", "", "", declared, discovered)

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no CertifyLegal node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "subjectId", Value: varve.Str(string(subjID))},
		{Key: "declaredLicense", Value: varve.Str("MIT")},
		{Key: "discoveredLicense", Value: varve.Str("Apache-2.0")},
		{Key: "justification", Value: varve.Str("scan")},
		{Key: "timeScanned", Value: varve.Str(fixedTimeStr)},
		{Key: "declaredLicenses", Value: varve.Str(declared)},
		{Key: "discoveredLicenses", Value: varve.Str(discovered)},
	})
	if _, ok := findEdge(got, EdgeIDFor(subjID, EdgeCertifyLegalSubject, evID)); !ok {
		t.Errorf("missing CertifyLegalSubject edge")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeCertifyLegalDeclaredLicense, "lic:MIT")); !ok {
		t.Errorf("missing CertifyLegalDeclaredLicense edge")
	}
	if _, ok := findEdge(got, EdgeIDFor(evID, EdgeCertifyLegalDiscoveredLicense, "lic:Apache-2.0")); !ok {
		t.Errorf("missing CertifyLegalDiscoveredLicense edge")
	}
}
