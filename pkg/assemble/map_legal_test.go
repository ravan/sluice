package assemble

import (
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/varve"
)

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
