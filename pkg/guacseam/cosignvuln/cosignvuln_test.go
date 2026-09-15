package cosignvuln_test

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/logging"

	"github.com/ravan/sluice/pkg/guacseam/cosignvuln"
)

const fixture = "../../../testdata/cosignvuln/alertmanager-0-0.34.0.x86_64-21.8.trivy_vuln.intoto.json"

// withSubject is a statement the way OBS should write it: the image purl in
// name and its manifest digest, one finding with two CVSS sources.
const withSubject = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cosign.sigstore.dev/attestation/vuln/v1",
  "subject": [{"name": "pkg:oci/alertmanager?repository_url=dp.apps.rancher.io/containers&arch=amd64",
               "digest": {"sha256": "AB12"}}],
  "predicate": {
    "scanner": {"uri": "pkg:github/aquasecurity/trivy@0.74.0", "version": "0.74.0",
                "db": {"uri": "", "version": ""},
                "result": {"SchemaVersion": 2, "CreatedAt": "2026-09-11T11:58:17Z", "Results": [
                  {"Target": "usr/bin/alertmanager", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-56854", "VendorIDs": ["GO-2026-6303"],
                     "PkgName": "golang.org/x/crypto", "InstalledVersion": "v0.54.0",
                     "PkgIdentifier": {"PURL": "pkg:golang/golang.org/x/crypto@v0.54.0"},
                     "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N", "V3Score": 9.1, "V2Score": 7.5},
                              "redhat": {"V3Vector": "CVSS:3.0/AV:N", "V3Score": 9.1}}}]},
                  {"Target": "usr/bin/amtool", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-56854", "VendorIDs": ["GO-2026-6303"],
                     "PkgName": "golang.org/x/crypto", "InstalledVersion": "v0.54.0",
                     "PkgIdentifier": {"PURL": "pkg:golang/golang.org/x/crypto@v0.54.0"}}]}]}},
    "metadata": {"scanStartedOn": "2026-09-01T22:36:29Z", "scanFinishedOn": "2026-09-01T22:36:30Z"}
  }
}`

// clean is a scan with a subject and no finding.
const clean = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cosign.sigstore.dev/attestation/vuln/v1",
  "subject": [{"name": "pkg:oci/alertmanager", "digest": {"sha256": "ab12"}}],
  "predicate": {"scanner": {"uri": "trivy", "version": "1", "result": {"Results": []}},
                "metadata": {"scanFinishedOn": "2026-09-01T22:36:30Z"}}
}`

// parse runs blob through GUAC's process and parse stages the way the seam
// does, after Classify, and returns the one predicate set.
func parse(t *testing.T, blob []byte) assembler.IngestPredicates {
	t.Helper()
	ctx := context.Background()
	doc := &processor.Document{Blob: blob, Type: processor.DocumentUnknown, Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{Collector: "test", Source: "file:test", DocumentRef: "ref"}}
	if !cosignvuln.Classify(doc) {
		t.Fatal("Classify = false, want true")
	}
	collector.AddChildLogger(logging.FromContext(ctx), doc)
	tree, err := process.Process(ctx, doc)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	preds, _, err := parser.ParseDocumentTree(ctx, tree, false, false, false, false)
	if err != nil {
		t.Fatalf("ParseDocumentTree: %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("predicate sets = %d, want 1", len(preds))
	}
	return preds[0]
}

func certified(p assembler.IngestPredicates) []string {
	var out []string
	for _, c := range p.CertifyVuln {
		out = append(out, helpers.PkgInputSpecToPurl(c.Pkg)+" "+c.Vulnerability.Type+"/"+c.Vulnerability.VulnerabilityID)
	}
	sort.Strings(out)
	return out
}

func equal(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

func TestParseOBSFixture(t *testing.T) {
	blob, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, blob)

	// The empty OBS subject yields nothing; both findings attach to the package.
	equal(t, "CertifyVuln", certified(p), []string{
		"pkg:golang/golang.org/x/crypto@v0.54.0 cve/cve-2026-56854",
		"pkg:golang/golang.org/x/crypto@v0.54.0 go/go-2026-5932",
	})
	if len(p.IsOccurrence) != 0 {
		t.Errorf("IsOccurrence = %d, want 0 for an empty subject", len(p.IsOccurrence))
	}
	if len(p.VulnEqual) != 1 || p.VulnEqual[0].EqualVulnerability.VulnerabilityID != "go-2026-6303" {
		t.Errorf("VulnEqual = %+v, want one alias go-2026-6303", p.VulnEqual)
	}
	if len(p.VulnMetadata) != 0 {
		t.Errorf("VulnMetadata = %d, want 0: the fixture carries no CVSS", len(p.VulnMetadata))
	}
	vd := p.CertifyVuln[0].VulnData
	want := time.Date(2026, 9, 1, 22, 36, 29, 575057273, time.UTC)
	if !vd.TimeScanned.Equal(want) {
		t.Errorf("TimeScanned = %v, want %v", vd.TimeScanned, want)
	}
	if vd.ScannerUri != "pkg:github/aquasecurity/trivy@0.74.0" || vd.ScannerVersion != "0.74.0" {
		t.Errorf("scanner = %q %q", vd.ScannerUri, vd.ScannerVersion)
	}
	if vd.Origin != "file:test" || vd.Collector != "test" || vd.DocumentRef != "ref" {
		t.Errorf("source information not applied: %+v", vd)
	}
}

func TestParseSubjectAndScores(t *testing.T) {
	p := parse(t, []byte(withSubject))

	// The finding certifies its package and the subject; the second target
	// repeats it and adds nothing.
	equal(t, "CertifyVuln", certified(p), []string{
		"pkg:golang/golang.org/x/crypto@v0.54.0 cve/cve-2026-56854",
		"pkg:oci/alertmanager?arch=amd64&repository_url=dp.apps.rancher.io%2Fcontainers cve/cve-2026-56854",
	})
	if len(p.IsOccurrence) != 1 {
		t.Fatalf("IsOccurrence = %d, want 1", len(p.IsOccurrence))
	}
	art := p.IsOccurrence[0].Artifact
	if art.Algorithm != "sha256" || art.Digest != "ab12" {
		t.Errorf("artifact = %+v, want sha256/ab12 lowercased", art)
	}
	if len(p.VulnEqual) != 1 {
		t.Errorf("VulnEqual = %d, want 1 after de-duplication", len(p.VulnEqual))
	}
	var scores []string
	for _, m := range p.VulnMetadata {
		scores = append(scores, string(m.VulnMetadata.ScoreType))
		if !m.VulnMetadata.Timestamp.Equal(time.Date(2026, 9, 1, 22, 36, 30, 0, time.UTC)) {
			t.Errorf("score timestamp = %v, want scanFinishedOn", m.VulnMetadata.Timestamp)
		}
	}
	// nvd: v2 then v3.1; redhat: v3.0 with the same value, a different type.
	equal(t, "score types", scores, []string{"CVSSv2", "CVSSv31", "CVSSv3"})
}

func TestParseCleanScanCertifiesNoVuln(t *testing.T) {
	p := parse(t, []byte(clean))
	equal(t, "CertifyVuln", certified(p), []string{"pkg:oci/alertmanager noVuln/"})
}

func TestClassifyLeavesOtherDocumentsAlone(t *testing.T) {
	cdx := &processor.Document{Blob: []byte(`{"bomFormat":"CycloneDX"}`), Type: processor.DocumentUnknown}
	if cosignvuln.Classify(cdx) || cdx.Type != processor.DocumentUnknown {
		t.Error("a CycloneDX document was classified")
	}
	typed := &processor.Document{Blob: []byte(withSubject), Type: processor.DocumentITE6Generic}
	if cosignvuln.Classify(typed) || typed.Type != processor.DocumentITE6Generic {
		t.Error("an already typed document was re-typed")
	}
	other := &processor.Document{Blob: []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`)}
	if cosignvuln.Classify(other) {
		t.Error("an SLSA statement was classified")
	}
}

func TestProcessorRejectsWrongType(t *testing.T) {
	err := cosignvuln.Processor{}.ValidateSchema(&processor.Document{Blob: []byte(withSubject), Type: processor.DocumentITE6Vul})
	if err == nil {
		t.Error("ValidateSchema accepted an ITE6VUL document")
	}
	bad := &processor.Document{Blob: []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://cosign.sigstore.dev/attestation/vuln/v1","subject":[{"name":"pkg:"}],"predicate":{}}`), Format: processor.FormatUnknown}
	cosignvuln.Classify(bad)
	collector.AddChildLogger(logging.FromContext(context.Background()), bad)
	if _, err := process.Process(context.Background(), bad); err != nil {
		t.Fatalf("Process: %v", err)
	}
	parsed := cosignvuln.NewParser()
	if err := parsed.Parse(context.Background(), bad); err == nil {
		t.Error("Parse accepted a subject purl that does not parse")
	}
}
