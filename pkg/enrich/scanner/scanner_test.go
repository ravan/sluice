package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// fixture is a real OBS attestation from the SUSE Application Collection, with
// each Result's Packages list and the image config dropped: 135 KB of package
// inventory nothing here reads. Every vulnerability, score and date is the
// scanner's own.
const fixture = "../../../testdata/scanner/metallb-configmaptocrs-0-0.16.1.x86_64-24.12.trivy_vuln.intoto.json"

func doc(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(fixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// vulnNode is the Vulnerability node the parser writes for one finding.
func vulnNode(typ, id string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:     assemble.VulnID(typ, id),
		Labels: []varve.NodeLabel{assemble.LabelVulnerability},
		Props: []varve.Prop{
			{Key: "type", Value: varve.Str(strings.ToLower(typ))},
			{Key: "vulnID", Value: varve.Str(strings.ToLower(id))},
		},
	}
}

func stream() varve.Stream {
	return varve.Stream{Nodes: []varve.NodeRecord{
		vulnNode("cve", "CVE-2026-46600"),
		vulnNode("cve", "CVE-2026-56852"),
	}}
}

func enriched(t *testing.T) []enrich.Claim {
	t.Helper()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	got, err := New().Enrich(context.Background(), enrich.Input{
		Digest: "sha256:test", Records: stream(), Document: doc(t), Now: now,
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	return got
}

// only returns the single claim with this subject and fact, failing otherwise.
func only(t *testing.T, claims []enrich.Claim, id, fact string) enrich.Claim {
	t.Helper()
	var found []enrich.Claim
	for _, c := range claims {
		if string(c.Subject) == string(assemble.VulnID("cve", id)) && string(c.Fact) == fact {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s %s: %d claims, want 1", id, fact, len(found))
	}
	return found[0]
}

func TestEnrichStatesWhatTheScanSaid(t *testing.T) {
	got := enriched(t)

	// The description GUAC's vocabulary has nowhere to put.
	d := only(t, got, "CVE-2026-46600", "description")
	want := "golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing"
	if d.Value != want {
		t.Errorf("description = %q, want %q", d.Value, want)
	}
	if d.Source != enrich.SourceScanner {
		t.Errorf("source = %q, want %q", d.Source, enrich.SourceScanner)
	}
	if d.Ref != "govulndb" {
		t.Errorf("ref = %q, want the database the scanner credited", d.Ref)
	}

	// The score, its version and the vector VulnMetadata drops.
	if c := only(t, got, "CVE-2026-46600", "cvss"); c.Value != "7.5" {
		t.Errorf("cvss = %q, want 7.5", c.Value)
	}
	if c := only(t, got, "CVE-2026-46600", "cvss_version"); c.Value != "3.1" {
		t.Errorf("cvss_version = %q, want 3.1", c.Value)
	}
	if c := only(t, got, "CVE-2026-46600", "cvss_vector"); c.Value != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Errorf("cvss_vector = %q", c.Value)
	}
	if c := only(t, got, "CVE-2026-46600", "fixed_by"); c.Value != "0.56.0" {
		t.Errorf("fixed_by = %q, want 0.56.0", c.Value)
	}

	// valid_from is the advisory's own date, not the day the image was built.
	c := only(t, got, "CVE-2026-56852", "description")
	if w := time.Date(2026, 7, 23, 18, 27, 48, 877_000_000, time.UTC); !c.ValidFrom.Equal(w) {
		t.Errorf("valid_from = %s, want the LastModifiedDate %s", c.ValidFrom, w)
	}
	// fetched_at is when the scanner ran, which is when it read the database.
	if w := time.Date(2026, 9, 4, 22, 42, 35, 16_403_708, time.UTC); !c.FetchedAt.Equal(w) {
		t.Errorf("fetched_at = %s, want the scan time %s", c.FetchedAt, w)
	}
}

// TestEnrichSkipsUnknownVulnerabilities holds the rule that a claim never
// points at a node nothing else wrote: the ABOUT edge would dangle.
func TestEnrichSkipsUnknownVulnerabilities(t *testing.T) {
	got, err := New().Enrich(context.Background(), enrich.Input{
		Records:  varve.Stream{Nodes: []varve.NodeRecord{vulnNode("cve", "CVE-2026-46600")}},
		Document: doc(t),
		Now:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	for _, c := range got {
		if c.Subject != assemble.VulnID("cve", "CVE-2026-46600") {
			t.Errorf("claim about %q, want only the vulnerability the stream carries", c.Subject)
		}
	}
	if len(got) == 0 {
		t.Fatal("no claims at all, want the ones about the node that is there")
	}
}

// TestEnrichIgnoresOtherDocuments: every enricher sees every document, so
// anything that is not a scan attestation must be silent rather than an error.
func TestEnrichIgnoresOtherDocuments(t *testing.T) {
	for _, blob := range [][]byte{
		nil,
		[]byte("not json at all"),
		[]byte(`{"bomFormat":"CycloneDX","components":[]}`),
		[]byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`),
	} {
		got, err := New().Enrich(context.Background(), enrich.Input{
			Records: stream(), Document: blob, Now: time.Now().UTC(),
		})
		if err != nil {
			t.Errorf("Enrich(%.30q): %v", blob, err)
		}
		if len(got) != 0 {
			t.Errorf("Enrich(%.30q) = %d claims, want none", blob, len(got))
		}
	}
}

func TestSource(t *testing.T) {
	if got := New().Source(); got != enrich.SourceScanner {
		t.Errorf("Source() = %q, want %q", got, enrich.SourceScanner)
	}
}

// TestScoreFactsZeroIsAbsent: Trivy leaves a score it has no value for at
// zero, and 0.0 is itself a CVSS score. Reading it as absent is the safe half
// of an ambiguity the document does not resolve.
func TestScoreFactsZeroIsAbsent(t *testing.T) {
	if got := scoreFacts("nvd", cvss{}); got != nil {
		t.Errorf("scoreFacts with no score = %+v, want none", got)
	}
	got := scoreFacts("nvd", cvss{V2Score: 5, V2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"})
	if len(got) != 3 || got[0].value != "5" || got[1].value != "2.0" {
		t.Errorf("scoreFacts fell back wrong: %+v", got)
	}
}

// TestScoreFactsNewestVersionWins: a database that gave both a v3 and a v4
// score states one cvss fact, the newest, so two databases compared side by
// side are speaking the same version wherever they can.
func TestScoreFactsNewestVersionWins(t *testing.T) {
	got := scoreFacts("ghsa", cvss{
		V3Score: 8.1, V3Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		V40Score: 8.7, V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
	})
	if len(got) != 3 || got[0].value != "8.7" || got[1].value != "4.0" {
		t.Errorf("scoreFacts = %+v, want the 4.0 score", got)
	}
	got = scoreFacts("ghsa", cvss{V3Score: 8.1, V3Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"})
	if len(got) != 3 || got[1].value != "3.0" {
		t.Errorf("scoreFacts = %+v, want the version read off the vector", got)
	}
}
