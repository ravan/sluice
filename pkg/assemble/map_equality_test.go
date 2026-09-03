package assemble

import (
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/varve"
)

func TestMapHashEqual(t *testing.T) {
	a := &generated.ArtifactInputSpec{Algorithm: "sha256", Digest: "aaa"}
	e := &generated.ArtifactInputSpec{Algorithm: "sha256", Digest: "bbb"}
	preds := []assembler.IngestPredicates{{
		HashEqual: []assembler.HashEqualIngest{{
			Artifact:      a,
			EqualArtifact: e,
			HashEqual:     &generated.HashEqualInputSpec{Justification: "same"},
		}},
	}}
	got := streamAt(t, preds)

	members := sortedIDs([]varve.NodeID{"art:sha256:aaa", "art:sha256:bbb"})
	joined := joinIDs(members)
	evID := EvidenceID("HashEqual", joined, "same", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no HashEqual node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "members", Value: varve.Str(joined)},
		{Key: "justification", Value: varve.Str("same")},
	})
	for _, m := range members {
		if _, ok := findEdge(got, EdgeIDFor(evID, EdgeHashEqualArtifact, m)); !ok {
			t.Errorf("missing HashEqualArtifact edge to %s", m)
		}
	}

	// Symmetric: swapping the two artifacts yields the same evidence id.
	swapped := streamAt(t, []assembler.IngestPredicates{{
		HashEqual: []assembler.HashEqualIngest{{
			Artifact:      e,
			EqualArtifact: a,
			HashEqual:     &generated.HashEqualInputSpec{Justification: "same"},
		}},
	}})
	if _, ok := findNode(swapped, evID); !ok {
		t.Errorf("HashEqual id not symmetric under artifact swap")
	}
}

func TestMapPkgEqual(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	p2 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v2.0.0")}
	preds := []assembler.IngestPredicates{{
		PkgEqual: []assembler.PkgEqualIngest{{
			Pkg:      p1,
			EqualPkg: p2,
			PkgEqual: &generated.PkgEqualInputSpec{Justification: "alias"},
		}},
	}}
	got := streamAt(t, preds)

	members := sortedIDs([]varve.NodeID{"pkg:v:golang/github.com/x/y/v1.0.0++", "pkg:v:golang/github.com/x/y/v2.0.0++"})
	joined := joinIDs(members)
	evID := EvidenceID("PkgEqual", joined, "alias", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no PkgEqual node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "members", Value: varve.Str(joined)},
		{Key: "justification", Value: varve.Str("alias")},
	})
	for _, m := range members {
		if _, ok := findEdge(got, EdgeIDFor(evID, EdgePkgEqualPackage, m)); !ok {
			t.Errorf("missing PkgEqualPackage edge to %s", m)
		}
	}
}

func TestMapVulnEqual(t *testing.T) {
	preds := []assembler.IngestPredicates{{
		VulnEqual: []assembler.VulnEqualIngest{{
			Vulnerability:      &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "GHSA-x"},
			EqualVulnerability: &generated.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "CVE-x"},
			VulnEqual:          &generated.VulnEqualInputSpec{Justification: "same-vuln"},
		}},
	}}
	got := streamAt(t, preds)

	members := sortedIDs([]varve.NodeID{"vuln:osv/ghsa-x", "vuln:cve/cve-x"})
	joined := joinIDs(members)
	evID := EvidenceID("VulnEqual", joined, "same-vuln", "", "", "")

	n, ok := findNode(got, evID)
	if !ok {
		t.Fatalf("no VulnEqual node with id %q; got:\n%s", evID, ndjson(t, got))
	}
	assertProps(t, n, []varve.Prop{
		{Key: "members", Value: varve.Str(joined)},
		{Key: "justification", Value: varve.Str("same-vuln")},
	})
	for _, m := range members {
		if _, ok := findEdge(got, EdgeIDFor(evID, EdgeVulnEqualVulnerability, m)); !ok {
			t.Errorf("missing VulnEqualVulnerability edge to %s", m)
		}
	}
}
