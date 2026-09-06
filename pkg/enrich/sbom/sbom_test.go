package sbom

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

const cycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {"component": {"type": "application", "name": "object-store", "purl": "pkg:generic/object-store@2.0.0", "supplier": {"name": "Acme GmbH"}}},
  "components": [
    {"type": "library", "name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3", "supplier": {"name": "Nordwind Software AG"}},
    {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
  ]
}`

const cycloneDXNested = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {"type": "library", "name": "outer", "purl": "pkg:npm/outer@1.0.0", "components": [
      {"type": "library", "name": "inner", "purl": "pkg:npm/inner@2.0.0", "supplier": {"name": "Inner Works Ltd"}}
    ]}
  ]
}`

const spdx = `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentDescribes": ["SPDXRef-Root"],
  "packages": [
    {"SPDXID": "SPDXRef-Root", "name": "root", "supplier": "Organization: Acme GmbH (ops@acme.example)",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/root@1.0.0"}]},
    {"SPDXID": "SPDXRef-serde", "name": "serde", "supplier": "Organization: Crabline Software Oy (hello@crabline.example)",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:cargo/serde@1.0.203"}]}
  ]
}`

const openVEX = `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://acme.example/vex/1", "statements": []}`

func TestSuppliers(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want map[string]string
	}{
		{"cyclonedx skips the root component", cycloneDX, map[string]string{"pkg:pypi/requests@2.32.3": "Nordwind Software AG"}},
		{"cyclonedx reads a nested component", cycloneDXNested, map[string]string{"pkg:npm/inner@2.0.0": "Inner Works Ltd"}},
		{"spdx skips the described package", spdx, map[string]string{"pkg:cargo/serde@1.0.203": "Crabline Software Oy"}},
		{"openvex states no supplier", openVEX, map[string]string{}},
		{"bytes that are not json", "not json", map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Suppliers([]byte(tc.doc))
			if len(got) != len(tc.want) {
				t.Fatalf("Suppliers() = %v, want %v", got, tc.want)
			}
			for purl, name := range tc.want {
				if got[purl] != name {
					t.Errorf("Suppliers()[%q] = %q, want %q", purl, got[purl], name)
				}
			}
		})
	}
}

func TestSupplierName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Organization: Acme GmbH (ops@acme.example)", "Acme GmbH"},
		{"Person: Jane Doe", "Jane Doe"},
		{"NOASSERTION", ""},
		{"NONE", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := SupplierName(tc.in); got != tc.want {
				t.Errorf("SupplierName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

var (
	pkgValidFrom = time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	testNow      = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
)

func testPkgNode(id, purl string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:        varve.NodeID(id),
		Labels:    []varve.NodeLabel{assemble.LabelPkgVersion},
		Props:     []varve.Prop{{Key: assemble.PropPurl, Value: varve.Str(purl)}},
		ValidFrom: pkgValidFrom,
	}
}

func TestEnrich(t *testing.T) {
	stream := varve.Stream{Nodes: []varve.NodeRecord{
		testPkgNode("pkg:requests", "pkg:pypi/requests@2.32.3"),
		testPkgNode("pkg:lodash", "pkg:npm/lodash@4.17.21"),
	}}
	e := New()
	if got := e.Source(); got != enrich.SourceSBOM {
		t.Fatalf("Source() = %q, want %q", got, enrich.SourceSBOM)
	}

	got, err := e.Enrich(context.Background(), enrich.Input{Digest: "abc", Records: stream, Document: []byte(cycloneDX), Now: testNow})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	want := []enrich.Claim{{
		Source:    enrich.SourceSBOM,
		Subject:   "pkg:requests",
		Fact:      enrich.FactSupplier,
		Value:     "Nordwind Software AG",
		Ref:       "abc",
		ValidFrom: pkgValidFrom,
		FetchedAt: testNow,
	}}
	if len(got) != len(want) {
		t.Fatalf("Enrich() returned %d claims, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("claim %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	empty := varve.Stream{Nodes: []varve.NodeRecord{testPkgNode("pkg:lodash", "pkg:npm/lodash@4.17.21")}}
	claims, err := e.Enrich(context.Background(), enrich.Input{Digest: "abc", Records: empty, Document: []byte(cycloneDX), Now: testNow})
	if err != nil {
		t.Fatalf("Enrich without the supplier's node: %v", err)
	}
	if len(claims) != 0 {
		t.Errorf("Enrich() returned %d claims for a purl the stream has no node for, want 0", len(claims))
	}

	claims, err = e.Enrich(context.Background(), enrich.Input{Digest: "abc", Records: stream, Now: testNow})
	if err != nil {
		t.Fatalf("Enrich without a document: %v", err)
	}
	if len(claims) != 0 {
		t.Errorf("Enrich() returned %d claims for a nil Document, want 0", len(claims))
	}
}
