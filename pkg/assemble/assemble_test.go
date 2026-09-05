package assemble

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

func ptr(s string) *string { return &s }

var testNow = time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

func streamAt(t *testing.T, preds []assembler.IngestPredicates) varve.Stream {
	t.Helper()
	return Assemble(context.Background(), preds, validtime.Default(), testNow).Stream
}

func ndjson(t *testing.T, s varve.Stream) string {
	t.Helper()
	var b strings.Builder
	if err := varve.WriteNDJSON(&b, s); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	return b.String()
}

func findNode(s varve.Stream, id varve.NodeID) (varve.NodeRecord, bool) {
	for _, n := range s.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return varve.NodeRecord{}, false
}

func assertProps(t *testing.T, n varve.NodeRecord, want []varve.Prop) {
	t.Helper()
	if !reflect.DeepEqual(n.Props, want) {
		t.Errorf("props mismatch for %s\n got: %+v\nwant: %+v", n.ID, n.Props, want)
	}
}

func depPreds() []assembler.IngestPredicates {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	p2 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v2.0.0")}
	p3 := &generated.PkgInputSpec{Type: "npm", Namespace: nil, Name: "left-pad", Version: ptr("1.3.0")}
	return []assembler.IngestPredicates{{
		IsDependency: []assembler.IsDependencyIngest{
			{Pkg: p1, DepPkg: p2},
			{Pkg: p1, DepPkg: p3},
		},
	}}
}

func TestAssemblePackages(t *testing.T) {
	got := streamAt(t, depPreds())

	want := varve.Stream{
		Nodes: []varve.NodeRecord{
			{ID: "pkg:n:golang/github.com%2Fx/y", Labels: []varve.NodeLabel{"PkgName"}, ValidFrom: testNow, Props: []varve.Prop{
				{Key: "type", Value: varve.Str("golang")},
				{Key: "namespace", Value: varve.Str("github.com/x")},
				{Key: "name", Value: varve.Str("y")},
			}},
			{ID: "pkg:n:npm//left-pad", Labels: []varve.NodeLabel{"PkgName"}, ValidFrom: testNow, Props: []varve.Prop{
				{Key: "type", Value: varve.Str("npm")},
				{Key: "name", Value: varve.Str("left-pad")},
			}},
			{ID: "pkg:v:golang/github.com%2Fx/y/v1.0.0++", Labels: []varve.NodeLabel{"PkgVersion"}, ValidFrom: testNow, Props: []varve.Prop{
				{Key: "type", Value: varve.Str("golang")},
				{Key: "namespace", Value: varve.Str("github.com/x")},
				{Key: "name", Value: varve.Str("y")},
				{Key: "version", Value: varve.Str("v1.0.0")},
				{Key: "purl", Value: varve.Str("pkg:golang/github.com/x/y@v1.0.0")},
			}},
			{ID: "pkg:v:golang/github.com%2Fx/y/v2.0.0++", Labels: []varve.NodeLabel{"PkgVersion"}, ValidFrom: testNow, Props: []varve.Prop{
				{Key: "type", Value: varve.Str("golang")},
				{Key: "namespace", Value: varve.Str("github.com/x")},
				{Key: "name", Value: varve.Str("y")},
				{Key: "version", Value: varve.Str("v2.0.0")},
				{Key: "purl", Value: varve.Str("pkg:golang/github.com/x/y@v2.0.0")},
			}},
			{ID: "pkg:v:npm//left-pad/1.3.0++", Labels: []varve.NodeLabel{"PkgVersion"}, ValidFrom: testNow, Props: []varve.Prop{
				{Key: "type", Value: varve.Str("npm")},
				{Key: "name", Value: varve.Str("left-pad")},
				{Key: "version", Value: varve.Str("1.3.0")},
				{Key: "purl", Value: varve.Str("pkg:npm/left-pad@1.3.0")},
			}},
		},
		Edges: []varve.EdgeRecord{
			{ID: "pkg:n:golang/github.com%252Fx/y|PkgHasVersion|pkg:v:golang/github.com%252Fx/y/v1.0.0++", Label: "PkgHasVersion", Src: "pkg:n:golang/github.com%2Fx/y", Dst: "pkg:v:golang/github.com%2Fx/y/v1.0.0++", ValidFrom: testNow},
			{ID: "pkg:n:golang/github.com%252Fx/y|PkgHasVersion|pkg:v:golang/github.com%252Fx/y/v2.0.0++", Label: "PkgHasVersion", Src: "pkg:n:golang/github.com%2Fx/y", Dst: "pkg:v:golang/github.com%2Fx/y/v2.0.0++", ValidFrom: testNow},
			{ID: "pkg:n:npm//left-pad|PkgHasVersion|pkg:v:npm//left-pad/1.3.0++", Label: "PkgHasVersion", Src: "pkg:n:npm//left-pad", Dst: "pkg:v:npm//left-pad/1.3.0++", ValidFrom: testNow},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Assemble packages mismatch\n got:\n%s\nwant:\n%s", ndjson(t, got), ndjson(t, want))
	}
}

func TestAssemblePackagesDeduplicates(t *testing.T) {
	got := streamAt(t, depPreds())

	countNode := func(id varve.NodeID) int {
		n := 0
		for _, nd := range got.Nodes {
			if nd.ID == id {
				n++
			}
		}
		return n
	}
	if c := countNode("pkg:v:golang/github.com%2Fx/y/v1.0.0++"); c != 1 {
		t.Errorf("PkgVersion v1.0.0 appears %d times, want 1", c)
	}
	if c := countNode("pkg:n:golang/github.com%2Fx/y"); c != 1 {
		t.Errorf("PkgName golang/github.com/x/y appears %d times, want 1", c)
	}
}

func TestAssemblePackagesDeterministic(t *testing.T) {
	preds := depPreds()
	first := ndjson(t, streamAt(t, preds))
	second := ndjson(t, streamAt(t, preds))
	if first != second {
		t.Errorf("Assemble is not deterministic\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestAssemblePackagesQualifiersAndSubpath(t *testing.T) {
	pq := &generated.PkgInputSpec{
		Type:      "golang",
		Namespace: ptr("github.com/x"),
		Name:      "y",
		Version:   ptr("v1.0.0"),
		Qualifiers: []generated.PackageQualifierInputSpec{
			{Key: "os", Value: "linux"},
			{Key: "arch", Value: "amd64"},
		},
		Subpath: ptr("cmd/x"),
	}
	preds := []assembler.IngestPredicates{{
		IsDependency: []assembler.IsDependencyIngest{{Pkg: pq}},
	}}

	got := streamAt(t, preds)

	const wantID = varve.NodeID("pkg:v:golang/github.com%2Fx/y/v1.0.0+arch=amd64&os=linux+cmd%2Fx")
	n, ok := findNode(got, wantID)
	if !ok {
		t.Fatalf("no PkgVersion node with id %q; got %s", wantID, ndjson(t, got))
	}
	props := map[string]varve.Value{}
	for _, p := range n.Props {
		props[p.Key] = p.Value
	}
	if props["qualifiers"] != varve.Str("arch=amd64&os=linux") {
		t.Errorf("qualifiers prop = %v, want %q", props["qualifiers"], "arch=amd64&os=linux")
	}
	if props["subpath"] != varve.Str("cmd/x") {
		t.Errorf("subpath prop = %v, want %q", props["subpath"], "cmd/x")
	}
}

func TestSourceNode(t *testing.T) {
	b := newBuilder(validtime.Default(), testNow)
	id := b.addSource(&generated.SourceInputSpec{Type: "git", Namespace: "github.com/x", Name: "y", Tag: ptr("v1"), Commit: ptr("abc")})
	const wantID = varve.NodeID("src:n:git/github.com/x/y@v1@abc")
	if id != wantID {
		t.Fatalf("addSource id = %q, want %q", id, wantID)
	}
	n, ok := findNode(b.Stream(), id)
	if !ok {
		t.Fatalf("no SrcName node with id %q", id)
	}
	want := varve.NodeRecord{ID: wantID, Labels: []varve.NodeLabel{"SrcName"}, Props: []varve.Prop{
		{Key: "type", Value: varve.Str("git")},
		{Key: "namespace", Value: varve.Str("github.com/x")},
		{Key: "name", Value: varve.Str("y")},
		{Key: "tag", Value: varve.Str("v1")},
		{Key: "commit", Value: varve.Str("abc")},
	}}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("SrcName node mismatch\n got: %+v\nwant: %+v", n, want)
	}
}

func TestArtifactNode(t *testing.T) {
	b := newBuilder(validtime.Default(), testNow)
	id := b.addArtifact(&generated.ArtifactInputSpec{Algorithm: "SHA256", Digest: "ABC123"})
	const wantID = varve.NodeID("art:sha256:abc123")
	if id != wantID {
		t.Fatalf("addArtifact id = %q, want %q", id, wantID)
	}
	n, _ := findNode(b.Stream(), id)
	want := varve.NodeRecord{ID: wantID, Labels: []varve.NodeLabel{"Artifact"}, Props: []varve.Prop{
		{Key: "algorithm", Value: varve.Str("sha256")},
		{Key: "digest", Value: varve.Str("abc123")},
	}}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("Artifact node mismatch\n got: %+v\nwant: %+v", n, want)
	}
}

func TestVulnerabilityNode(t *testing.T) {
	b := newBuilder(validtime.Default(), testNow)
	id := b.addVulnerability(&generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "CVE-2021-44228"})
	const wantID = varve.NodeID("vuln:osv/cve-2021-44228")
	if id != wantID {
		t.Fatalf("addVulnerability id = %q, want %q", id, wantID)
	}
	n, _ := findNode(b.Stream(), id)
	want := varve.NodeRecord{ID: wantID, Labels: []varve.NodeLabel{"Vulnerability"}, Props: []varve.Prop{
		{Key: "type", Value: varve.Str("osv")},
		{Key: "vulnID", Value: varve.Str("cve-2021-44228")},
	}}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("Vulnerability node mismatch\n got: %+v\nwant: %+v", n, want)
	}

	b2 := newBuilder(validtime.Default(), testNow)
	nv := b2.addVulnerability(&generated.VulnerabilityInputSpec{Type: "noVuln", VulnerabilityID: ""})
	if nv != "vuln:novuln" {
		t.Fatalf("addVulnerability novuln id = %q, want %q", nv, "vuln:novuln")
	}
	n2, _ := findNode(b2.Stream(), nv)
	want2 := varve.NodeRecord{ID: "vuln:novuln", Labels: []varve.NodeLabel{"Vulnerability"}, Props: []varve.Prop{
		{Key: "type", Value: varve.Str("novuln")},
	}}
	if !reflect.DeepEqual(n2, want2) {
		t.Errorf("noVuln node mismatch\n got: %+v\nwant: %+v", n2, want2)
	}
}

func TestBuilderNode(t *testing.T) {
	b := newBuilder(validtime.Default(), testNow)
	id := b.addBuilder(&generated.BuilderInputSpec{Uri: "https://ci/x"})
	const wantID = varve.NodeID("bld:https://ci/x")
	if id != wantID {
		t.Fatalf("addBuilder id = %q, want %q", id, wantID)
	}
	n, _ := findNode(b.Stream(), id)
	want := varve.NodeRecord{ID: wantID, Labels: []varve.NodeLabel{"Builder"}, Props: []varve.Prop{
		{Key: "uri", Value: varve.Str("https://ci/x")},
	}}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("Builder node mismatch\n got: %+v\nwant: %+v", n, want)
	}
}

func TestLicenseNode(t *testing.T) {
	b := newBuilder(validtime.Default(), testNow)
	named := b.addLicense(generated.LicenseInputSpec{Name: "GPL-2.0", ListVersion: ptr("3.0")})
	if named != "lic:GPL-2.0" {
		t.Fatalf("addLicense named id = %q, want %q", named, "lic:GPL-2.0")
	}
	n, _ := findNode(b.Stream(), named)
	wantNamed := varve.NodeRecord{ID: "lic:GPL-2.0", Labels: []varve.NodeLabel{"License"}, Props: []varve.Prop{
		{Key: "name", Value: varve.Str("GPL-2.0")},
		{Key: "listVersion", Value: varve.Str("3.0")},
	}}
	if !reflect.DeepEqual(n, wantNamed) {
		t.Errorf("named License node mismatch\n got: %+v\nwant: %+v", n, wantNamed)
	}

	b2 := newBuilder(validtime.Default(), testNow)
	inline := "some license text"
	il := b2.addLicense(generated.LicenseInputSpec{Name: "x", Inline: &inline})
	wantID := LicenseID("x", &inline)
	if il != wantID {
		t.Fatalf("addLicense inline id = %q, want %q", il, wantID)
	}
	n2, _ := findNode(b2.Stream(), il)
	wantInline := varve.NodeRecord{ID: wantID, Labels: []varve.NodeLabel{"License"}, Props: []varve.Prop{
		{Key: "name", Value: varve.Str("x")},
		{Key: "inline", Value: varve.Str("some license text")},
	}}
	if !reflect.DeepEqual(n2, wantInline) {
		t.Errorf("inline License node mismatch\n got: %+v\nwant: %+v", n2, wantInline)
	}
}

func TestAssembleDeterministic(t *testing.T) {
	preds := depPreds()
	first := ndjson(t, streamAt(t, preds))
	second := ndjson(t, streamAt(t, preds))
	if first != second {
		t.Errorf("Assemble not byte-deterministic")
	}
}

func TestAssembleEmptyIsEmpty(t *testing.T) {
	got := streamAt(t, nil)
	if len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Errorf("Assemble(nil) = %d nodes / %d edges, want 0 / 0", len(got.Nodes), len(got.Edges))
	}
}

func certifyVulnPreds(scanned time.Time) []assembler.IngestPredicates {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	return []assembler.IngestPredicates{{
		CertifyVuln: []assembler.CertifyVulnIngest{{
			Pkg:           p1,
			Vulnerability: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "CVE-2021-44228"},
			VulnData:      &generated.ScanMetadataInput{TimeScanned: scanned},
		}},
	}}
}

func TestValidFromInBounds(t *testing.T) {
	scanned := time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC)
	res := Assemble(context.Background(), certifyVulnPreds(scanned), validtime.Default(), testNow)
	if res.Fallbacks != 0 {
		t.Errorf("Fallbacks = %d, want 0", res.Fallbacks)
	}

	subjID := varve.NodeID("pkg:v:golang/github.com%2Fx/y/v1.0.0++")
	vulnID := varve.NodeID("vuln:osv/cve-2021-44228")
	evID := EvidenceID("CertifyVuln", string(subjID), string(vulnID),
		"2021-12-10T10:15:00Z", "", "", "", "", "", "", "")

	ev, ok := findNode(res.Stream, evID)
	if !ok {
		t.Fatalf("no CertifyVuln node %q", evID)
	}
	if !ev.ValidFrom.Equal(scanned) {
		t.Errorf("CertifyVuln ValidFrom = %v, want %v", ev.ValidFrom, scanned)
	}
	subj, _ := findNode(res.Stream, subjID)
	if !subj.ValidFrom.Equal(scanned) {
		t.Errorf("PkgVersion ValidFrom = %v, want %v", subj.ValidFrom, scanned)
	}
	vuln, _ := findNode(res.Stream, vulnID)
	if !vuln.ValidFrom.Equal(scanned) {
		t.Errorf("Vulnerability ValidFrom = %v, want %v", vuln.ValidFrom, scanned)
	}
	edge, ok := findEdge(res.Stream, EdgeIDFor(subjID, EdgeCertifyVulnSubject, evID))
	if !ok {
		t.Fatalf("no CertifyVulnSubject edge")
	}
	if !edge.ValidFrom.Equal(scanned) {
		t.Errorf("CertifyVulnSubject edge ValidFrom = %v, want %v", edge.ValidFrom, scanned)
	}
}

func TestValidFromFallbackBeforeFloor(t *testing.T) {
	scanned := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	res := Assemble(context.Background(), certifyVulnPreds(scanned), validtime.Default(), testNow)
	if res.Fallbacks != 1 {
		t.Errorf("Fallbacks = %d, want 1", res.Fallbacks)
	}

	subjID := varve.NodeID("pkg:v:golang/github.com%2Fx/y/v1.0.0++")
	vulnID := varve.NodeID("vuln:osv/cve-2021-44228")
	evID := EvidenceID("CertifyVuln", string(subjID), string(vulnID),
		"1970-01-01T00:00:00Z", "", "", "", "", "", "", "")

	ev, ok := findNode(res.Stream, evID)
	if !ok {
		t.Fatalf("no CertifyVuln node %q", evID)
	}
	if !ev.ValidFrom.Equal(testNow) {
		t.Errorf("CertifyVuln ValidFrom = %v, want %v (fallback)", ev.ValidFrom, testNow)
	}
	// The raw timestamp property still records the doctored 1970 value: property
	// and valid_from diverge exactly when the guard fired.
	var ts varve.Value
	for _, p := range ev.Props {
		if p.Key == "timeScanned" {
			ts = p.Value
		}
	}
	if ts != varve.Str("1970-01-01T00:00:00Z") {
		t.Errorf("timeScanned prop = %v, want %q", ts, "1970-01-01T00:00:00Z")
	}
}

func TestValidFromFutureSkew(t *testing.T) {
	scanned := testNow.Add(10 * time.Minute)
	res := Assemble(context.Background(), certifyVulnPreds(scanned), validtime.Default(), testNow)
	if res.Fallbacks != 1 {
		t.Errorf("Fallbacks = %d, want 1", res.Fallbacks)
	}

	subjID := varve.NodeID("pkg:v:golang/github.com%2Fx/y/v1.0.0++")
	vulnID := varve.NodeID("vuln:osv/cve-2021-44228")
	evID := EvidenceID("CertifyVuln", string(subjID), string(vulnID),
		"2026-08-07T00:10:00Z", "", "", "", "", "", "", "")

	ev, ok := findNode(res.Stream, evID)
	if !ok {
		t.Fatalf("no CertifyVuln node %q", evID)
	}
	if !ev.ValidFrom.Equal(testNow) {
		t.Errorf("CertifyVuln ValidFrom = %v, want %v (fallback)", ev.ValidFrom, testNow)
	}
}

func TestValidFromAbsentKind(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	p2 := &generated.PkgInputSpec{Type: "npm", Namespace: nil, Name: "left-pad", Version: ptr("1.3.0")}
	preds := []assembler.IngestPredicates{{
		IsDependency: []assembler.IsDependencyIngest{{
			Pkg: p1, DepPkg: p2,
			IsDependency: &generated.IsDependencyInputSpec{DependencyType: "DIRECT", Justification: "dep"},
		}},
	}}
	res := Assemble(context.Background(), preds, validtime.Default(), testNow)
	if res.Fallbacks != 1 {
		t.Errorf("Fallbacks = %d, want 1", res.Fallbacks)
	}

	subjID := varve.NodeID("pkg:v:golang/github.com%2Fx/y/v1.0.0++")
	objID := varve.NodeID("pkg:v:npm//left-pad/1.3.0++")
	evID := EvidenceID("IsDependency", string(subjID), string(objID), "DIRECT", "dep", "", "", "")

	for _, id := range []varve.NodeID{evID, subjID, objID} {
		n, ok := findNode(res.Stream, id)
		if !ok {
			t.Fatalf("no node %q", id)
		}
		if !n.ValidFrom.Equal(testNow) {
			t.Errorf("node %q ValidFrom = %v, want %v (fallback)", id, n.ValidFrom, testNow)
		}
	}
}

func TestIdentityNodeEarliest(t *testing.T) {
	p1 := &generated.PkgInputSpec{Type: "golang", Namespace: ptr("github.com/x"), Name: "y", Version: ptr("v1.0.0")}
	sbomTime := time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC)
	vulnTime := time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC)
	preds := []assembler.IngestPredicates{{
		HasSBOM: []assembler.HasSBOMIngest{{
			Pkg:     p1,
			HasSBOM: &generated.HasSBOMInputSpec{Uri: "http://sbom", KnownSince: sbomTime},
		}},
		CertifyVuln: []assembler.CertifyVulnIngest{{
			Pkg:           p1,
			Vulnerability: &generated.VulnerabilityInputSpec{Type: "osv", VulnerabilityID: "CVE-2021-44228"},
			VulnData:      &generated.ScanMetadataInput{TimeScanned: vulnTime},
		}},
	}}
	res := Assemble(context.Background(), preds, validtime.Default(), testNow)
	if res.Fallbacks != 0 {
		t.Errorf("Fallbacks = %d, want 0", res.Fallbacks)
	}

	versionID := varve.NodeID("pkg:v:golang/github.com%2Fx/y/v1.0.0++")
	nameID := varve.NodeID("pkg:n:golang/github.com%2Fx/y")
	for _, id := range []varve.NodeID{versionID, nameID} {
		n, _ := findNode(res.Stream, id)
		if !n.ValidFrom.Equal(sbomTime) {
			t.Errorf("identity node %q ValidFrom = %v, want %v (earliest)", id, n.ValidFrom, sbomTime)
		}
	}

	vulnEvID := EvidenceID("CertifyVuln", string(versionID), "vuln:osv/cve-2021-44228",
		"2021-12-10T10:15:00Z", "", "", "", "", "", "", "")
	sbomEvID := EvidenceID("HasSBOM", string(versionID), "http://sbom", "", "", "",
		"2020-03-01T00:00:00Z", "", "", "")

	vulnEv, ok := findNode(res.Stream, vulnEvID)
	if !ok {
		t.Fatalf("no CertifyVuln node %q", vulnEvID)
	}
	if !vulnEv.ValidFrom.Equal(vulnTime) {
		t.Errorf("CertifyVuln evidence ValidFrom = %v, want %v", vulnEv.ValidFrom, vulnTime)
	}
	sbomEv, ok := findNode(res.Stream, sbomEvID)
	if !ok {
		t.Fatalf("no HasSBOM node %q", sbomEvID)
	}
	if !sbomEv.ValidFrom.Equal(sbomTime) {
		t.Errorf("HasSBOM evidence ValidFrom = %v, want %v", sbomEv.ValidFrom, sbomTime)
	}
}

func TestValidFromDeterministicAcrossRuns(t *testing.T) {
	preds := certifyVulnPreds(time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC))
	first := ndjson(t, Assemble(context.Background(), preds, validtime.Default(), testNow).Stream)
	second := ndjson(t, Assemble(context.Background(), preds, validtime.Default(), testNow).Stream)
	if first != second {
		t.Errorf("valid_from not deterministic across runs\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestResultDocumentValidFrom(t *testing.T) {
	t1 := time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	t0 := time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC)

	b := newBuilder(validtime.Default(), testNow)
	b.beginAssertion(&t1)
	b.beginAssertion(nil) // falls back
	b.beginAssertion(&t0)
	res := b.result()
	if !res.ValidFrom.Equal(t0) {
		t.Errorf("ValidFrom = %v, want %v (earliest accepted native time)", res.ValidFrom, t0)
	}
	if res.Fallback {
		t.Errorf("Fallback = true, want false (a native time was accepted)")
	}
	if res.Fallbacks != 1 {
		t.Errorf("Fallbacks = %d, want 1", res.Fallbacks)
	}

	b2 := newBuilder(validtime.Default(), testNow)
	b2.beginAssertion(nil)
	res2 := b2.result()
	if !res2.ValidFrom.Equal(testNow) || !res2.Fallback {
		t.Errorf("all-fallback result = {ValidFrom %v, Fallback %v}, want {%v, true}", res2.ValidFrom, res2.Fallback, testNow)
	}

	b3 := newBuilder(validtime.Default(), testNow)
	res3 := b3.result()
	if !res3.ValidFrom.Equal(testNow) || !res3.Fallback {
		t.Errorf("no-assertion result = {ValidFrom %v, Fallback %v}, want {%v, true}", res3.ValidFrom, res3.Fallback, testNow)
	}
}

func TestDistinctQualifiersKeepSeparateEvidence(t *testing.T) {
	a := &generated.PkgInputSpec{Type: "generic", Name: "example", Version: ptr("1"), Qualifiers: []generated.PackageQualifierInputSpec{{Key: "arch", Value: "x&distro=y"}}}
	b := &generated.PkgInputSpec{Type: "generic", Name: "example", Version: ptr("1"), Qualifiers: []generated.PackageQualifierInputSpec{{Key: "arch", Value: "x"}, {Key: "distro", Value: "y"}}}
	s := streamAt(t, []assembler.IngestPredicates{{CertifyVuln: []assembler.CertifyVulnIngest{
		{Pkg: a, Vulnerability: &generated.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2024-1"}, VulnData: &generated.ScanMetadataInput{ScannerUri: "osv.dev"}},
		{Pkg: b, Vulnerability: &generated.VulnerabilityInputSpec{Type: "cve", VulnerabilityID: "cve-2024-1"}, VulnData: &generated.ScanMetadataInput{ScannerUri: "osv.dev"}},
	}}})
	if countLabel(s, LabelPkgVersion) != 2 || countLabel(s, LabelCertifyVuln) != 2 {
		t.Fatalf("distinct packages or evidence merged:\n%s", ndjson(t, s))
	}
	purls := make(map[string]bool)
	for _, n := range s.Nodes {
		for _, p := range n.Props {
			if p.Key == PropPurl {
				v, ok := p.Value.AsString()
				if !ok {
					t.Fatal("purl is not string")
				}
				purls[v] = true
			}
		}
	}
	for _, purl := range []string{"pkg:generic/example@1?arch=x%26distro%3Dy", "pkg:generic/example@1?arch=x&distro=y"} {
		if !purls[purl] {
			t.Errorf("missing purl %q: %#v", purl, purls)
		}
	}
}
