package assemble

import (
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/internal/varve"
)

func TestPkgNameID(t *testing.T) {
	tests := []struct {
		name      string
		typ       string
		namespace string
		pkgName   string
		want      varve.NodeID
	}{
		{
			name:      "namespaced",
			typ:       "golang",
			namespace: "github.com/x",
			pkgName:   "y",
			want:      "pkg:n:golang/github.com/x/y",
		},
		{
			name:      "empty namespace",
			typ:       "npm",
			namespace: "",
			pkgName:   "left-pad",
			want:      "pkg:n:npm//left-pad",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PkgNameID(tt.typ, tt.namespace, tt.pkgName); got != tt.want {
				t.Errorf("PkgNameID(%q, %q, %q) = %q, want %q", tt.typ, tt.namespace, tt.pkgName, got, tt.want)
			}
		})
	}
}

func TestPkgVersionID(t *testing.T) {
	tests := []struct {
		name            string
		typ             string
		namespace       string
		pkgName         string
		version         string
		canonQualifiers string
		subpath         string
		want            varve.NodeID
	}{
		{
			name:            "full",
			typ:             "golang",
			namespace:       "github.com/x",
			pkgName:         "y",
			version:         "v1.0.0",
			canonQualifiers: "arch=amd64&os=linux",
			subpath:         "sub",
			want:            "pkg:v:golang/github.com/x/y/v1.0.0+arch=amd64&os=linux+sub",
		},
		{
			name:            "minimal",
			typ:             "golang",
			namespace:       "",
			pkgName:         "y",
			version:         "",
			canonQualifiers: "",
			subpath:         "",
			want:            "pkg:v:golang//y/++",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PkgVersionID(tt.typ, tt.namespace, tt.pkgName, tt.version, tt.canonQualifiers, tt.subpath)
			if got != tt.want {
				t.Errorf("PkgVersionID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonQualifiers(t *testing.T) {
	tests := []struct {
		name  string
		quals []generated.PackageQualifierInputSpec
		want  string
	}{
		{
			name:  "nil",
			quals: nil,
			want:  "",
		},
		{
			name:  "sorted",
			quals: []generated.PackageQualifierInputSpec{{Key: "os", Value: "linux"}, {Key: "arch", Value: "amd64"}},
			want:  "arch=amd64&os=linux",
		},
		{
			name:  "reversed input is order independent",
			quals: []generated.PackageQualifierInputSpec{{Key: "arch", Value: "amd64"}, {Key: "os", Value: "linux"}},
			want:  "arch=amd64&os=linux",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonQualifiers(tt.quals); got != tt.want {
				t.Errorf("CanonQualifiers(%v) = %q, want %q", tt.quals, got, tt.want)
			}
		})
	}
}

func TestEdgeIDFor(t *testing.T) {
	tests := []struct {
		name  string
		src   varve.NodeID
		label varve.EdgeLabel
		dst   varve.NodeID
		want  varve.EdgeID
	}{
		{
			name:  "pkg has version",
			src:   "pkg:n:a",
			label: EdgePkgHasVersion,
			dst:   "pkg:v:b",
			want:  "pkg:n:a|PkgHasVersion|pkg:v:b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EdgeIDFor(tt.src, tt.label, tt.dst); got != tt.want {
				t.Errorf("EdgeIDFor(%q, %q, %q) = %q, want %q", tt.src, tt.label, tt.dst, got, tt.want)
			}
		})
	}
}

func TestLabelVocabulary(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "LabelPkgVersion", got: string(LabelPkgVersion), want: "PkgVersion"},
		{name: "LabelPkgName", got: string(LabelPkgName), want: "PkgName"},
		{name: "EdgePkgHasVersion", got: string(EdgePkgHasVersion), want: "PkgHasVersion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestSrcNameID(t *testing.T) {
	tests := []struct {
		name                            string
		typ, namespace, nm, tag, commit string
		want                            varve.NodeID
	}{
		{name: "full", typ: "git", namespace: "github.com/x", nm: "y", tag: "v1.0", commit: "abc", want: "src:n:git/github.com/x/y@v1.0@abc"},
		{name: "empty positions", typ: "git", namespace: "", nm: "y", tag: "", commit: "", want: "src:n:git//y@@"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SrcNameID(tt.typ, tt.namespace, tt.nm, tt.tag, tt.commit); got != tt.want {
				t.Errorf("SrcNameID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestArtifactID(t *testing.T) {
	if got := ArtifactID("SHA256", "ABC123"); got != "art:sha256:abc123" {
		t.Errorf("ArtifactID = %q, want %q", got, "art:sha256:abc123")
	}
}

func TestBuilderID(t *testing.T) {
	if got := BuilderID("https://ci/x"); got != "bld:https://ci/x" {
		t.Errorf("BuilderID = %q, want %q", got, "bld:https://ci/x")
	}
}

func TestVulnID(t *testing.T) {
	tests := []struct {
		name    string
		typ, id string
		want    varve.NodeID
	}{
		{name: "cve", typ: "CVE", id: "CVE-2021-44228", want: "vuln:cve/cve-2021-44228"},
		{name: "osv", typ: "osv", id: "GHSA-x", want: "vuln:osv/ghsa-x"},
		{name: "novuln empty", typ: "noVuln", id: "", want: "vuln:novuln"},
		{name: "novuln with id and case", typ: "NOVULN", id: "anything", want: "vuln:novuln"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VulnID(tt.typ, tt.id); got != tt.want {
				t.Errorf("VulnID(%q, %q) = %q, want %q", tt.typ, tt.id, got, tt.want)
			}
		})
	}
}

func TestLicenseID(t *testing.T) {
	if got := LicenseID("GPL-2.0", nil); got != "lic:GPL-2.0" {
		t.Errorf("LicenseID named = %q, want %q", got, "lic:GPL-2.0")
	}
	empty := ""
	if got := LicenseID("GPL-2.0", &empty); got != "lic:GPL-2.0" {
		t.Errorf("LicenseID empty inline = %q, want %q", got, "lic:GPL-2.0")
	}
	inline := "text"
	wantInline := varve.NodeID("lic:" + hashParts("inline", "text"))
	a := LicenseID("a", &inline)
	b := LicenseID("b", &inline)
	if a != b {
		t.Errorf("LicenseID inline not name-independent: %q != %q", a, b)
	}
	if a != wantInline {
		t.Errorf("LicenseID inline = %q, want %q", a, wantInline)
	}
}

func TestEvidenceID(t *testing.T) {
	got := EvidenceID("CertifyVuln", "pkg:v:x", "vuln:cve/y")
	if len(got) != len("CertifyVuln:")+64 {
		t.Errorf("EvidenceID length = %d, want %d", len(got), len("CertifyVuln:")+64)
	}
	if !strings.HasPrefix(string(got), "CertifyVuln:") {
		t.Errorf("EvidenceID = %q, want prefix %q", got, "CertifyVuln:")
	}
	want := varve.NodeID("CertifyVuln:" + hashParts("pkg:v:x", "vuln:cve/y"))
	if got != want {
		t.Errorf("EvidenceID = %q, want %q", got, want)
	}
}

func TestEdgeLabelVocabulary(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "EdgeCertifyVulnVulnerability", got: string(EdgeCertifyVulnVulnerability), want: "CertifyVulnVulnerability"},
		{name: "EdgeIsDependencyObject", got: string(EdgeIsDependencyObject), want: "IsDependencyObject"},
		{name: "LabelVulnerability", got: string(LabelVulnerability), want: "Vulnerability"},
		{name: "LabelVex", got: string(LabelVex), want: "Vex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}
