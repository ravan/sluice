package federatedcode

import (
	"errors"
	"testing"
)

func TestPurlHash(t *testing.T) {
	tests := []struct {
		purl string
		bits int
		want string
	}{
		{"pkg:pypi/univers@30.12.0", 7, "09"},
		{"pkg:pypi/univers@30.12.0?foo=bar#sub/path", 7, "09"},
		{"pkg:pypi/license_expression", 7, "50"},
		{"pkg:pypi/license-expression@30.3.1", 7, "50"},
		{"pkg:pypi/expressionss", 7, "57"},
		{"pkg:npm/lodash@4.17.21", 10, "026"},
		{"pkg:golang/golang.org/x/net@0.27.0", 7, "25"},
		{"pkg:generic/acme/demo-app@1.2.0", 5, "0d"},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			core, err := CorePurl(tt.purl)
			if err != nil {
				t.Fatalf("CorePurl(%q) returned error: %v", tt.purl, err)
			}
			if got := PurlHash(core, tt.bits); got != tt.want {
				t.Errorf("PurlHash(%q, %d) = %q, want %q", core, tt.bits, got, tt.want)
			}
		})
	}
}

func TestPathFor(t *testing.T) {
	t.Run("npm", func(t *testing.T) {
		p, err := PathFor("pkg:npm/lodash@4.17.21")
		if err != nil {
			t.Fatalf("PathFor returned error: %v", err)
		}
		want := PackagePath{Bucket: "aboutcode-packages-npm-026", Core: "npm/lodash"}
		if p != want {
			t.Errorf("PathFor = %+v, want %+v", p, want)
		}
		if got, want := p.Dir(), "aboutcode-packages-npm-026/npm/lodash"; got != want {
			t.Errorf("Dir() = %q, want %q", got, want)
		}
	})

	t.Run("golang", func(t *testing.T) {
		p, err := PathFor("pkg:golang/golang.org/x/net@0.27.0")
		if err != nil {
			t.Fatalf("PathFor returned error: %v", err)
		}
		if p.Bucket != "aboutcode-packages-golang-25" {
			t.Errorf("Bucket = %q, want %q", p.Bucket, "aboutcode-packages-golang-25")
		}
		if p.Core != "golang/golang.org/x/net" {
			t.Errorf("Core = %q, want %q", p.Core, "golang/golang.org/x/net")
		}
	})

	t.Run("zero bits", func(t *testing.T) {
		p, err := PathFor("pkg:cargo/serde@1.0.203")
		if err != nil {
			t.Fatalf("PathFor returned error: %v", err)
		}
		if len(p.Bucket) < 2 || p.Bucket[len(p.Bucket)-2:] != "-0" {
			t.Errorf("Bucket = %q, want suffix %q", p.Bucket, "-0")
		}
		if hash := p.Bucket[len(p.Bucket)-1:]; len(hash) != 1 {
			t.Errorf("hash = %q, want length 1", hash)
		}
	})

	t.Run("bad purl", func(t *testing.T) {
		_, err := PathFor("not-a-purl")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrPurl) {
			t.Errorf("error = %v, want errors.Is(err, ErrPurl)", err)
		}
	})
}

func TestVulnerabilityPath(t *testing.T) {
	tests := []struct {
		vcid string
		want string
	}{
		{"VCID-1111-2222-3333", "aboutcode-vulnerabilities/11/VCID-1111-2222-3333.yml"},
		{"VCID-4wn8-fck1-aaaq", "aboutcode-vulnerabilities/4w/VCID-4wn8-fck1-aaaq.yml"},
	}

	for _, tt := range tests {
		t.Run(tt.vcid, func(t *testing.T) {
			got, err := VulnerabilityPath(tt.vcid)
			if err != nil {
				t.Fatalf("VulnerabilityPath(%q) returned error: %v", tt.vcid, err)
			}
			if got != tt.want {
				t.Errorf("VulnerabilityPath(%q) = %q, want %q", tt.vcid, got, tt.want)
			}
		})
	}

	t.Run("too short", func(t *testing.T) {
		if _, err := VulnerabilityPath("VCID-"); !errors.Is(err, ErrVCID) {
			t.Errorf("error = %v, want errors.Is(err, ErrVCID)", err)
		}
	})
}
