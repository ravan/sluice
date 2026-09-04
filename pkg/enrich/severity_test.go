package enrich_test

import (
	"testing"

	"github.com/ravan/sluice/pkg/enrich"
)

func TestCVSS(t *testing.T) {
	sevs := []enrich.Severity{
		{System: "generic_textual", Score: "Medium"},
		{System: "cvssv3.1", Score: ""},
		{System: "cvssv4", Score: "6.9"},
		{System: "cvssv3.1", Score: "6.5", Elements: "CVSS:3.1/AV:N"},
	}
	got, ok := enrich.CVSS(sevs)
	if !ok {
		t.Fatal("CVSS() ok = false, want true")
	}
	if got != sevs[2] {
		t.Errorf("CVSS() = %+v, want %+v", got, sevs[2])
	}

	_, ok = enrich.CVSS([]enrich.Severity{{System: "cvssv3.1", Score: ""}})
	if ok {
		t.Error("CVSS() ok = true for an empty-score entry, want false")
	}
}

func TestEPSS(t *testing.T) {
	sevs := []enrich.Severity{
		{System: "rhas", Score: "low"},
		{System: "epss", Score: "0.00103"},
	}
	got, ok := enrich.EPSS(sevs)
	if !ok {
		t.Fatal("EPSS() ok = false, want true")
	}
	if got != sevs[1] {
		t.Errorf("EPSS() = %+v, want %+v", got, sevs[1])
	}
}

func TestVersion(t *testing.T) {
	tests := []struct {
		system string
		want   string
	}{
		{"cvssv3.1", "3.1"},
		{"cvssv3", "3"},
		{"generic_textual", ""},
	}
	for _, tt := range tests {
		got := enrich.Severity{System: tt.system}.Version()
		if got != tt.want {
			t.Errorf("Severity{System: %q}.Version() = %q, want %q", tt.system, got, tt.want)
		}
	}
}
