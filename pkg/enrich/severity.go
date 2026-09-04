package enrich

import (
	"strconv"
	"strings"
)

// cvssPrefix is what a scoring system's name starts with when its score is a
// CVSS base score. epssSystem is the one whose score is an EPSS probability.
const (
	cvssPrefix = "cvssv"
	epssSystem = "epss"
)

// Severity is one score a source states, normalised to the three fields the
// cvss facts need. VulnerableCode's V3 API calls the score "value"; a
// FederatedCode advisory calls it "score".
type Severity struct {
	System   string // the scoring system, e.g. "cvssv3.1"
	Score    string // the score exactly as the source wrote it
	Elements string // the vector, when the source states one
}

// CVSS is the first severity whose system names a CVSS version and whose score
// parses as a number. One advisory mixes cvssv3.1, cvssv4, generic_textual,
// epss and rhas in one list, and a score can be empty or a word.
func CVSS(sevs []Severity) (Severity, bool) {
	for _, s := range sevs {
		if !strings.HasPrefix(s.System, cvssPrefix) {
			continue
		}
		if _, err := strconv.ParseFloat(s.Score, 64); err != nil {
			continue
		}
		return s, true
	}
	return Severity{}, false
}

// EPSS is the first severity whose system is exactly "epss".
func EPSS(sevs []Severity) (Severity, bool) {
	for _, s := range sevs {
		if s.System == epssSystem {
			return s, true
		}
	}
	return Severity{}, false
}

// Version is what follows a CVSS system's "cvssv" prefix: "3.1", or "3".
func (s Severity) Version() string {
	if !strings.HasPrefix(s.System, cvssPrefix) {
		return ""
	}
	return strings.TrimPrefix(s.System, cvssPrefix)
}
