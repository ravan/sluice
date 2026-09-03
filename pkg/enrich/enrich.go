// Package enrich holds the org's enrichment policy as the pipeline sees it,
// the Claim record every enricher emits, and the Enricher seam itself.
package enrich

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/varve"
)

// Source is one enrichment source's name, matching a Silt rules.Enricher.
type Source string

// Jurisdiction is where a source's host sits, for the eu_only cap.
type Jurisdiction string

// SourceEUVD and the names below it are the registered enrichment sources;
// EU, US and Other are the jurisdictions they can sit in.
const (
	SourceEUVD           Source = "euvd"
	SourceVulnerableCode Source = "vulnerablecode"
	SourceOSV            Source = "osv"
	SourceClearlyDefined Source = "clearlydefined"
	SourceEOL            Source = "eol"
	SourceDepsDev        Source = "deps_dev"

	EU    Jurisdiction = "eu"
	US    Jurisdiction = "us"
	Other Jurisdiction = "other"
)

// Sources is the closed set ParsePolicy accepts.
var Sources = []Source{
	SourceEUVD, SourceVulnerableCode, SourceOSV,
	SourceClearlyDefined, SourceEOL, SourceDepsDev,
}

// Jurisdictions maps a source to the jurisdiction of the host it calls.
// vulnerablecode is deliberately absent: its host is a deployment choice, so
// under eu_only it does not run until slice 2b sets it from config.
var Jurisdictions = map[Source]Jurisdiction{
	SourceEUVD:           EU,
	SourceOSV:            US,
	SourceClearlyDefined: US,
	SourceEOL:            US,
	SourceDepsDev:        US,
}

// AllJurisdictions is the closed set ParseJurisdiction accepts.
var AllJurisdictions = []Jurisdiction{EU, US, Other}

// ErrUnknownSource is returned when a policy names a source outside Sources.
var ErrUnknownSource = errors.New("enrich: unknown source")

// ErrUnknownJurisdiction is returned when a name falls outside AllJurisdictions.
var ErrUnknownJurisdiction = errors.New("enrich: unknown jurisdiction")

// Policy is the org's enrichment rules as the pipeline enforces them.
type Policy struct {
	Sources []Source // priority order
	EUOnly  bool
	Hosted  map[Source]Jurisdiction // per-install jurisdiction for a source whose host is a deployment choice; wins over Jurisdictions
}

// ParsePolicy validates source names and hosted jurisdictions into a Policy.
func ParsePolicy(sources []string, euOnly bool, hosted map[Source]Jurisdiction) (Policy, error) {
	p := Policy{EUOnly: euOnly}
	seen := map[Source]bool{}
	for _, name := range sources {
		s := Source(name)
		if !slices.Contains(Sources, s) {
			return Policy{}, fmt.Errorf("%w: %q", ErrUnknownSource, name)
		}
		if seen[s] {
			return Policy{}, fmt.Errorf("enrich: duplicate source: %q", name)
		}
		seen[s] = true
		p.Sources = append(p.Sources, s)
	}
	for s, j := range hosted {
		if !slices.Contains(Sources, s) {
			return Policy{}, fmt.Errorf("%w: %q", ErrUnknownSource, s)
		}
		if !slices.Contains(AllJurisdictions, j) {
			return Policy{}, fmt.Errorf("%w: %q for source %q", ErrUnknownJurisdiction, j, s)
		}
		if p.Hosted == nil {
			p.Hosted = map[Source]Jurisdiction{}
		}
		p.Hosted[s] = j
	}
	return p, nil
}

// ParseJurisdiction validates a jurisdiction name read out of config.
func ParseJurisdiction(name string) (Jurisdiction, error) {
	j := Jurisdiction(name)
	if !slices.Contains(AllJurisdictions, j) {
		return "", fmt.Errorf("%w: %q", ErrUnknownJurisdiction, name)
	}
	return j, nil
}

// JurisdictionOf answers for one source: Hosted, else Jurisdictions, else Other.
func (p Policy) JurisdictionOf(s Source) Jurisdiction {
	if j, ok := p.Hosted[s]; ok {
		return j
	}
	if j, ok := Jurisdictions[s]; ok {
		return j
	}
	return Other
}

// Stamp places every claim in the jurisdiction JurisdictionOf gives its source.
// It is the only constructor of StampedClaim, so an enricher cannot state where
// its own host sits.
func (p Policy) Stamp(claims []Claim) []StampedClaim {
	out := make([]StampedClaim, 0, len(claims))
	for _, c := range claims {
		out = append(out, StampedClaim{Claim: c, jurisdiction: p.JurisdictionOf(c.Source)})
	}
	return out
}

// Allows reports whether s may run: listed, and under EUOnly sitting in the EU.
func (p Policy) Allows(s Source) bool {
	if !slices.Contains(p.Sources, s) {
		return false
	}
	if !p.EUOnly {
		return true
	}
	return p.JurisdictionOf(s) == EU
}

// ScanFlags gates GUAC's four in-parser scanners by the same policy.
func (p Policy) ScanFlags() guacseam.ScanFlags {
	return guacseam.ScanFlags{
		Vulns:    p.Allows(SourceOSV),
		Licenses: p.Allows(SourceClearlyDefined),
		EOL:      p.Allows(SourceEOL),
		DepsDev:  p.Allows(SourceDepsDev),
	}
}

// Input is one document as an enricher sees it. Records holds earlier
// enrichers' claims too.
type Input struct {
	Digest  string // lower-case hex sha256 of the document bytes
	Records varve.Stream
	Now     time.Time
}

// Enricher asks one source about a document and returns what it said.
type Enricher interface {
	Source() Source
	Enrich(ctx context.Context, in Input) ([]Claim, error) // must not modify in.Records
}

// VulnNames returns the vulnID of every Vulnerability node of type cve or
// euvd, sorted and deduped.
func VulnNames(s varve.Stream) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range s.Nodes {
		if !slices.Contains(n.Labels, assemble.LabelVulnerability) {
			continue
		}
		typ, _ := propStr(n.Props, assemble.PropType)
		if typ != "cve" && typ != "euvd" {
			continue
		}
		name, ok := propStr(n.Props, assemble.PropVulnID)
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// VulnNodes maps every Vulnerability node's lower-cased vulnID to its node id.
func VulnNodes(s varve.Stream) map[string]varve.NodeID {
	out := map[string]varve.NodeID{}
	for _, n := range s.Nodes {
		if !slices.Contains(n.Labels, assemble.LabelVulnerability) {
			continue
		}
		name, ok := propStr(n.Props, assemble.PropVulnID)
		if !ok || name == "" {
			continue
		}
		out[strings.ToLower(name)] = n.ID
	}
	return out
}

// PkgPurls returns the purl of every PkgVersion node, sorted and deduped,
// skipping the empty ones.
func PkgPurls(s varve.Stream) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range s.Nodes {
		if !slices.Contains(n.Labels, assemble.LabelPkgVersion) {
			continue
		}
		purl, ok := propStr(n.Props, assemble.PropPurl)
		if !ok || purl == "" || seen[purl] {
			continue
		}
		seen[purl] = true
		out = append(out, purl)
	}
	sort.Strings(out)
	return out
}

// propStr reads one property as the string a claim value is written from.
func propStr(props []varve.Prop, key string) (string, bool) {
	for _, p := range props {
		if p.Key != key {
			continue
		}
		switch v := p.Value.(type) {
		case varve.Str:
			return string(v), true
		case varve.Float:
			return strconv.FormatFloat(float64(v), 'f', -1, 64), true
		case varve.Int:
			return strconv.FormatInt(int64(v), 10), true
		}
		return "", false
	}
	return "", false
}
