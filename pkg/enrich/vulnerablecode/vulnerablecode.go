// Package vulnerablecode asks AboutCode's VulnerableCode which advisories
// affect the packages a document names, and returns what it said as
// enrich.Claim records.
package vulnerablecode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// DefaultURL is the public instance that answers. public.vulnerablecode.io
// returned 500 on every path on 2026-09-03; public2 did not.
const DefaultURL = "https://public2.vulnerablecode.io"

// UserAgent is not a courtesy. VCIOUserAgentMiddleware rejects any request to
// /api/ whose User-Agent is not exactly this value with 403; the project's own
// API documentation states it. No API key is involved (ADR 0031 amendment).
const UserAgent = "VCIO_API_AGENT"

// affectedPath is the purl-keyed V3 endpoint. The API is V3: /api/v2/ is 404.
const affectedPath = "api/v3/affected-by-advisories"

// ErrStatus is returned when the API answers with anything but 200.
var ErrStatus = errors.New("vulnerablecode: unexpected status")

// Enricher is the VulnerableCode source as the pipeline sees it.
type Enricher struct {
	base   *url.URL
	client *http.Client
}

// advisory is one record of the affected-by-advisories response. Go's
// case-insensitive field match does not bridge an underscore, so every
// snake_case field carries a tag and the others need none.
type advisory struct {
	AdvisoryID  string `json:"advisory_id"`
	AdvisoryUID string `json:"advisory_uid"`
	Aliases     []string
	Summary     string
	Severities  []severity
	References  []reference
	FixedBy     []string `json:"fixed_by_packages"`
}

type severity struct {
	Value           string
	ScoringSystem   string `json:"scoring_system"`
	ScoringElements string `json:"scoring_elements"`
}

type reference struct{ URL string }

type page struct{ Results []advisory }

// New builds an Enricher against baseURL. A bad URL is an error; a nil client
// is a 20 s-timeout client.
func New(baseURL string, client *http.Client) (*Enricher, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("vulnerablecode: parse base url %q: %w", baseURL, err)
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Enricher{base: u, client: client}, nil
}

// Source names this enricher.
func (e *Enricher) Source() enrich.Source { return enrich.SourceVulnerableCode }

// Enrich asks about every package version the stream names.
func (e *Enricher) Enrich(ctx context.Context, in enrich.Input) ([]enrich.Claim, error) {
	vulns := enrich.VulnNodes(in.Records)
	var out []enrich.Claim
	for _, purl := range enrich.PkgPurls(in.Records) {
		p, err := e.affectedBy(ctx, purl)
		if err != nil {
			return nil, err
		}
		subject := subjectOf(in.Records, purl)
		for _, a := range p.Results {
			out = append(out, claimsFor(a, subject, vulns, in.Now)...)
		}
	}
	return out, nil
}

// affectedBy runs one GET against the affected-by-advisories endpoint.
func (e *Enricher) affectedBy(ctx context.Context, purl string) (p page, err error) {
	u := e.base.JoinPath(affectedPath)
	q := url.Values{}
	q.Set("purl", purl)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return page{}, fmt.Errorf("vulnerablecode: request %s: %w", purl, err)
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := e.client.Do(req)
	if err != nil {
		return page{}, fmt.Errorf("vulnerablecode: get %s: %w", purl, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("vulnerablecode: close %s: %w", purl, cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return page{}, fmt.Errorf("%w: %d for %s", ErrStatus, resp.StatusCode, purl)
	}
	if derr := json.NewDecoder(resp.Body).Decode(&p); derr != nil {
		return page{}, fmt.Errorf("vulnerablecode: decode %s: %w", purl, derr)
	}
	return p, nil
}

// subjectOf finds the PkgVersion node the purl came off.
func subjectOf(s varve.Stream, purl string) varve.NodeID {
	for _, n := range s.Nodes {
		if !slices.Contains(n.Labels, assemble.LabelPkgVersion) {
			continue
		}
		for _, p := range n.Props {
			if p.Key != assemble.PropPurl {
				continue
			}
			if v, ok := p.Value.(varve.Str); ok && string(v) == purl {
				return n.ID
			}
		}
	}
	return ""
}

// claimsFor renders one advisory: one claim about the package, plus a set
// about every alias vulnerability the stream already carries (D4, D5).
func claimsFor(a advisory, subject varve.NodeID, vulns map[string]varve.NodeID, now time.Time) []enrich.Claim {
	aliases := aliasNodes(a.Aliases, vulns)
	out := []enrich.Claim{claim(a, subject, aliases, enrich.FactAffected, a.AdvisoryID, now)}
	facts := vulnFacts(a)
	for _, node := range aliases {
		for _, f := range facts {
			out = append(out, claim(a, node, nil, f.Fact, f.Value, now))
		}
	}
	return out
}

// aliasNodes are the vulnerability nodes the aliases name, in alias order,
// skipping every alias the stream carries no node for: an ABOUT edge to a
// node nothing else wrote would dangle (D5).
func aliasNodes(aliases []string, vulns map[string]varve.NodeID) []varve.NodeID {
	var out []varve.NodeID
	for _, alias := range aliases {
		if node, ok := vulns[strings.ToLower(strings.TrimSpace(alias))]; ok {
			out = append(out, node)
		}
	}
	return out
}

// vulnFacts is what the advisory states about the vulnerability itself. A fact
// whose value would be empty is not emitted.
func vulnFacts(a advisory) []enrich.FactValue {
	facts := []enrich.FactValue{
		{Fact: enrich.FactAdvisoryID, Value: a.AdvisoryID},
		{Fact: enrich.FactDescription, Value: a.Summary},
	}
	sevs := make([]enrich.Severity, len(a.Severities))
	for i, s := range a.Severities {
		sevs[i] = enrich.Severity{System: s.ScoringSystem, Score: s.Value, Elements: s.ScoringElements}
	}
	if s, ok := enrich.CVSS(sevs); ok {
		facts = append(facts,
			enrich.FactValue{Fact: enrich.FactCVSS, Value: s.Score},
			enrich.FactValue{Fact: enrich.FactCVSSVersion, Value: s.Version()},
			enrich.FactValue{Fact: enrich.FactCVSSVector, Value: s.Elements},
		)
	}
	if s, ok := enrich.EPSS(sevs); ok {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactEPSS, Value: s.Score})
	}
	for _, r := range a.References {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactReference, Value: r.URL})
	}
	for _, f := range a.FixedBy {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactFixedBy, Value: f})
	}

	kept := make([]enrich.FactValue, 0, len(facts))
	for _, f := range facts {
		if f.Value != "" {
			kept = append(kept, f)
		}
	}
	return kept
}

// claim renders one fact. ValidFrom is FetchedAt: the V3 response carries no
// advisory date (D7).
func claim(a advisory, subject varve.NodeID, also []varve.NodeID, fact enrich.Fact, value string, now time.Time) enrich.Claim {
	return enrich.Claim{
		Source:    enrich.SourceVulnerableCode,
		Subject:   subject,
		Also:      also,
		Fact:      fact,
		Value:     value,
		Ref:       a.AdvisoryUID,
		ValidFrom: now,
		FetchedAt: now,
	}
}
