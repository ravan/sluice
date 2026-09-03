// Package euvd asks ENISA's European Vulnerability Database about the
// vulnerability names a document already carries, and returns what it said as
// enrich.Claim records.
package euvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// DefaultURL is the public EUVD API base.
const DefaultURL = "https://euvdservices.enisa.europa.eu/api"

// dateLayout is the format every EUVD date field carries.
const dateLayout = "Jan 2, 2006, 3:04:05 PM"

// ErrStatus is returned when the API answers with anything but 200.
var ErrStatus = errors.New("euvd: unexpected status")

// Enricher is the EUVD source as the pipeline sees it.
type Enricher struct {
	base   *url.URL
	client *http.Client
}

// item is one EUVD record as the search endpoint returns it.
type item struct {
	ID, Description, DatePublished, DateUpdated string
	BaseScore                                   float64
	BaseScoreVersion, BaseScoreVector           string
	References, Aliases, Assigner               string
	EPSS                                        float64 `json:"epss"`
}

// page is one search response.
type page struct {
	Items []item `json:"items"`
	Total int    `json:"total"`
}

// New builds an Enricher against baseURL, defaulting the client.
func New(baseURL string, client *http.Client) (*Enricher, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("euvd: parse base url %q: %w", baseURL, err)
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Enricher{base: u, client: client}, nil
}

// Source names this enricher.
func (e *Enricher) Source() enrich.Source { return enrich.SourceEUVD }

// Enrich asks EUVD about every cve or euvd vulnerability name in the stream.
func (e *Enricher) Enrich(ctx context.Context, in enrich.Input) ([]enrich.Claim, error) {
	var out []enrich.Claim
	for _, name := range enrich.VulnNames(in.Records) {
		p, err := e.search(ctx, name)
		if err != nil {
			return nil, err
		}
		for _, it := range p.Items {
			if !matches(name, it) {
				continue
			}
			out = append(out, claimsFor(subjectOf(name), it, in.Now)...)
		}
	}
	return out, nil
}

// search runs one GET against the search endpoint.
func (e *Enricher) search(ctx context.Context, name string) (p page, err error) {
	u := e.base.JoinPath("search")
	q := url.Values{}
	q.Set("text", name)
	q.Set("size", "10")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return page{}, fmt.Errorf("euvd: request %s: %w", name, err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return page{}, fmt.Errorf("euvd: get %s: %w", name, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("euvd: close %s: %w", name, cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return page{}, fmt.Errorf("%w: %d for %s", ErrStatus, resp.StatusCode, name)
	}
	if derr := json.NewDecoder(resp.Body).Decode(&p); derr != nil {
		return page{}, fmt.Errorf("euvd: decode %s: %w", name, derr)
	}
	return p, nil
}

// subjectOf names the vulnerability node a claim about name hangs off.
func subjectOf(name string) varve.NodeID {
	typ := "cve"
	if strings.HasPrefix(strings.ToLower(name), "euvd-") {
		typ = "euvd"
	}
	return assemble.VulnID(typ, name)
}

// matches reports whether it answers to name, by id or by alias.
func matches(name string, it item) bool {
	if strings.EqualFold(name, it.ID) {
		return true
	}
	for _, alias := range strings.Split(it.Aliases, "\n") {
		if strings.EqualFold(name, strings.TrimSpace(alias)) && strings.TrimSpace(alias) != "" {
			return true
		}
	}
	return false
}

// parseDate reads one EUVD date as UTC.
func parseDate(s string) (time.Time, bool) {
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// claimsFor renders one item's facts about subject.
func claimsFor(subject varve.NodeID, it item, now time.Time) []enrich.Claim {
	validFrom := now
	updated, ok := parseDate(it.DateUpdated)
	if ok {
		validFrom = updated
	}
	facts := []enrich.FactValue{
		{Fact: enrich.FactEUVDID, Value: it.ID},
		{Fact: enrich.FactCVSS, Value: strconv.FormatFloat(it.BaseScore, 'f', -1, 64)},
		{Fact: enrich.FactCVSSVersion, Value: it.BaseScoreVersion},
		{Fact: enrich.FactCVSSVector, Value: it.BaseScoreVector},
		{Fact: enrich.FactEPSS, Value: strconv.FormatFloat(it.EPSS, 'f', -1, 64)},
		{Fact: enrich.FactDescription, Value: it.Description},
	}
	if published, ok := parseDate(it.DatePublished); ok {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactPublished, Value: published.Format(time.RFC3339)})
	}
	if ok {
		facts = append(facts, enrich.FactValue{Fact: enrich.FactUpdated, Value: updated.Format(time.RFC3339)})
	}
	for _, ref := range strings.Split(it.References, "\n") {
		if ref = strings.TrimSpace(ref); ref != "" {
			facts = append(facts, enrich.FactValue{Fact: enrich.FactReference, Value: ref})
		}
	}

	claims := make([]enrich.Claim, 0, len(facts))
	for _, f := range facts {
		claims = append(claims, enrich.Claim{
			Source:       enrich.SourceEUVD,
			Jurisdiction: enrich.EU,
			Subject:      subject,
			Fact:         f.Fact,
			Value:        f.Value,
			Ref:          it.ID,
			ValidFrom:    validFrom,
			FetchedAt:    now,
		})
	}
	return claims
}
