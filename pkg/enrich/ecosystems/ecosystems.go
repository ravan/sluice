// Package ecosystems asks packages.ecosyste.ms who owns the repository a
// package is published from, and returns that owner as the package's supplier.
package ecosystems

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// DefaultURL is the public instance that answers.
const DefaultURL = "https://packages.ecosyste.ms"

// lookupPath is the purl-keyed lookup endpoint.
const lookupPath = "api/v1/packages/lookup"

// ErrStatus is returned when the API answers with anything but 200.
var ErrStatus = errors.New("ecosystems: unexpected status")

// Enricher is the ecosystems source as the pipeline sees it.
type Enricher struct {
	base   *url.URL
	client *http.Client
}

// record is the part of one lookup result this reads.
type record struct {
	RepositoryURL string `json:"repository_url"`
	RepoMetadata  struct {
		OwnerRecord struct {
			Name string `json:"name"`
		} `json:"owner_record"`
	} `json:"repo_metadata"`
}

// New builds an Enricher against baseURL. A bad URL is an error; a nil client
// is a 20 s-timeout client.
func New(baseURL string, client *http.Client) (*Enricher, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("ecosystems: parse base url %q: %w", baseURL, err)
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Enricher{base: u, client: client}, nil
}

// Source names this enricher.
func (e *Enricher) Source() enrich.Source { return enrich.SourceEcosystems }

// Enrich asks about every package version the stream names, in purl order.
func (e *Enricher) Enrich(ctx context.Context, in enrich.Input) ([]enrich.Claim, error) {
	var out []enrich.Claim
	for _, purl := range enrich.PkgPurls(in.Records) {
		recs, err := e.lookup(ctx, purl)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 || recs[0].RepoMetadata.OwnerRecord.Name == "" {
			continue
		}
		node, ok := pkgNode(in.Records, purl)
		if !ok {
			continue
		}
		out = append(out, enrich.Claim{
			Source:    enrich.SourceEcosystems,
			Subject:   node.ID,
			Fact:      enrich.FactSupplier,
			Value:     recs[0].RepoMetadata.OwnerRecord.Name,
			Ref:       recs[0].RepositoryURL,
			ValidFrom: in.Now,
			FetchedAt: in.Now,
		})
	}
	return out, nil
}

// lookup runs one GET against the packages lookup endpoint.
func (e *Enricher) lookup(ctx context.Context, purl string) (recs []record, err error) {
	u := e.base.JoinPath(lookupPath)
	q := url.Values{}
	q.Set("purl", purl)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("ecosystems: request %s: %w", purl, err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ecosystems: get %s: %w", purl, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("ecosystems: close %s: %w", purl, cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d for %s", ErrStatus, resp.StatusCode, purl)
	}
	if derr := json.NewDecoder(resp.Body).Decode(&recs); derr != nil {
		return nil, fmt.Errorf("ecosystems: decode %s: %w", purl, derr)
	}
	return recs, nil
}

// pkgNode finds the PkgVersion node carrying exactly this purl.
func pkgNode(s varve.Stream, purl string) (varve.NodeRecord, bool) {
	for _, n := range s.Nodes {
		if !slices.Contains(n.Labels, assemble.LabelPkgVersion) {
			continue
		}
		for _, p := range n.Props {
			if p.Key != assemble.PropPurl {
				continue
			}
			if v, ok := p.Value.AsString(); ok && v == purl {
				return n, true
			}
		}
	}
	return varve.NodeRecord{}, false
}
