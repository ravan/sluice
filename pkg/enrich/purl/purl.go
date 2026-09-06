// Package purl states who supplies a package from its purl alone: a namespace
// under a known project names its supplier, and often that supplier's country.
// It calls no host.
package purl

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// Rule states who supplies every package whose purl has this type and whose namespace starts with Namespace.
type Rule struct{ Type, Namespace, Supplier, Country string } // Country "" when the rule states none

// Rules is the table Lookup applies.
var Rules = []Rule{
	{"golang", "golang.org/x/", "Google LLC", "US"},
	{"golang", "github.com/golang/", "Google LLC", "US"},
	{"maven", "org.apache.", "The Apache Software Foundation", "US"},
	{"maven", "org.eclipse.", "Eclipse Foundation AISBL", "BE"},
	{"npm", "@angular/", "Google LLC", "US"},
	{"deb", "debian/", "Debian Project", ""},
	{"deb", "ubuntu/", "Canonical Ltd", "GB"},
	{"rpm", "opensuse/", "openSUSE Project", "DE"},
	{"rpm", "fedora/", "Fedora Project", "US"},
	{"rpm", "redhat/", "Red Hat, Inc.", "US"},
}

// Origin is what a matched rule states about the package.
type Origin struct{ Supplier, Country, Ref string } // Ref is Type + "/" + Namespace of the rule that matched

// Lookup applies the longest matching rule of the purl's type. ok is false when none matches or p is not a purl.
func Lookup(p string) (o Origin, ok bool) {
	typ, path, valid := split(p)
	if !valid {
		return Origin{}, false
	}
	var best Rule
	for _, r := range Rules {
		if r.Type != typ || !strings.HasPrefix(path, r.Namespace) {
			continue
		}
		if len(r.Namespace) > len(best.Namespace) {
			best = r
		}
	}
	if best.Namespace == "" {
		return Origin{}, false
	}
	return Origin{Supplier: best.Supplier, Country: best.Country, Ref: best.Type + "/" + best.Namespace}, true
}

// split reads a purl's type and the namespace-plus-name that follows it.
func split(p string) (typ, path string, ok bool) {
	rest, found := strings.CutPrefix(p, "pkg:")
	if !found {
		return "", "", false
	}
	typ, path, found = strings.Cut(rest, "/")
	if !found || typ == "" {
		return "", "", false
	}
	if i := strings.IndexAny(path, "@?#"); i >= 0 {
		path = path[:i]
	}
	return typ, path, true
}

// Enricher is the purl source as the pipeline sees it.
type Enricher struct{}

// New builds the Enricher. It has nothing to configure.
func New() *Enricher { return &Enricher{} }

// Source names this enricher.
func (e *Enricher) Source() enrich.Source { return enrich.SourcePURL }

// Enrich states a supplier, and where a rule knows one a country, for every
// package version the stream names whose purl a rule matches.
func (e *Enricher) Enrich(_ context.Context, in enrich.Input) ([]enrich.Claim, error) {
	var out []enrich.Claim
	for _, p := range enrich.PkgPurls(in.Records) {
		o, ok := Lookup(p)
		if !ok {
			continue
		}
		node, found := pkgNode(in.Records, p)
		if !found {
			continue
		}
		out = append(out, claim(node, enrich.FactSupplier, o.Supplier, o.Ref, in.Now))
		if o.Country != "" {
			out = append(out, claim(node, enrich.FactOriginCountry, o.Country, o.Ref, in.Now))
		}
	}
	return out, nil
}

// claim renders one fact about one package version.
func claim(node varve.NodeRecord, fact enrich.Fact, value, ref string, now time.Time) enrich.Claim {
	return enrich.Claim{
		Source:    enrich.SourcePURL,
		Subject:   node.ID,
		Fact:      fact,
		Value:     value,
		Ref:       ref,
		ValidFrom: node.ValidFrom,
		FetchedAt: now,
	}
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
