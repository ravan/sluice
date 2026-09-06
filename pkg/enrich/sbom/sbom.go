// Package sbom reads the supplier a document states for each of its own
// components, and returns those statements as enrich.Claim records. It calls
// no host: the document already carries the answer.
package sbom

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// Enricher is the sbom source as the pipeline sees it.
type Enricher struct{}

// New builds the Enricher. It has nothing to configure.
func New() *Enricher { return &Enricher{} }

// Source names this enricher.
func (e *Enricher) Source() enrich.Source { return enrich.SourceSBOM }

// cdxComponent is one CycloneDX component, and the components it nests.
type cdxComponent struct {
	PURL     string `json:"purl"`
	Supplier struct {
		Name string `json:"name"`
	} `json:"supplier"`
	Components []cdxComponent `json:"components"`
}

// cyclonedx is the part of a CycloneDX document this reads.
type cyclonedx struct {
	Components []cdxComponent `json:"components"`
}

// spdxPackage is one SPDX package and the external refs that name its purl.
type spdxPackage struct {
	SPDXID       string `json:"SPDXID"`
	Supplier     string `json:"supplier"`
	ExternalRefs []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

// spdxDoc is the part of an SPDX document this reads.
type spdxDoc struct {
	DocumentDescribes []string      `json:"documentDescribes"`
	Packages          []spdxPackage `json:"packages"`
}

// format is the top-level shape, the only thing read before the format is known.
type format struct {
	BOMFormat   string `json:"bomFormat"`
	SPDXVersion string `json:"spdxVersion"`
}

// Suppliers is the per-component supplier name a CycloneDX 1.x or SPDX 2.x JSON
// document states, by purl. The root component (CycloneDX metadata.component,
// the SPDX document's described package) is never read. Any other document, or
// bytes that are not JSON, is an empty map and a nil error.
func Suppliers(doc []byte) map[string]string {
	out := map[string]string{}
	var f format
	if err := json.Unmarshal(doc, &f); err != nil {
		return out
	}
	switch {
	case f.BOMFormat == "CycloneDX":
		var d cyclonedx
		if err := json.Unmarshal(doc, &d); err != nil {
			return out
		}
		walkComponents(d.Components, out)
	case f.SPDXVersion != "":
		var d spdxDoc
		if err := json.Unmarshal(doc, &d); err != nil {
			return out
		}
		for _, p := range d.Packages {
			if slices.Contains(d.DocumentDescribes, p.SPDXID) {
				continue
			}
			name := SupplierName(p.Supplier)
			if name == "" {
				continue
			}
			for _, ref := range p.ExternalRefs {
				if ref.ReferenceType == "purl" && ref.ReferenceLocator != "" {
					out[ref.ReferenceLocator] = name
				}
			}
		}
	}
	return out
}

// walkComponents records every component's supplier, nested ones included.
func walkComponents(comps []cdxComponent, out map[string]string) {
	for _, c := range comps {
		if c.PURL != "" && c.Supplier.Name != "" {
			out[c.PURL] = c.Supplier.Name
		}
		walkComponents(c.Components, out)
	}
}

// SupplierName reads an SPDX supplier: "Organization: Acme GmbH (ops@acme.example)" → "Acme GmbH",
// "Person: Jane Doe" → "Jane Doe", "NOASSERTION", "NONE" and "" → "".
func SupplierName(spdx string) string {
	s := strings.TrimSpace(spdx)
	if s == "" || s == "NOASSERTION" || s == "NONE" {
		return ""
	}
	if _, rest, ok := strings.Cut(s, ": "); ok {
		s = rest
	}
	if i := strings.LastIndex(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// Enrich states one supplier claim per component the document names and the
// stream carries a PkgVersion node for, in purl order.
func (e *Enricher) Enrich(_ context.Context, in enrich.Input) ([]enrich.Claim, error) {
	suppliers := Suppliers(in.Document)
	purls := make([]string, 0, len(suppliers))
	for purl := range suppliers {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	var out []enrich.Claim
	for _, purl := range purls {
		name := suppliers[purl]
		node, ok := pkgNode(in.Records, purl)
		if !ok || name == "" {
			continue
		}
		out = append(out, enrich.Claim{
			Source:    enrich.SourceSBOM,
			Subject:   node.ID,
			Fact:      enrich.FactSupplier,
			Value:     name,
			Ref:       in.Digest,
			ValidFrom: node.ValidFrom,
			FetchedAt: in.Now,
		})
	}
	return out, nil
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
