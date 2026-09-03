// Licensing evidence.

package assemble

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/pkg/varve"
)

func (b *builder) mapCertifyLegal(legals []assembler.CertifyLegalIngest) {
	for _, c := range legals {
		if c.CertifyLegal == nil {
			continue
		}
		cl := c.CertifyLegal
		b.beginAssertion(&cl.TimeScanned)
		subjID := b.pkgOrSrcSubject(c.Pkg, c.Src)
		declared := make([]varve.NodeID, 0, len(c.Declared))
		for _, l := range c.Declared {
			declared = append(declared, b.addLicense(l))
		}
		discovered := make([]varve.NodeID, 0, len(c.Discovered))
		for _, l := range c.Discovered {
			discovered = append(discovered, b.addLicense(l))
		}
		declaredJoin := joinIDs(declared)
		discoveredJoin := joinIDs(discovered)
		evID := EvidenceID(LabelCertifyLegal, string(subjID),
			cl.DeclaredLicense, cl.DiscoveredLicense, cl.Attribution, cl.Justification, fmtTime(cl.TimeScanned),
			cl.Origin, cl.Collector, cl.DocumentRef, declaredJoin, discoveredJoin)
		b.addNode(evID, LabelCertifyLegal, []varve.Prop{
			{Key: PropSubjectID, Value: varve.Str(string(subjID))},
			{Key: PropDeclaredLicense, Value: varve.Str(cl.DeclaredLicense)},
			{Key: PropDiscoveredLicense, Value: varve.Str(cl.DiscoveredLicense)},
			{Key: PropAttribution, Value: varve.Str(cl.Attribution)},
			{Key: PropJustification, Value: varve.Str(cl.Justification)},
			{Key: PropTimeScanned, Value: varve.Str(fmtTime(cl.TimeScanned))},
			{Key: PropOrigin, Value: varve.Str(cl.Origin)},
			{Key: PropCollector, Value: varve.Str(cl.Collector)},
			{Key: PropDocumentRef, Value: varve.Str(cl.DocumentRef)},
			{Key: PropDeclaredLicenses, Value: varve.Str(declaredJoin)},
			{Key: PropDiscoveredLicenses, Value: varve.Str(discoveredJoin)},
		})
		b.addEdge(subjID, EdgeCertifyLegalSubject, evID)
		for _, lic := range declared {
			b.addEdge(evID, EdgeCertifyLegalDeclaredLicense, lic)
		}
		for _, lic := range discovered {
			b.addEdge(evID, EdgeCertifyLegalDiscoveredLicense, lic)
		}
	}
}
