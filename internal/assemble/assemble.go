package assemble

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/ravan/sluice/internal/validtime"
	"github.com/ravan/sluice/internal/varve"
)

// builder accumulates the flattened graph for a set of documents, deduplicating
// every node and edge by its deterministic id (first write wins; a repeat is
// byte-identical, so first-wins == any-wins). It is the only stateful object in
// the package; all mapping funcs write through it.
type builder struct {
	nodes     map[varve.NodeID]varve.NodeRecord
	edges     map[varve.EdgeID]varve.EdgeRecord
	order     []varve.NodeID
	guard     validtime.Guard
	now       time.Time
	cur       time.Time
	nodeVF    map[varve.NodeID]time.Time
	edgeVF    map[varve.EdgeID]time.Time
	fallbacks int
}

func newBuilder(guard validtime.Guard, now time.Time) *builder {
	return &builder{
		nodes:  map[varve.NodeID]varve.NodeRecord{},
		edges:  map[varve.EdgeID]varve.EdgeRecord{},
		guard:  guard,
		now:    now,
		nodeVF: map[varve.NodeID]time.Time{},
		edgeVF: map[varve.EdgeID]time.Time{},
	}
}

// AssembleResult is Assemble's return: the stamped stream plus the count of
// evidence assertions whose timestamp fell back to ingest time (§2.4, §6 inv. 9).
type AssembleResult struct {
	Stream    varve.Stream
	Fallbacks int
}

// beginAssertion resolves the current assertion's native timestamp under the
// guard, sets cur (folded into every node/edge the assertion then touches), and
// counts a fallback. It is the FIRST statement of each mapping's per-item loop.
func (b *builder) beginAssertion(t *time.Time) {
	vf, fallback := b.guard.Resolve(t, b.now)
	b.cur = vf
	if fallback {
		b.fallbacks++
	}
}

// foldNodeVF keeps the earliest non-zero valid_from seen for id (dedup takes the
// min, so identity nodes reflect the earliest asserting document, §2.4).
func (b *builder) foldNodeVF(id varve.NodeID) {
	if b.cur.IsZero() {
		return
	}
	if prev, ok := b.nodeVF[id]; !ok || b.cur.Before(prev) {
		b.nodeVF[id] = b.cur
	}
}

// foldEdgeVF is identical, over edgeVF keyed by varve.EdgeID.
func (b *builder) foldEdgeVF(id varve.EdgeID) {
	if b.cur.IsZero() {
		return
	}
	if prev, ok := b.edgeVF[id]; !ok || b.cur.Before(prev) {
		b.edgeVF[id] = b.cur
	}
}

// addNode inserts a node record if its id is unseen (dedup). props omit any
// empty-string value (§6 inv. 3: absence is omission); _id is added by the
// emitter, not here.
func (b *builder) addNode(id varve.NodeID, label varve.NodeLabel, props []varve.Prop) {
	b.foldNodeVF(id)
	if _, ok := b.nodes[id]; ok {
		return
	}
	kept := make([]varve.Prop, 0, len(props))
	for _, p := range props {
		if s, ok := p.Value.(varve.Str); ok && s == "" {
			continue
		}
		kept = append(kept, p)
	}
	b.nodes[id] = varve.NodeRecord{ID: id, Labels: []varve.NodeLabel{label}, Props: kept}
	b.order = append(b.order, id)
}

// addEdge inserts one semantic edge (dedup by EdgeIDFor). A silent no-op if
// either endpoint id is empty.
func (b *builder) addEdge(src varve.NodeID, label varve.EdgeLabel, dst varve.NodeID) {
	if src == "" || dst == "" {
		return
	}
	id := EdgeIDFor(src, label, dst)
	b.foldEdgeVF(id)
	if _, ok := b.edges[id]; ok {
		return
	}
	b.edges[id] = varve.EdgeRecord{ID: id, Label: label, Src: src, Dst: dst}
}

// addPackage ensures the PkgVersion+PkgName nodes and their PkgHasVersion edge
// exist for p, returning both ids. A nil *PkgInputSpec adds nothing and returns
// ("", "").
func (b *builder) addPackage(p *generated.PkgInputSpec) (nameID, versionID varve.NodeID) {
	if p == nil {
		return "", ""
	}
	namespace := deref(p.Namespace)
	version := deref(p.Version)
	subpath := deref(p.Subpath)
	canonQuals := CanonQualifiers(p.Qualifiers)

	versionID = PkgVersionID(p.Type, namespace, p.Name, version, canonQuals, subpath)
	nameID = PkgNameID(p.Type, namespace, p.Name)

	purl := helpers.PkgToPurl(p.Type, namespace, p.Name, version, subpath, qualifierList(p.Qualifiers))
	b.addNode(versionID, LabelPkgVersion, []varve.Prop{
		{Key: "type", Value: varve.Str(p.Type)},
		{Key: "namespace", Value: varve.Str(namespace)},
		{Key: "name", Value: varve.Str(p.Name)},
		{Key: "version", Value: varve.Str(version)},
		{Key: "qualifiers", Value: varve.Str(canonQuals)},
		{Key: "subpath", Value: varve.Str(subpath)},
		{Key: "purl", Value: varve.Str(purl)},
	})
	b.addNode(nameID, LabelPkgName, []varve.Prop{
		{Key: "type", Value: varve.Str(p.Type)},
		{Key: "namespace", Value: varve.Str(namespace)},
		{Key: "name", Value: varve.Str(p.Name)},
	})
	b.addEdge(nameID, EdgePkgHasVersion, versionID)
	return nameID, versionID
}

// addSource ensures the SrcName node exists, returning its id. Nil → "".
func (b *builder) addSource(s *generated.SourceInputSpec) varve.NodeID {
	if s == nil {
		return ""
	}
	tag := deref(s.Tag)
	commit := deref(s.Commit)
	id := SrcNameID(s.Type, s.Namespace, s.Name, tag, commit)
	b.addNode(id, LabelSrcName, []varve.Prop{
		{Key: "type", Value: varve.Str(s.Type)},
		{Key: "namespace", Value: varve.Str(s.Namespace)},
		{Key: "name", Value: varve.Str(s.Name)},
		{Key: "tag", Value: varve.Str(tag)},
		{Key: "commit", Value: varve.Str(commit)},
	})
	return id
}

// addArtifact ensures the Artifact node exists, returning its id. Nil → "".
func (b *builder) addArtifact(a *generated.ArtifactInputSpec) varve.NodeID {
	if a == nil {
		return ""
	}
	id := ArtifactID(a.Algorithm, a.Digest)
	b.addNode(id, LabelArtifact, []varve.Prop{
		{Key: "algorithm", Value: varve.Str(strings.ToLower(a.Algorithm))},
		{Key: "digest", Value: varve.Str(strings.ToLower(a.Digest))},
	})
	return id
}

// addVulnerability ensures the Vulnerability node exists, returning its id. The
// novuln sentinel collapses to "vuln:novuln" with only its type prop. Nil → "".
func (b *builder) addVulnerability(v *generated.VulnerabilityInputSpec) varve.NodeID {
	if v == nil {
		return ""
	}
	id := VulnID(v.Type, v.VulnerabilityID)
	vulnID := strings.ToLower(v.VulnerabilityID)
	if id == "vuln:novuln" {
		vulnID = ""
	}
	b.addNode(id, LabelVulnerability, []varve.Prop{
		{Key: "type", Value: varve.Str(strings.ToLower(v.Type))},
		{Key: "vulnID", Value: varve.Str(vulnID)},
	})
	return id
}

// addBuilder ensures the Builder node exists, returning its id. Nil → "".
func (b *builder) addBuilder(bd *generated.BuilderInputSpec) varve.NodeID {
	if bd == nil {
		return ""
	}
	id := BuilderID(bd.Uri)
	b.addNode(id, LabelBuilder, []varve.Prop{
		{Key: "uri", Value: varve.Str(bd.Uri)},
	})
	return id
}

// addLicense ensures the License node exists, returning its id.
func (b *builder) addLicense(l generated.LicenseInputSpec) varve.NodeID {
	id := LicenseID(l.Name, l.Inline)
	b.addNode(id, LabelLicense, []varve.Prop{
		{Key: "name", Value: varve.Str(l.Name)},
		{Key: "inline", Value: varve.Str(deref(l.Inline))},
		{Key: "listVersion", Value: varve.Str(deref(l.ListVersion))},
	})
	return id
}

// pkgSubjectID resolves a package subject at the level MatchFlags selects: the
// PkgName id when flag.Pkg == ALL_VERSIONS, else the PkgVersion id.
func (b *builder) pkgSubjectID(p *generated.PkgInputSpec, flag generated.MatchFlags) (varve.NodeID, varve.NodeLabel) {
	nameID, versionID := b.addPackage(p)
	if nameID == "" {
		return "", ""
	}
	if flag.Pkg == generated.PkgMatchTypeAllVersions {
		return nameID, LabelPkgName
	}
	return versionID, LabelPkgVersion
}

// psaSubject resolves the single non-nil subject of a package|source|artifact
// evidence, honoring MatchFlags on the package arm.
func (b *builder) psaSubject(pkg *generated.PkgInputSpec, flag generated.MatchFlags, src *generated.SourceInputSpec, art *generated.ArtifactInputSpec) (varve.NodeID, varve.NodeLabel) {
	if pkg != nil {
		return b.pkgSubjectID(pkg, flag)
	}
	if src != nil {
		return b.addSource(src), LabelSrcName
	}
	if art != nil {
		return b.addArtifact(art), LabelArtifact
	}
	return "", ""
}

// Stream returns the accumulated nodes and edges, each sorted by id, so the
// emitted NDJSON is byte-deterministic for a given input (§6 inv. 2).
func (b *builder) Stream() varve.Stream {
	nodes := make([]varve.NodeRecord, 0, len(b.nodes))
	for _, n := range b.nodes {
		n.ValidFrom = b.nodeVF[n.ID]
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := make([]varve.EdgeRecord, 0, len(b.edges))
	for _, e := range b.edges {
		e.ValidFrom = b.edgeVF[e.ID]
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })

	return varve.Stream{Nodes: nodes, Edges: edges}
}

// Assemble maps every predicate list of every element of preds into the
// flattened graph and returns one deduplicated, id-sorted Stream. Package
// identity is ensured first for the whole dedup set, so a document asserting
// only e.g. HasSBOM still yields its packages (§10.1).
func Assemble(ctx context.Context, preds []assembler.IngestPredicates, guard validtime.Guard, now time.Time) AssembleResult {
	b := newBuilder(guard, now)
	for _, p := range preds {
		b.cur = b.now
		for _, idp := range p.GetPackages(ctx) {
			b.addPackage(idp.PackageInput)
		}
		b.mapIsDependency(p.IsDependency)
		b.mapCertifyVuln(p.CertifyVuln)
		b.mapHasSourceAt(p.HasSourceAt)
		b.mapIsOccurrence(p.IsOccurrence)
		b.mapHasSBOM(p.HasSBOM)
		b.mapVex(p.Vex)
		b.mapCertifyBad(p.CertifyBad)
		b.mapCertifyGood(p.CertifyGood)
		b.mapHasMetadata(p.HasMetadata)
		b.mapPointOfContact(p.PointOfContact)
		b.mapHashEqual(p.HashEqual)
		b.mapPkgEqual(p.PkgEqual)
		b.mapVulnEqual(p.VulnEqual)
		b.mapVulnMetadata(p.VulnMetadata)
		b.mapHasSlsa(p.HasSlsa)
		b.mapCertifyScorecard(p.CertifyScorecard)
		b.mapCertifyLegal(p.CertifyLegal)
	}
	return AssembleResult{Stream: b.Stream(), Fallbacks: b.fallbacks}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func qualifierList(quals []generated.PackageQualifierInputSpec) []string {
	if len(quals) == 0 {
		return nil
	}
	sorted := make([]generated.PackageQualifierInputSpec, len(quals))
	copy(sorted, quals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	out := make([]string, 0, len(sorted)*2)
	for _, q := range sorted {
		out = append(out, q.Key, q.Value)
	}
	return out
}
