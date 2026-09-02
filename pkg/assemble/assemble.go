package assemble

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

// builder accumulates the flattened graph for a set of documents. Every
// addNode/addEdge appends a record stamped with the current assertion's
// valid_from; Stream() dedups the lot through varve.Merge (first write wins,
// earliest valid_from wins) so the one dedup rule lives in one place. It is
// the only stateful object in the package; all mapping funcs write through it.
type builder struct {
	nodes     []varve.NodeRecord
	edges     []varve.EdgeRecord
	guard     validtime.Guard
	now       time.Time
	cur       time.Time
	earliest  time.Time // earliest native (non-fallback) assertion time seen
	fallbacks int
}

func newBuilder(guard validtime.Guard, now time.Time) *builder {
	return &builder{guard: guard, now: now}
}

// AssembleResult is Assemble's return: the stamped stream, the count of
// evidence assertions whose timestamp fell back to ingest time (§2.4, §6 inv.
// 9), and the document-level valid time. ValidFrom is the earliest native
// assertion time the guard accepted; when no assertion carried an acceptable
// time it is the ingest time and Fallback is true.
type AssembleResult struct {
	Stream    varve.Stream
	Fallbacks int
	ValidFrom time.Time
	Fallback  bool
}

// beginAssertion resolves the current assertion's native timestamp under the
// guard, sets cur (folded into every node/edge the assertion then touches), and
// counts a fallback. It is the FIRST statement of each mapping's per-item loop.
func (b *builder) beginAssertion(t *time.Time) {
	vf, fallback := b.guard.Resolve(t, b.now)
	b.cur = vf
	if fallback {
		b.fallbacks++
		return
	}
	if b.earliest.IsZero() || vf.Before(b.earliest) {
		b.earliest = vf
	}
}

// addNode appends a node record stamped with cur. props omit any empty-string
// value (§6 inv. 3: absence is omission); _id is added by the emitter, not
// here. Repeats of the same id collapse in Stream().
func (b *builder) addNode(id varve.NodeID, label varve.NodeLabel, props []varve.Prop) {
	kept := make([]varve.Prop, 0, len(props))
	for _, p := range props {
		if s, ok := p.Value.(varve.Str); ok && s == "" {
			continue
		}
		kept = append(kept, p)
	}
	b.nodes = append(b.nodes, varve.NodeRecord{ID: id, Labels: []varve.NodeLabel{label}, Props: kept, ValidFrom: b.cur})
}

// addEdge appends one semantic edge (id by EdgeIDFor) stamped with cur. A
// silent no-op if either endpoint id is empty.
func (b *builder) addEdge(src varve.NodeID, label varve.EdgeLabel, dst varve.NodeID) {
	if src == "" || dst == "" {
		return
	}
	b.edges = append(b.edges, varve.EdgeRecord{ID: EdgeIDFor(src, label, dst), Label: label, Src: src, Dst: dst, ValidFrom: b.cur})
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

// Stream dedups the accumulated records through varve.Merge and sorts nodes
// and edges by id, so the emitted NDJSON is byte-deterministic for a given
// input (§6 inv. 2).
func (b *builder) Stream() varve.Stream {
	s := varve.Merge(varve.Stream{Nodes: b.nodes, Edges: b.edges})
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].ID < s.Nodes[j].ID })
	sort.Slice(s.Edges, func(i, j int) bool { return s.Edges[i].ID < s.Edges[j].ID })
	return s
}

// result finalises the builder into an AssembleResult.
func (b *builder) result() AssembleResult {
	res := AssembleResult{Stream: b.Stream(), Fallbacks: b.fallbacks, ValidFrom: b.earliest}
	if res.ValidFrom.IsZero() {
		res.ValidFrom = b.now
		res.Fallback = true
	}
	return res
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
	return b.result()
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
