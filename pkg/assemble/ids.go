package assemble

import (
	"net/url"
	"sort"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/ravan/sluice/pkg/varve"
)

// The label vocabulary of the flattened two-level package model (§2.3).
// PkgHasVersion is the only structural package edge; type- and
// namespace-level questions are property filters, not hops.
const (
	LabelPkgVersion varve.NodeLabel = "PkgVersion"
	LabelPkgName    varve.NodeLabel = "PkgName"

	EdgePkgHasVersion varve.EdgeLabel = "PkgHasVersion"
)

// PkgVersionID joins escaped components as "pkg:v:<type>/<ns>/<name>/<version>+<canonQuals>+<subpath>".
func PkgVersionID(typ, namespace, name, version, canonQualifiers, subpath string) varve.NodeID {
	return varve.NodeID("pkg:v:" + identityPart(typ) + "/" + identityPart(namespace) + "/" + identityPart(name) + "/" + identityPart(version) + "+" + identityPart(canonQualifiers) + "+" + identityPart(subpath))
}

// PkgNameID joins escaped components as "pkg:n:<type>/<ns>/<name>".
func PkgNameID(typ, namespace, name string) varve.NodeID {
	return varve.NodeID("pkg:n:" + identityPart(typ) + "/" + identityPart(namespace) + "/" + identityPart(name))
}

// CanonQualifiers renders qualifiers as a sorted, order-independent "k=v&…"
// list, so the same package re-ingests to the same id whatever order a parser
// produced.
func CanonQualifiers(quals []generated.PackageQualifierInputSpec) string {
	sorted := make([]generated.PackageQualifierInputSpec, len(quals))
	copy(sorted, quals)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Key == sorted[j].Key {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].Key < sorted[j].Key
	})
	parts := make([]string, 0, len(sorted))
	for _, q := range sorted {
		parts = append(parts, url.QueryEscape(q.Key)+"="+url.QueryEscape(q.Value))
	}
	return strings.Join(parts, "&")
}

// EdgeIDFor joins percent-escaped fields as "<src>|<label>|<dst>".
func EdgeIDFor(src varve.NodeID, label varve.EdgeLabel, dst varve.NodeID) varve.EdgeID {
	return varve.EdgeID(edgePart(string(src)) + "|" + edgePart(string(label)) + "|" + edgePart(string(dst)))
}

// Identity-node labels (flattened two-level model; no PkgType/PkgNamespace/
// SrcType/SrcNamespace/VulnType — those trie levels are retired, §2.3/§7).
const (
	LabelSrcName       varve.NodeLabel = "SrcName"
	LabelArtifact      varve.NodeLabel = "Artifact"
	LabelBuilder       varve.NodeLabel = "Builder"
	LabelVulnerability varve.NodeLabel = "Vulnerability"
	LabelLicense       varve.NodeLabel = "License"
)

// Evidence-node labels — one per predicate kind (spec §2.3 list, verbatim).
const (
	LabelIsDependency     varve.NodeLabel = "IsDependency"
	LabelIsOccurrence     varve.NodeLabel = "IsOccurrence"
	LabelHasSBOM          varve.NodeLabel = "HasSBOM"
	LabelCertifyVuln      varve.NodeLabel = "CertifyVuln"
	LabelVex              varve.NodeLabel = "Vex"
	LabelHasSlsa          varve.NodeLabel = "HasSlsa"
	LabelCertifyScorecard varve.NodeLabel = "CertifyScorecard"
	LabelCertifyLegal     varve.NodeLabel = "CertifyLegal"
	LabelHasSourceAt      varve.NodeLabel = "HasSourceAt"
	LabelCertifyBad       varve.NodeLabel = "CertifyBad"
	LabelCertifyGood      varve.NodeLabel = "CertifyGood"
	LabelHashEqual        varve.NodeLabel = "HashEqual"
	LabelPkgEqual         varve.NodeLabel = "PkgEqual"
	LabelVulnEqual        varve.NodeLabel = "VulnEqual"
	LabelVulnMetadata     varve.NodeLabel = "VulnMetadata"
	LabelHasMetadata      varve.NodeLabel = "HasMetadata"
	LabelPointOfContact   varve.NodeLabel = "PointOfContact"
)

// Semantic edge labels. Each is a distinct first-class label (never a generic
// label discriminated by a `kind` property, §6 inv. 7): Varve's planner prunes
// on labels (§7).
const (
	EdgeIsDependencySubject varve.EdgeLabel = "IsDependencySubject"
	EdgeIsDependencyObject  varve.EdgeLabel = "IsDependencyObject"

	EdgeIsOccurrenceSubject  varve.EdgeLabel = "IsOccurrenceSubject"
	EdgeIsOccurrenceArtifact varve.EdgeLabel = "IsOccurrenceArtifact"

	EdgeHasSbomSubject varve.EdgeLabel = "HasSbomSubject"

	EdgeCertifyVulnSubject       varve.EdgeLabel = "CertifyVulnSubject"
	EdgeCertifyVulnVulnerability varve.EdgeLabel = "CertifyVulnVulnerability"

	EdgeVexSubject       varve.EdgeLabel = "VexSubject"
	EdgeVexVulnerability varve.EdgeLabel = "VexVulnerability"

	EdgeHasSlsaSubject  varve.EdgeLabel = "HasSlsaSubject"
	EdgeHasSlsaBuiltBy  varve.EdgeLabel = "HasSlsaBuiltBy"
	EdgeHasSlsaMaterial varve.EdgeLabel = "HasSlsaMaterial"

	EdgeCertifyScorecardSubject varve.EdgeLabel = "CertifyScorecardSubject"

	EdgeCertifyLegalSubject           varve.EdgeLabel = "CertifyLegalSubject"
	EdgeCertifyLegalDeclaredLicense   varve.EdgeLabel = "CertifyLegalDeclaredLicense"
	EdgeCertifyLegalDiscoveredLicense varve.EdgeLabel = "CertifyLegalDiscoveredLicense"

	EdgeHasSourceAtSubject varve.EdgeLabel = "HasSourceAtSubject"
	EdgeHasSourceAtSource  varve.EdgeLabel = "HasSourceAtSource"

	EdgeCertifyBadSubject     varve.EdgeLabel = "CertifyBadSubject"
	EdgeCertifyGoodSubject    varve.EdgeLabel = "CertifyGoodSubject"
	EdgeHasMetadataSubject    varve.EdgeLabel = "HasMetadataSubject"
	EdgePointOfContactSubject varve.EdgeLabel = "PointOfContactSubject"

	EdgeHashEqualArtifact         varve.EdgeLabel = "HashEqualArtifact"
	EdgePkgEqualPackage           varve.EdgeLabel = "PkgEqualPackage"
	EdgeVulnEqualVulnerability    varve.EdgeLabel = "VulnEqualVulnerability"
	EdgeVulnMetadataVulnerability varve.EdgeLabel = "VulnMetadataVulnerability"
)

// SrcNameID derives "src:n:<type>/<ns>/<name>@<tag>@<commit>". The flattened
// SrcName carries tag and commit in the natural key (spec §2.3): two refs to a
// repo at different commits are distinct nodes. Both '@' are always present so
// empty positions are encoded.
func SrcNameID(typ, namespace, name, tag, commit string) varve.NodeID {
	return varve.NodeID("src:n:" + typ + "/" + namespace + "/" + name + "@" + tag + "@" + commit)
}

// ArtifactID derives "art:<algo>:<digest>", both lowercased.
func ArtifactID(algorithm, digest string) varve.NodeID {
	return varve.NodeID("art:" + strings.ToLower(algorithm) + ":" + strings.ToLower(digest))
}

// BuilderID derives "bld:<uri>".
func BuilderID(uri string) varve.NodeID {
	return varve.NodeID("bld:" + uri)
}

// VulnID derives "vuln:<type>/<id>" (both lowercased). The GUAC "novuln"
// sentinel — type == "novuln" (case-insensitive) — collapses to the exact
// literal "vuln:novuln" (spec §2.3), whatever the id field holds.
func VulnID(typ, id string) varve.NodeID {
	if strings.EqualFold(typ, "novuln") {
		return varve.NodeID("vuln:novuln")
	}
	return varve.NodeID("vuln:" + strings.ToLower(typ) + "/" + strings.ToLower(id))
}

// LicenseID derives "lic:<name>" for a named license, or "lic:<sha256(hex)>"
// of the inline text when inline is non-empty (name is then ignored, so the
// same text always collapses to one node).
func LicenseID(name string, inline *string) varve.NodeID {
	if inline != nil && *inline != "" {
		return varve.NodeID("lic:" + hashParts("inline", *inline))
	}
	return varve.NodeID("lic:" + name)
}

// EvidenceID hashes length-prefixed fields, preserving every field boundary.
func EvidenceID(kind varve.NodeLabel, parts ...string) varve.NodeID {
	return varve.NodeID(string(kind) + ":" + hashParts(parts...))
}

// identityPart escapes delimiters and percent signs before composing an ID.
// Qualifier separators remain readable; their keys and values are escaped by
// CanonQualifiers before the whole qualifier field is escaped here.
func identityPart(s string) string {
	return strings.NewReplacer("%", "%25", "/", "%2F", "+", "%2B", "|", "%7C", "\n", "%0A", "\r", "%0D").Replace(s)
}

func edgePart(s string) string {
	return strings.NewReplacer("%", "%25", "|", "%7C").Replace(s)
}
