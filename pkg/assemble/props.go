package assemble

// The property-key vocabulary of the flattened graph, alongside the label and
// edge vocabularies in ids.go. Enrichment reads evidence nodes back by these
// names (pkg/enrich reads subjectId, collector, documentRef and the per-scanner
// value keys), so a key is a cross-package contract, not private spelling.
const (
	PropSubjectID = "subjectId"
	PropObjectID  = "objectId"

	PropType      = "type"
	PropNamespace = "namespace"
	PropName      = "name"
	PropVersion   = "version"

	PropQualifiers = "qualifiers"
	PropSubpath    = "subpath"
	PropPurl       = "purl"
	PropTag        = "tag"
	PropCommit     = "commit"
	PropAlgorithm  = "algorithm"
	PropDigest     = "digest"
	PropURI        = "uri"
	PropVulnID     = "vulnID"
	PropInline     = "inline"

	PropListVersion = "listVersion"

	PropOrigin        = "origin"
	PropCollector     = "collector"
	PropDocumentRef   = "documentRef"
	PropJustification = "justification"

	PropKnownSince  = "knownSince"
	PropTimeScanned = "timeScanned"
	PropTimestamp   = "timestamp"
	PropSince       = "since"
	PropStartedOn   = "startedOn"
	PropFinishedOn  = "finishedOn"

	PropDependencyType = "dependencyType"

	PropDBURI          = "dbUri"
	PropDBVersion      = "dbVersion"
	PropScannerURI     = "scannerUri"
	PropScannerVersion = "scannerVersion"

	PropDownloadLocation     = "downloadLocation"
	PropIncludedSoftware     = "includedSoftware"
	PropIncludedDependencies = "includedDependencies"
	PropIncludedOccurrences  = "includedOccurrences"

	PropStatus           = "status"
	PropVexJustification = "vexJustification"
	PropStatement        = "statement"
	PropStatusNotes      = "statusNotes"

	PropKey   = "key"
	PropValue = "value"
	PropEmail = "email"
	PropInfo  = "info"

	PropMembers    = "members"
	PropScoreType  = "scoreType"
	PropScoreValue = "scoreValue"

	PropBuiltByID   = "builtById"
	PropBuiltFrom   = "builtFrom"
	PropBuildType   = "buildType"
	PropSlsaVersion = "slsaVersion"
	PropPredicates  = "predicates"

	PropAggregateScore   = "aggregateScore"
	PropScorecardVersion = "scorecardVersion"
	PropScorecardCommit  = "scorecardCommit"
	PropChecks           = "checks"

	PropDeclaredLicense    = "declaredLicense"
	PropDiscoveredLicense  = "discoveredLicense"
	PropDeclaredLicenses   = "declaredLicenses"
	PropDiscoveredLicenses = "discoveredLicenses"
	PropAttribution        = "attribution"
)
