// Package federatedcode replays an AboutCode FederatedCode data repository.
// The data is git, so its commits are the source's own history and a claim
// carries the date the source stated the fact, not the date Silt read it.
package federatedcode

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/package-url/packageurl-go"
)

// PackagesPrefix is the directory prefix aboutcode.hashid buckets packages
// under.
const PackagesPrefix = "aboutcode-packages"

// VulnerabilitiesDir is the directory holding VulnerabilitiesFile for every
// VCID.
const VulnerabilitiesDir = "aboutcode-vulnerabilities"

// VulnerabilitiesFile is the filename a package's vulnerability data sits in.
const VulnerabilitiesFile = "vulnerabilities.yml"

// BitCounts is aboutcode.hashid's BIT_COUNT_BY_ECOSYSTEM: how many bits of a
// purl's hash name the bucket its type lives in. An absent type uses 0 bits.
var BitCounts = map[string]int{
	"github": 10,
	"npm":    10,

	"golang": 7,
	"maven":  7,
	"nuget":  7,
	"perl":   7,
	"php":    7,
	"pypi":   7,
	"ruby":   7,

	"alpm":        5,
	"bitbucket":   5,
	"cocoapods":   5,
	"composer":    5,
	"deb":         5,
	"docker":      5,
	"gem":         5,
	"generic":     5,
	"huggingface": 5,
	"mlflow":      5,
	"pub":         5,
	"rpm":         5,
}

// ErrPurl is returned when a purl will not parse.
var ErrPurl = errors.New("federatedcode: bad purl")

// CorePurl normalises a purl and drops version, qualifiers and subpath: the
// string the hash is taken over.
// verbatim exception — which fields survive is the decision, packageurl-go
// normalises on the way back out, and a wrong guess moves every hash.
func CorePurl(purl string) (string, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrPurl, purl, err)
	}
	return packageurl.NewPackageURL(p.Type, p.Namespace, p.Name, "", nil, "").ToString(), nil
}

// PurlHash is aboutcode.hashid's get_purl_hash.
// verbatim exception — the arithmetic is a contract with another language's
// library and every doctest value depends on each step of it.
func PurlHash(corePurl string, bits int) string {
	sum := sha256.Sum256([]byte(corePurl))
	n := new(big.Int).SetBytes(sum[:])
	n.Mod(n, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	return fmt.Sprintf("%0*x", (bits+3)/4, n)
}

// PackagePath is where one package's data files sit in a data repository.
type PackagePath struct {
	Bucket string // "aboutcode-packages-npm-026"
	Core   string // "npm/lodash"
}

// Dir joins Bucket and Core: the directory holding VulnerabilitiesFile.
func (p PackagePath) Dir() string {
	return p.Bucket + "/" + p.Core
}

// PathFor is aboutcode.hashid's get_package_base_dir.
func PathFor(purl string) (PackagePath, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return PackagePath{}, fmt.Errorf("%w: %q: %w", ErrPurl, purl, err)
	}

	core, err := CorePurl(purl)
	if err != nil {
		return PackagePath{}, err
	}

	hash := PurlHash(core, BitCounts[p.Type])

	namespaced := p.Name
	if p.Namespace != "" {
		namespaced = p.Namespace + "/" + p.Name
	}

	return PackagePath{
		Bucket: fmt.Sprintf("%s-%s-%s", PackagesPrefix, p.Type, hash),
		Core:   p.Type + "/" + namespaced,
	}, nil
}

// VulnerabilityPath is where one VCID's file sits under VulnerabilitiesDir.
func VulnerabilityPath(vcid string) string {
	dir := ""
	if len(vcid) >= 7 {
		dir = vcid[5:7]
	}
	return fmt.Sprintf("%s/%s/%s.yml", VulnerabilitiesDir, dir, vcid)
}
