package federatedcode

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

// Request is what a caller wants replayed. A replay hangs its claims on nodes
// the caller already holds and never invents one.
type Request struct {
	Subjects map[string]varve.NodeID // exact versioned purl -> its PkgVersion node
	Vulns    map[string]varve.NodeID // lower-cased vulnerability id -> its Vulnerability node
}

// Result is one replay's outcome: the counts a job receipt reports.
type Result struct {
	Packages int            // subjects the repository holds a file for
	Commits  int            // commits read across all of them
	Claims   []enrich.Claim // every claim produced, oldest commit first
	Missing  []string       // subject purls with no file, sorted
}

// Repo is an opened FederatedCode data repository. from is the commit every
// history walk starts at, resolved once when the repository is opened.
type Repo struct {
	git  *git.Repository
	from plumbing.Hash
}

// ErrNoRepo is returned when dir holds no repository and url is empty.
var ErrNoRepo = errors.New("federatedcode: no repository, and no url to clone")

// Open opens the clone at dir, cloning it from url when dir holds none, and
// fetches an existing one so a later replay sees what the source published.
func Open(ctx context.Context, dir, url string) (*Repo, error) {
	r, err := git.PlainOpen(dir)
	if err == nil {
		// A clone already carrying everything, and a repository built on the
		// host with no remote at all, are both nothing to fetch.
		err := r.FetchContext(ctx, &git.FetchOptions{})
		if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) && !errors.Is(err, git.ErrRemoteNotFound) {
			return nil, fmt.Errorf("federatedcode: fetch %s: %w", dir, err)
		}
		return &Repo{git: r, from: tip(r)}, nil
	}
	if url == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoRepo, dir)
	}

	r, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{URL: url})
	if err != nil {
		return nil, fmt.Errorf("federatedcode: clone %s: %w", url, err)
	}
	return &Repo{git: r, from: tip(r)}, nil
}

// tip is the commit a replay reads the source at. A fetch moves the remote
// ref, never the local branch, so walking from HEAD would replay the clone as
// it was when it was made and ignore everything the fetch just downloaded. The
// remote's copy of the checked-out branch is preferred, then the remote's own
// HEAD; a repository with no remote falls back to plumbing.ZeroHash, which
// go-git reads as HEAD.
func tip(r *git.Repository) plumbing.Hash {
	names := []plumbing.ReferenceName{plumbing.NewRemoteHEADReferenceName(git.DefaultRemoteName)}
	if head, err := r.Head(); err == nil && head.Name().IsBranch() {
		remote := plumbing.NewRemoteReferenceName(git.DefaultRemoteName, head.Name().Short())
		names = append([]plumbing.ReferenceName{remote}, names...)
	}

	for _, name := range names {
		if ref, err := r.Reference(name, true); err == nil && !ref.Hash().IsZero() {
			return ref.Hash()
		}
	}
	return plumbing.ZeroHash
}

// Replay walks two histories per subject and returns one claim per fact per
// commit, each dated by the commit that stated it. The package file's history
// dates the affected claims; each advisory file's own history dates that
// vulnerability's facts. Result.Commits is the size of the union.
func (r *Repo) Replay(ctx context.Context, req Request) (Result, error) {
	purls := make([]string, 0, len(req.Subjects))
	for purl := range req.Subjects {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	var res Result
	read := map[plumbing.Hash]bool{}
	for _, purl := range purls {
		path, err := PathFor(purl)
		if err != nil {
			return Result{}, err
		}

		commits, err := r.history(ctx, path.Dir()+"/"+VulnerabilitiesFile)
		if err != nil {
			return Result{}, err
		}
		if len(commits) == 0 {
			res.Missing = append(res.Missing, purl)
			continue
		}
		res.Packages++

		vcids, claims, err := r.packageClaims(commits, purl, req, read)
		if err != nil {
			return Result{}, err
		}
		res.Claims = append(res.Claims, claims...)

		for _, vcid := range vcids {
			path, err := VulnerabilityPath(vcid)
			if err != nil {
				return Result{}, err
			}
			commits, err := r.history(ctx, path)
			if err != nil {
				return Result{}, err
			}
			claims, err := r.advisoryClaims(commits, vcid, req, read)
			if err != nil {
				return Result{}, err
			}
			res.Claims = append(res.Claims, claims...)
		}
	}
	res.Commits = len(read)

	sort.SliceStable(res.Claims, func(i, j int) bool {
		return res.Claims[i].ValidFrom.Before(res.Claims[j].ValidFrom)
	})
	return res, nil
}

// history is every commit that touched path, oldest first. go-git's Log yields
// newest first, so the walk is reversed.
func (r *Repo) history(ctx context.Context, path string) ([]*object.Commit, error) {
	iter, err := r.git.Log(&git.LogOptions{From: r.from, FileName: &path, Order: git.LogOrderCommitterTime})
	if err != nil {
		return nil, fmt.Errorf("federatedcode: log %s: %w", path, err)
	}
	defer iter.Close()

	var commits []*object.Commit
	if err := iter.ForEach(func(c *object.Commit) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		commits = append(commits, c)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("federatedcode: walk %s: %w", path, err)
	}

	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}
	return commits, nil
}

// packageClaims is one affected claim per vulnerability the package file names
// at each commit that changed it, plus every VCID the history mentioned, in the
// order it first mentioned them.
func (r *Repo) packageClaims(commits []*object.Commit, purl string, req Request, read map[plumbing.Hash]bool) ([]string, []enrich.Claim, error) {
	path, err := PathFor(purl)
	if err != nil {
		return nil, nil, err
	}

	var vcids []string
	var out []enrich.Claim
	for _, c := range commits {
		read[c.Hash] = true
		entries, err := readYAML(c, path.Dir()+"/"+VulnerabilitiesFile, ParsePackageEntries)
		if err != nil {
			return nil, nil, err
		}

		when := c.Committer.When.UTC()
		for _, e := range entries {
			if e.Purl != purl {
				continue
			}
			for _, vcid := range e.AffectedBy {
				advisoryPath, err := VulnerabilityPath(vcid)
				if err != nil {
					return nil, nil, err
				}
				advisory, err := readYAML(c, advisoryPath, ParseAdvisory)
				if err != nil {
					return nil, nil, err
				}
				if !slices.Contains(vcids, vcid) {
					vcids = append(vcids, vcid)
				}
				aliases := aliasNodes(advisory.Aliases, req.Vulns)
				out = append(out, claim(vcid, req.Subjects[purl], aliases, enrich.FactAffected, vcid, when))
			}
		}
	}
	return vcids, out, nil
}

// advisoryClaims is what the advisory states about the vulnerability itself,
// dated by the commits that changed the advisory file rather than by the
// package file's own history.
func (r *Repo) advisoryClaims(commits []*object.Commit, vcid string, req Request, read map[plumbing.Hash]bool) ([]enrich.Claim, error) {
	path, err := VulnerabilityPath(vcid)
	if err != nil {
		return nil, err
	}

	var out []enrich.Claim
	for _, c := range commits {
		read[c.Hash] = true
		advisory, err := readYAML(c, path, ParseAdvisory)
		if err != nil {
			return nil, err
		}
		if advisory.VulnerabilityID == "" {
			continue
		}

		when := c.Committer.When.UTC()
		for _, node := range aliasNodes(advisory.Aliases, req.Vulns) {
			for _, f := range advisory.Facts() {
				out = append(out, claim(vcid, node, nil, f.Fact, f.Value, when))
			}
		}
	}
	return out, nil
}

// readYAML parses the blob at path in c. A path absent at a commit is the
// normal case for a repository's early history, not an error: parse returns
// its zero value.
func readYAML[T Advisory | []PackageEntry](c *object.Commit, path string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	f, err := c.File(path)
	if err != nil {
		return zero, nil
	}
	body, err := f.Contents()
	if err != nil {
		return zero, fmt.Errorf("federatedcode: read %s at %s: %w", path, c.Hash, err)
	}
	return parse([]byte(body))
}

// aliasNodes are the vulnerability nodes the aliases name, in alias order,
// skipping every alias the request carries no node for: a replay never invents
// a node (D6).
func aliasNodes(aliases []string, vulns map[string]varve.NodeID) []varve.NodeID {
	var out []varve.NodeID
	for _, alias := range aliases {
		if node, ok := vulns[strings.ToLower(strings.TrimSpace(alias))]; ok {
			out = append(out, node)
		}
	}
	return out
}

// claim renders one fact. ValidFrom is the commit date: the source's history is
// the source's own clock (D7).
func claim(vcid string, subject varve.NodeID, also []varve.NodeID, fact enrich.Fact, value string, when time.Time) enrich.Claim {
	return enrich.Claim{
		Source:    enrich.SourceFederatedCode,
		Subject:   subject,
		Also:      also,
		Fact:      fact,
		Value:     value,
		Ref:       vcid,
		ValidFrom: when,
		FetchedAt: when,
	}
}
