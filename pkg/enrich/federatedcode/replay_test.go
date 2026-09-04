package federatedcode

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

const (
	lodashPurl = "pkg:npm/lodash@4.17.21"
	lodashFile = "aboutcode-packages-npm-026/npm/lodash/vulnerabilities.yml"
	vcid1      = "VCID-1111-2222-3333"
	vcid2      = "VCID-4444-5555-6666"
	adv1File   = "aboutcode-vulnerabilities/11/VCID-1111-2222-3333.yml"
	adv2File   = "aboutcode-vulnerabilities/44/VCID-4444-5555-6666.yml"
	pkgNode    = varve.NodeID("pkgv:1")
	vulnNode   = varve.NodeID("vuln:cve/cve-2026-12345")
)

var (
	commit1At = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	commit2At = time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	commit3At = time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
)

// buildRepo writes the three-commit fixture repository into a temp directory.
// A commit date is fixed only by setting the same signature as author and
// committer, which is what the Silt fixture builder does too.
func buildRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}

	commit := func(when time.Time, files map[string]string) {
		t.Helper()
		for name, body := range files {
			full := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", name, err)
			}
			if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		if err := wt.AddWithOptions(&git.AddOptions{All: true}); err != nil {
			t.Fatalf("add: %v", err)
		}
		sig := &object.Signature{Name: "fixture", Email: "fixture@example.test", When: when}
		if _, err := wt.Commit(when.Format(time.RFC3339), &git.CommitOptions{Author: sig, Committer: sig}); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	pkgOne := "- purl: " + lodashPurl + "\n  affected_by_vulnerabilities:\n    - " + vcid1 + "\n  fixing_vulnerabilities: []\n"
	pkgTwo := "- purl: " + lodashPurl + "\n  affected_by_vulnerabilities:\n    - " + vcid1 + "\n    - " + vcid2 + "\n  fixing_vulnerabilities: []\n"
	advisory := func(id, alias, score string) string {
		return "vulnerability_id: " + id + "\naliases:\n  - " + alias +
			"\nsummary: a summary\nseverities:\n  - score: '" + score +
			"'\n    scoring_system: cvssv3.1\n    scoring_elements: CVSS:3.1/AV:N\nreferences: []\n"
	}

	commit(commit1At, map[string]string{
		lodashFile: pkgOne,
		adv1File:   advisory(vcid1, "CVE-2026-12345", "9.8"),
	})
	commit(commit2At, map[string]string{
		adv1File: advisory(vcid1, "CVE-2026-12345", "9.1"),
	})
	commit(commit3At, map[string]string{
		lodashFile: pkgTwo,
		adv2File:   advisory(vcid2, "CVE-2026-99999", "5.3"),
	})
	return dir
}

func replayLodash(t *testing.T, dir string) Result {
	t.Helper()
	repo, err := Open(t.Context(), dir, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	res, err := repo.Replay(t.Context(), Request{
		Subjects: map[string]varve.NodeID{lodashPurl: pkgNode},
		Vulns:    map[string]varve.NodeID{"cve-2026-12345": vulnNode},
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return res
}

func TestReplay(t *testing.T) {
	res := replayLodash(t, buildRepo(t))

	if res.Packages != 1 {
		t.Errorf("packages = %d, want 1", res.Packages)
	}
	if res.Commits != 3 {
		t.Errorf("commits = %d, want 3", res.Commits)
	}
	if len(res.Missing) != 0 {
		t.Errorf("missing = %v, want empty", res.Missing)
	}

	var cvss, affected1, affected2 []enrich.Claim
	for _, c := range res.Claims {
		if c.Source != enrich.SourceFederatedCode {
			t.Errorf("source = %q, want federatedcode", c.Source)
		}
		if !c.ValidFrom.Equal(c.FetchedAt) {
			t.Errorf("valid_from %s != fetched_at %s", c.ValidFrom, c.FetchedAt)
		}
		for _, n := range append([]varve.NodeID{c.Subject}, c.Also...) {
			if n == "vuln:cve/cve-2026-99999" {
				t.Errorf("claim names a node for an unheld alias: %+v", c)
			}
		}
		switch {
		case c.Fact == enrich.FactCVSS && c.Subject == vulnNode:
			cvss = append(cvss, c)
		case c.Fact == enrich.FactAffected && c.Value == vcid1:
			affected1 = append(affected1, c)
		case c.Fact == enrich.FactAffected && c.Value == vcid2:
			affected2 = append(affected2, c)
		}
	}

	if len(cvss) != 2 {
		t.Fatalf("cvss claims = %d, want 2: %+v", len(cvss), cvss)
	}
	if cvss[0].Value != "9.8" || !cvss[0].ValidFrom.Equal(commit1At) {
		t.Errorf("cvss[0] = %s at %s, want 9.8 at %s", cvss[0].Value, cvss[0].ValidFrom, commit1At)
	}
	if cvss[1].Value != "9.1" || !cvss[1].ValidFrom.Equal(commit2At) {
		t.Errorf("cvss[1] = %s at %s, want 9.1 at %s", cvss[1].Value, cvss[1].ValidFrom, commit2At)
	}

	if len(affected1) != 2 {
		t.Errorf("affected %s claims = %d, want 2", vcid1, len(affected1))
	}
	for _, c := range affected1 {
		if c.Subject != pkgNode {
			t.Errorf("affected subject = %q, want %q", c.Subject, pkgNode)
		}
		if len(c.Also) != 1 || c.Also[0] != vulnNode {
			t.Errorf("affected %s also = %v, want [%s]", vcid1, c.Also, vulnNode)
		}
	}
	if len(affected2) != 1 {
		t.Fatalf("affected %s claims = %d, want 1", vcid2, len(affected2))
	}
	if !affected2[0].ValidFrom.Equal(commit3At) {
		t.Errorf("affected %s at %s, want %s", vcid2, affected2[0].ValidFrom, commit3At)
	}
	if len(affected2[0].Also) != 0 {
		t.Errorf("affected %s also = %v, want empty", vcid2, affected2[0].Also)
	}

	for i := 1; i < len(res.Claims); i++ {
		if res.Claims[i].ValidFrom.Before(res.Claims[i-1].ValidFrom) {
			t.Fatalf("claims out of order at %d: %s before %s", i, res.Claims[i].ValidFrom, res.Claims[i-1].ValidFrom)
		}
	}
}

func TestReplayMissing(t *testing.T) {
	repo, err := Open(t.Context(), buildRepo(t), "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	res, err := repo.Replay(t.Context(), Request{
		Subjects: map[string]varve.NodeID{"pkg:npm/nothing@1.0.0": "pkgv:2"},
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if res.Packages != 0 || res.Commits != 0 || len(res.Claims) != 0 {
		t.Errorf("packages=%d commits=%d claims=%d, want 0 0 0", res.Packages, res.Commits, len(res.Claims))
	}
	if len(res.Missing) != 1 || res.Missing[0] != "pkg:npm/nothing@1.0.0" {
		t.Errorf("missing = %v, want [pkg:npm/nothing@1.0.0]", res.Missing)
	}
}

func TestOpenNoRepo(t *testing.T) {
	if _, err := Open(t.Context(), t.TempDir(), ""); !errors.Is(err, ErrNoRepo) {
		t.Errorf("err = %v, want ErrNoRepo", err)
	}
}

func TestOpenClones(t *testing.T) {
	src := buildRepo(t)
	repo, err := Open(t.Context(), t.TempDir(), src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	cloned, err := repo.Replay(t.Context(), Request{
		Subjects: map[string]varve.NodeID{lodashPurl: pkgNode},
		Vulns:    map[string]varve.NodeID{"cve-2026-12345": vulnNode},
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	want := replayLodash(t, src)
	if cloned.Packages != want.Packages || cloned.Commits != want.Commits || len(cloned.Claims) != len(want.Claims) {
		t.Errorf("clone gave packages=%d commits=%d claims=%d, want %d %d %d",
			cloned.Packages, cloned.Commits, len(cloned.Claims),
			want.Packages, want.Commits, len(want.Claims))
	}
}
