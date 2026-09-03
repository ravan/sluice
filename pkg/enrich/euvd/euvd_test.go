package euvd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

const fixtureDescription = "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. \r\n" +
	"Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object " +
	"file from a disguised test file existing in the source code, which is then used to modify " +
	"specific functions in the liblzma code. This results in a modified liblzma library that can be " +
	"used by any software linked against this library, intercepting and modifying the data " +
	"interaction with this library."

func fixtureItem(t *testing.T) item {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "euvd", "search-cve-2024-3094.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var p page
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(p.Items) != 1 {
		t.Fatalf("fixture items = %d, want 1", len(p.Items))
	}
	return p.Items[0]
}

func TestParseDate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "published", in: "Mar 29, 2024, 4:51:12 PM", want: "2024-03-29T16:51:12Z", ok: true},
		{name: "updated", in: "Aug 4, 2026, 7:05:54 AM", want: "2026-08-04T07:05:54Z", ok: true},
		{name: "empty", in: ""},
		{name: "iso date", in: "2026-09-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDate(tc.in)
			if ok != tc.ok {
				t.Fatalf("parseDate(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
			if !tc.ok {
				return
			}
			if s := got.UTC().Format(time.RFC3339); s != tc.want {
				t.Errorf("parseDate(%q) = %s, want %s", tc.in, s, tc.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	it := fixtureItem(t)
	cases := []struct {
		name string
		want bool
	}{
		{name: "cve-2024-3094", want: true},
		{name: "CVE-2024-3094", want: true},
		{name: "euvd-2024-31700", want: true},
		{name: "cve-2024-0001", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matches(tc.name, it); got != tc.want {
				t.Errorf("matches(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestClaimsFor(t *testing.T) {
	it := fixtureItem(t)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	subject := varve.NodeID("vuln:cve/cve-2024-3094")

	want := [][2]string{
		{"euvd_id", "EUVD-2024-31700"},
		{"cvss", "10"},
		{"cvss_version", "3.1"},
		{"cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		{"epss", "85.97"},
		{"description", fixtureDescription},
		{"published", "2024-03-29T16:51:12Z"},
		{"updated", "2026-08-04T07:05:54Z"},
		{"reference", "https://access.redhat.com/security/cve/CVE-2024-3094"},
		{"reference", "https://bugzilla.redhat.com/show_bug.cgi?id=2272210"},
		{"reference", "https://www.openwall.com/lists/oss-security/2024/03/29/4"},
		{"reference", "https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users"},
	}

	got := claimsFor(subject, it, now)
	if len(got) != len(want) {
		t.Fatalf("claimsFor returned %d claims, want %d", len(got), len(want))
	}
	validFrom := time.Date(2026, 8, 4, 7, 5, 54, 0, time.UTC)
	for i, w := range want {
		c := got[i]
		if c.Fact != w[0] || c.Value != w[1] {
			t.Errorf("claim %d = (%q, %q), want (%q, %q)", i, c.Fact, c.Value, w[0], w[1])
		}
		if c.Source != enrich.SourceEUVD {
			t.Errorf("claim %d source = %q, want %q", i, c.Source, enrich.SourceEUVD)
		}
		if c.Jurisdiction != enrich.EU {
			t.Errorf("claim %d jurisdiction = %q, want %q", i, c.Jurisdiction, enrich.EU)
		}
		if c.Ref != "EUVD-2024-31700" {
			t.Errorf("claim %d ref = %q, want %q", i, c.Ref, "EUVD-2024-31700")
		}
		if c.Subject != subject {
			t.Errorf("claim %d subject = %q, want %q", i, c.Subject, subject)
		}
		if !c.ValidFrom.Equal(validFrom) {
			t.Errorf("claim %d valid_from = %s, want %s", i, c.ValidFrom.UTC().Format(time.RFC3339), validFrom.Format(time.RFC3339))
		}
		if !c.FetchedAt.Equal(now) {
			t.Errorf("claim %d fetched_at = %s, want %s", i, c.FetchedAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}

	bad := it
	bad.DateUpdated = "soon"
	got = claimsFor(subject, bad, now)
	if len(got) != 11 {
		t.Fatalf("claimsFor with an unparseable dateUpdated returned %d claims, want 11", len(got))
	}
	for i, c := range got {
		if c.Fact == "updated" {
			t.Errorf("claim %d is %q, want no updated fact", i, c.Fact)
		}
		if !c.ValidFrom.Equal(now) {
			t.Errorf("claim %d valid_from = %s, want %s", i, c.ValidFrom.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}
}

func vulnNode(typ, id string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:     assemble.VulnID(typ, id),
		Labels: []varve.NodeLabel{assemble.LabelVulnerability},
		Props: []varve.Prop{
			{Key: "type", Value: varve.Str(strings.ToLower(typ))},
			{Key: "vulnID", Value: varve.Str(strings.ToLower(id))},
		},
	}
}

type recorder struct {
	paths []string
	texts []string
	sizes []string
}

func newServer(t *testing.T, rec *recorder, status int) *httptest.Server {
	t.Helper()
	hit, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "euvd", "search-cve-2024-3094.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	miss, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "euvd", "search-empty.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		text := r.URL.Query().Get("text")
		rec.paths = append(rec.paths, r.URL.Path)
		rec.texts = append(rec.texts, text)
		rec.sizes = append(rec.sizes, r.URL.Query().Get("size"))
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if strings.EqualFold(text, "cve-2024-3094") {
			_, _ = w.Write(hit)
			return
		}
		_, _ = w.Write(miss)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnrich(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	stream := varve.Stream{Nodes: []varve.NodeRecord{
		vulnNode("cve", "cve-2024-3094"),
		vulnNode("cve", "cve-2099-99999"),
		vulnNode("ghsa", "GHSA-rxwq-x6h5-x525"),
	}}

	t.Run("two names, one hit", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, http.StatusOK)
		e, err := New(srv.URL+"/api", srv.Client())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		claims, err := e.Enrich(t.Context(), enrich.Input{Digest: "d", Records: stream, Now: now})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(claims) != 12 {
			t.Fatalf("Enrich returned %d claims, want 12", len(claims))
		}
		if len(rec.texts) != 2 {
			t.Fatalf("server saw %d requests (%v), want 2", len(rec.texts), rec.texts)
		}
		for i, p := range rec.paths {
			if p != "/api/search" {
				t.Errorf("request %d path = %q, want %q", i, p, "/api/search")
			}
			if rec.sizes[i] != "10" {
				t.Errorf("request %d size = %q, want %q", i, rec.sizes[i], "10")
			}
		}
		for i, want := range []string{"cve-2024-3094", "cve-2099-99999"} {
			if rec.texts[i] != want {
				t.Errorf("request %d text = %q, want %q", i, rec.texts[i], want)
			}
		}
		if e.Source() != enrich.SourceEUVD {
			t.Errorf("Source() = %q, want %q", e.Source(), enrich.SourceEUVD)
		}
	})

	t.Run("no vulnerability node", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, http.StatusOK)
		e, err := New(srv.URL+"/api", srv.Client())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		claims, err := e.Enrich(t.Context(), enrich.Input{Records: varve.Stream{}, Now: now})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(claims) != 0 {
			t.Errorf("Enrich returned %d claims, want 0", len(claims))
		}
		if len(rec.texts) != 0 {
			t.Errorf("server saw %d requests, want 0", len(rec.texts))
		}
	})

	t.Run("server error", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, http.StatusServiceUnavailable)
		e, err := New(srv.URL+"/api", srv.Client())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		claims, err := e.Enrich(t.Context(), enrich.Input{Records: stream, Now: now})
		if !errors.Is(err, ErrStatus) {
			t.Fatalf("Enrich error = %v, want errors.Is(ErrStatus)", err)
		}
		if !strings.Contains(err.Error(), "503") {
			t.Errorf("Enrich error = %q, want it to contain %q", err, "503")
		}
		if len(claims) != 0 {
			t.Errorf("Enrich returned %d claims, want 0", len(claims))
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		rec := &recorder{}
		srv := newServer(t, rec, http.StatusOK)
		e, err := New(srv.URL+"/api", srv.Client())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := e.Enrich(ctx, enrich.Input{Records: stream, Now: now}); err == nil {
			t.Fatal("Enrich with a cancelled context error = nil, want an error")
		}
	})
}

func TestNewBadURL(t *testing.T) {
	if _, err := New("://nope", nil); err == nil {
		t.Fatal("New with a malformed URL error = nil, want an error")
	}
}
