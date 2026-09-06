package purl

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/varve"
)

func TestLookup(t *testing.T) {
	cases := []struct {
		purl string
		want Origin
		ok   bool
	}{
		{"pkg:golang/golang.org/x/crypto@v0.26.0", Origin{"Google LLC", "US", "golang/golang.org/x/"}, true},
		{"pkg:maven/org.apache.commons/commons-lang3@3.14.0", Origin{"The Apache Software Foundation", "US", "maven/org.apache."}, true},
		{"pkg:rpm/opensuse/zlib@1.3.1-1.1?arch=aarch64&distro=opensuse-tumbleweed", Origin{"openSUSE Project", "DE", "rpm/opensuse/"}, true},
		{"pkg:deb/debian/openssl@3.0.13-1~deb12u1?arch=arm64&distro=debian-12", Origin{"Debian Project", "", "deb/debian/"}, true},
		{"pkg:npm/lodash@4.17.21", Origin{}, false},
		{"pkg:golang/github.com/gorilla/mux@v1.8.1", Origin{}, false},
		{"not-a-purl", Origin{}, false},
		{"pkg:maven/org.apachefoo/x@1", Origin{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.purl, func(t *testing.T) {
			got, ok := Lookup(tc.purl)
			if ok != tc.ok {
				t.Fatalf("Lookup(%q) ok = %v, want %v", tc.purl, ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("Lookup(%q) = %+v, want %+v", tc.purl, got, tc.want)
			}
		})
	}
}

var (
	pkgValidFrom = time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	testNow      = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
)

func testPkgNode(id, purl string) varve.NodeRecord {
	return varve.NodeRecord{
		ID:        varve.NodeID(id),
		Labels:    []varve.NodeLabel{assemble.LabelPkgVersion},
		Props:     []varve.Prop{{Key: assemble.PropPurl, Value: varve.Str(purl)}},
		ValidFrom: pkgValidFrom,
	}
}

func TestEnrich(t *testing.T) {
	stream := varve.Stream{Nodes: []varve.NodeRecord{
		testPkgNode("pkg:crypto", "pkg:golang/golang.org/x/crypto@v0.26.0"),
		testPkgNode("pkg:openssl", "pkg:deb/debian/openssl@3.0.13-1~deb12u1?arch=arm64&distro=debian-12"),
	}}
	e := New()
	if got := e.Source(); got != enrich.SourcePURL {
		t.Fatalf("Source() = %q, want %q", got, enrich.SourcePURL)
	}
	got, err := e.Enrich(context.Background(), enrich.Input{Records: stream, Now: testNow})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	want := []enrich.Claim{
		{Source: enrich.SourcePURL, Subject: "pkg:openssl", Fact: enrich.FactSupplier, Value: "Debian Project", Ref: "deb/debian/", ValidFrom: pkgValidFrom, FetchedAt: testNow},
		{Source: enrich.SourcePURL, Subject: "pkg:crypto", Fact: enrich.FactSupplier, Value: "Google LLC", Ref: "golang/golang.org/x/", ValidFrom: pkgValidFrom, FetchedAt: testNow},
		{Source: enrich.SourcePURL, Subject: "pkg:crypto", Fact: enrich.FactOriginCountry, Value: "US", Ref: "golang/golang.org/x/", ValidFrom: pkgValidFrom, FetchedAt: testNow},
	}
	if len(got) != len(want) {
		t.Fatalf("Enrich() returned %d claims, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("claim %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
