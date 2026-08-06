package guacseam_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/internal/guacseam"
)

// orderFixtureDir writes a directory whose lexically FIRST document is by far the
// slowest to parse (a 1.4MB SPDX), followed by small copies and two unparseable
// files. Under the parallel process+parse pool the big document finishes last, so
// any implementation that replayed completion order instead of arrival order would
// not put it first.
func orderFixtureDir(t *testing.T) (dir string, wantSources, wantFailed []string) {
	t.Helper()
	dir = t.TempDir()

	big, err := os.ReadFile("../assemble/testdata/corpus/oci-kubectl-linux-arm-v7-spdx.json")
	if err != nil {
		t.Fatalf("reading big fixture: %v", err)
	}
	small, err := os.ReadFile("../../testdata/sboms/small-spdx.json")
	if err != nil {
		t.Fatalf("reading small fixture: %v", err)
	}

	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	write("00-big.json", big)
	wantSources = append(wantSources, "00-big.json")
	for i := 1; i <= 10; i++ {
		name := string(rune('0'+i/10)) + string(rune('0'+i%10)) + "-small.json"
		if i%4 == 0 {
			write(name, []byte(`{"not":"a document"}`))
			wantFailed = append(wantFailed, name)
			continue
		}
		write(name, small)
		wantSources = append(wantSources, name)
	}
	return dir, wantSources, wantFailed
}

func TestCollectReplaysDocumentsInArrivalOrder(t *testing.T) {
	ctx := context.Background()
	dir, wantSources, wantFailed := orderFixtureDir(t)

	var inFn, overlaps atomic.Int64
	var gotSources []string

	out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: dir}},
		func(_ context.Context, source string, _ []assembler.IngestPredicates, _ []string) error {
			if inFn.Add(1) != 1 {
				overlaps.Add(1)
			}
			gotSources = append(gotSources, filepath.Base(source))
			inFn.Add(-1)
			return nil
		})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if n := overlaps.Load(); n != 0 {
		t.Errorf("fn ran concurrently %d times, want 0 (the consumer must serialise it)", n)
	}
	if out.Documents != len(wantSources)+len(wantFailed) {
		t.Errorf("Documents = %d, want %d", out.Documents, len(wantSources)+len(wantFailed))
	}
	if strings.Join(gotSources, ",") != strings.Join(wantSources, ",") {
		t.Errorf("fn saw %v, want %v (arrival order, not completion order)", gotSources, wantSources)
	}

	var gotFailed []string
	for _, f := range out.Failed {
		gotFailed = append(gotFailed, filepath.Base(f.Source))
	}
	if strings.Join(gotFailed, ",") != strings.Join(wantFailed, ",") {
		t.Errorf("Failed = %v, want %v (arrival order)", gotFailed, wantFailed)
	}
}

func TestCollectIsDeterministicAcrossRuns(t *testing.T) {
	ctx := context.Background()
	dir, _, _ := orderFixtureDir(t)

	run := func() (sources []string, failed []string) {
		out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: dir}},
			func(_ context.Context, source string, _ []assembler.IngestPredicates, _ []string) error {
				sources = append(sources, filepath.Base(source))
				return nil
			})
		if err != nil {
			t.Fatalf("Collect returned error: %v", err)
		}
		for _, f := range out.Failed {
			failed = append(failed, filepath.Base(f.Source))
		}
		return sources, failed
	}

	// The file collector emits each file at most once per process, so a second
	// Collect over the same dir sees nothing; compare two fresh dirs instead.
	firstSources, firstFailed := run()
	dir2, _, _ := orderFixtureDir(t)
	dir = dir2
	secondSources, secondFailed := run()

	if strings.Join(firstSources, ",") != strings.Join(secondSources, ",") {
		t.Errorf("run 1 saw %v, run 2 saw %v; parallel parsing must not change the order", firstSources, secondSources)
	}
	if strings.Join(firstFailed, ",") != strings.Join(secondFailed, ",") {
		t.Errorf("run 1 failed %v, run 2 failed %v", firstFailed, secondFailed)
	}
}
