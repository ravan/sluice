package guacseam_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/ravan/sluice/pkg/guacseam"
)

func TestCollectFilesParsesFixture(t *testing.T) {
	ctx := context.Background()

	var calls int
	var gotSource string
	unionKeys := map[string]bool{}
	names := map[string]bool{}

	fn := func(ctx context.Context, source string, preds []assembler.IngestPredicates, _ []string) error {
		calls++
		gotSource = source
		for _, p := range preds {
			for key, idp := range p.GetPackages(ctx) {
				unionKeys[key] = true
				if idp.PackageInput != nil {
					names[idp.PackageInput.Name] = true
				}
			}
		}
		return nil
	}

	out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: "../../testdata/sboms"}}, fn)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if out.Documents != 1 {
		t.Errorf("Documents = %d, want 1", out.Documents)
	}
	if len(out.Failed) != 0 {
		t.Errorf("Failed = %+v, want empty", out.Failed)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1", calls)
	}
	if !strings.Contains(gotSource, "small-spdx.json") {
		t.Errorf("source = %q, want it to contain small-spdx.json", gotSource)
	}
	if len(unionKeys) != 3 {
		t.Errorf("union of GetPackages has %d entries, want 3", len(unionKeys))
	}
	want := map[string]bool{"text": true, "quote": true, "sampler": true}
	if len(names) != len(want) {
		t.Errorf("package names = %v, want %v", names, want)
	}
	for n := range want {
		if !names[n] {
			t.Errorf("missing package name %q; got %v", n, names)
		}
	}
	for n := range names {
		if !want[n] {
			t.Errorf("unexpected package name %q; got %v", n, names)
		}
	}
}

func TestCollectFilesTwiceInOneProcess(t *testing.T) {
	ctx := context.Background()

	run := func() guacseam.Outcome {
		out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: "../../testdata/sboms"}},
			func(context.Context, string, []assembler.IngestPredicates, []string) error { return nil })
		if err != nil {
			t.Fatalf("Collect returned error: %v", err)
		}
		return out
	}

	first := run()
	second := run()

	if first.Documents != 1 || second.Documents != 1 {
		t.Errorf("Documents = %d then %d, want 1 then 1", first.Documents, second.Documents)
	}
	if len(first.Failed) != 0 || len(second.Failed) != 0 {
		t.Errorf("Failed = %+v then %+v, want empty both times", first.Failed, second.Failed)
	}
}

func TestCollectFilesSkipsUnparseableDocument(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"not":"a document"}`), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	var calls int
	out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: dir}},
		func(context.Context, string, []assembler.IngestPredicates, []string) error {
			calls++
			return nil
		})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if out.Documents != 1 {
		t.Errorf("Documents = %d, want 1", out.Documents)
	}
	if len(out.Failed) != 1 {
		t.Fatalf("Failed len = %d, want 1: %+v", len(out.Failed), out.Failed)
	}
	if !strings.Contains(out.Failed[0].Source, "bad.json") {
		t.Errorf("Failed source = %q, want it to contain bad.json", out.Failed[0].Source)
	}
	if out.Failed[0].Err == nil {
		t.Errorf("Failed err is nil, want non-nil")
	}
	if calls != 0 {
		t.Errorf("fn called %d times, want 0 (a skipped document never reaches fn)", calls)
	}
}

func TestCollectFilesOnSkipHook(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"not":"a document"}`), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	var skipped []guacseam.FailedDocument
	out, err := guacseam.Collect(ctx, guacseam.Sources{
		Files:  &guacseam.FilesReceiver{Path: dir},
		OnSkip: func(fd guacseam.FailedDocument) { skipped = append(skipped, fd) },
	}, func(context.Context, string, []assembler.IngestPredicates, []string) error { return nil })
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(out.Failed) != 1 {
		t.Fatalf("Failed len = %d, want 1: %+v", len(out.Failed), out.Failed)
	}
	if len(skipped) != 1 {
		t.Fatalf("OnSkip fired %d times, want 1", len(skipped))
	}
	if !strings.Contains(skipped[0].Source, "bad.json") {
		t.Errorf("skipped source = %q, want it to contain bad.json", skipped[0].Source)
	}
}

func TestCollectFilesPollPicksUpNewFile(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("../../testdata/sboms/small-spdx.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	writeFixture := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	writeFixture("a.json")

	got := make(chan string, 8)
	fn := func(_ context.Context, source string, _ []assembler.IngestPredicates, _ []string) error {
		got <- source
		return nil
	}

	type result struct {
		out guacseam.Outcome
		err error
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result, 1)
	go func() {
		out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: dir, Poll: true, Interval: 25 * time.Millisecond}}, fn)
		done <- result{out, err}
	}()

	waitFor := func(substr string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case src := <-got:
				if strings.Contains(src, substr) {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for source containing %q", substr)
			}
		}
	}

	waitFor("a.json")
	writeFixture("b.json")
	waitFor("b.json")

	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case res := <-done:
			if res.err != nil {
				t.Fatalf("CollectFiles returned error on cancel, want nil: %v", res.err)
			}
			return
		case <-got:
		case <-deadline:
			t.Fatal("timed out waiting for CollectFiles to return after cancel")
		}
	}
}
