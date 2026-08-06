package guacseam

import (
	"context"
	"os"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// fakeCollector implements collector.Collector by emitting one canned document
// bearing the small-spdx fixture bytes. Its Type is the registration key.
type fakeCollector struct {
	typ  string
	blob []byte
}

func (f fakeCollector) Type() string { return f.typ }

func (f fakeCollector) RetrieveArtifacts(_ context.Context, docChannel chan<- *processor.Document) error {
	docChannel <- &processor.Document{
		Blob:              f.blob,
		Type:              processor.DocumentUnknown,
		Format:            processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{Collector: f.typ, Source: f.typ + "-doc"},
	}
	return nil
}

func readSmallSPDX(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/sboms/small-spdx.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

func TestCollectWithMultipleCollectors(t *testing.T) {
	ctx := context.Background()
	blob := readSmallSPDX(t)
	fA := fakeCollector{typ: "fakeA", blob: blob}
	fB := fakeCollector{typ: "fakeB", blob: blob}

	var calls int
	names := map[string]bool{}
	fn := func(ctx context.Context, _ string, preds []assembler.IngestPredicates, _ []string) error {
		calls++
		for _, p := range preds {
			for _, idp := range p.GetPackages(ctx) {
				if idp.PackageInput != nil {
					names[idp.PackageInput.Name] = true
				}
			}
		}
		return nil
	}

	out, err := collectWith(ctx, []collector.Collector{fA, fB}, ScanFlags{}, nil, fn)
	if err != nil {
		t.Fatalf("collectWith returned error: %v", err)
	}
	if out.Documents != 2 {
		t.Errorf("Documents = %d, want 2", out.Documents)
	}
	if len(out.Failed) != 0 {
		t.Errorf("Failed = %+v, want empty", out.Failed)
	}
	if calls != 2 {
		t.Errorf("fn called %d times, want 2", calls)
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

func TestCollectWithDeregistersForReuse(t *testing.T) {
	ctx := context.Background()
	blob := readSmallSPDX(t)
	fA := fakeCollector{typ: "fakeA", blob: blob}
	fB := fakeCollector{typ: "fakeB", blob: blob}

	run := func() Outcome {
		out, err := collectWith(ctx, []collector.Collector{fA, fB}, ScanFlags{}, nil,
			func(context.Context, string, []assembler.IngestPredicates, []string) error { return nil })
		if err != nil {
			t.Fatalf("collectWith returned error: %v", err)
		}
		return out
	}

	first := run()
	second := run()

	if first.Documents != 2 || second.Documents != 2 {
		t.Errorf("Documents = %d then %d, want 2 then 2", first.Documents, second.Documents)
	}
}
