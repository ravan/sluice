package assemble

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"

	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

var update = flag.Bool("update", false, "update golden")

const (
	corpusDir  = "testdata/corpus"
	goldenPath = "testdata/parity.golden.json"
)

// Counts is the golden oracle: per-label node and edge tallies plus the
// document totals. Maps marshal with sorted keys, so the committed golden bytes
// are stable.
type Counts struct {
	Documents int            `json:"documents"`
	Failed    int            `json:"failed"`
	Nodes     map[string]int `json:"nodes"`
	Edges     map[string]int `json:"edges"`
}

func countStream(out guacseam.Outcome, s varve.Stream) Counts {
	c := Counts{
		Documents: out.Documents,
		Failed:    len(out.Failed),
		Nodes:     map[string]int{},
		Edges:     map[string]int{},
	}
	for _, n := range s.Nodes {
		for _, l := range n.Labels {
			c.Nodes[string(l)]++
		}
	}
	for _, e := range s.Edges {
		c.Edges[string(e.Label)]++
	}
	return c
}

func TestCorpusParity(t *testing.T) {
	ctx := context.Background()

	var all []assembler.IngestPredicates
	out, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: corpusDir}},
		func(_ context.Context, p guacseam.Parsed) error {
			all = append(all, p.Preds...)
			return nil
		})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	res := Assemble(ctx, all, validtime.Default(), testNow)
	got := countStream(out, res.Stream)

	// The corpus has thousands of timestamp-free IsDependency/IsOccurrence
	// assertions, so at least one falls back to ingest time (§2.4).
	if res.Fallbacks <= 0 {
		t.Errorf("expected some valid-time fallbacks in the corpus, got %d", res.Fallbacks)
	}

	if *update {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal golden: %v", err)
		}
		data = append(data, '\n')
		if err := os.WriteFile(goldenPath, data, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	} else {
		raw, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		var want Counts
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("unmarshal golden: %v", err)
		}
		gotJSON, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal got: %v", err)
		}
		wantJSON, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatalf("marshal want: %v", err)
		}
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("parity mismatch vs golden %s\n got=%s\nwant=%s", goldenPath, gotJSON, wantJSON)
		}
	}

	// Structural falsification — asserts the model, not its past output.

	// Retired trie levels are absent by design.
	for _, retired := range []string{"PkgType", "PkgNamespace", "SrcType", "SrcNamespace", "VulnType"} {
		if n := got.Nodes[retired]; n != 0 {
			t.Errorf("retired trie label %q present: %d nodes (flattened model, §2.3)", retired, n)
		}
	}

	// Names are the shared prefix of versions.
	if got.Nodes[string(LabelPkgName)] > got.Nodes[string(LabelPkgVersion)] {
		t.Errorf("PkgName (%d) > PkgVersion (%d): names must not outnumber versions",
			got.Nodes[string(LabelPkgName)], got.Nodes[string(LabelPkgVersion)])
	}

	// Every predicate kind present in the corpus emits its evidence label.
	present := []varve.NodeLabel{
		LabelPkgVersion, LabelPkgName, LabelIsDependency, LabelHasSBOM,
		LabelCertifyVuln, LabelIsOccurrence, LabelHasSlsa, LabelCertifyLegal,
		LabelHasMetadata, LabelVex, LabelVulnEqual, LabelVulnMetadata,
		LabelCertifyScorecard, LabelHasSourceAt,
	}
	for _, l := range present {
		if got.Nodes[string(l)] == 0 {
			t.Errorf("corpus-present evidence label %q has count 0", l)
		}
	}

	// Idempotent assembly: NDJSON of two independent assemblies is identical.
	var b1, b2 bytes.Buffer
	if err := varve.WriteNDJSON(&b1, Assemble(ctx, all, validtime.Default(), testNow).Stream); err != nil {
		t.Fatalf("WriteNDJSON first: %v", err)
	}
	if err := varve.WriteNDJSON(&b2, Assemble(ctx, all, validtime.Default(), testNow).Stream); err != nil {
		t.Fatalf("WriteNDJSON second: %v", err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Errorf("assembly is not idempotent: NDJSON differs across two calls")
	}

	// Sanity bands — guards, never oracles: a >=/<= range that brackets the
	// measured value without deadlocking on small parser drift.
	for _, band := range []struct {
		label  varve.NodeLabel
		lo, hi int
	}{
		{LabelPkgVersion, 550, 750},
		{LabelPkgName, 520, 700},
		{LabelHasSBOM, 20, 40},
		{LabelCertifyVuln, 10, 30},
	} {
		if n := got.Nodes[string(band.label)]; n < band.lo || n > band.hi {
			t.Errorf("%s count %d outside sanity band [%d, %d]", band.label, n, band.lo, band.hi)
		}
	}
}
