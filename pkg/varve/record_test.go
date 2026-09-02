package varve

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// orderStream is the 2-node, 1-edge stream shared by TestWriteNDJSONOrder and
// the client's success test (step 3), so both pin the identical bytes.
func orderStream() Stream {
	name := NodeRecord{
		ID:     "pkg:n:golang/github.com/x/y",
		Labels: []NodeLabel{"PkgName"},
		Props: []Prop{
			{"type", Str("golang")},
			{"namespace", Str("github.com/x")},
			{"name", Str("y")},
		},
	}
	ver := NodeRecord{
		ID:     "pkg:v:golang/github.com/x/y/v1.0.0++",
		Labels: []NodeLabel{"PkgVersion"},
		Props: []Prop{
			{"type", Str("golang")},
			{"namespace", Str("github.com/x")},
			{"name", Str("y")},
			{"version", Str("v1.0.0")},
			{"purl", Str("pkg:golang/github.com/x/y@v1.0.0")},
		},
	}
	edge := EdgeRecord{
		ID:    "pkg:n:golang/github.com/x/y|PkgHasVersion|pkg:v:golang/github.com/x/y/v1.0.0++",
		Label: "PkgHasVersion",
		Src:   "pkg:n:golang/github.com/x/y",
		Dst:   "pkg:v:golang/github.com/x/y/v1.0.0++",
	}
	return Stream{Nodes: []NodeRecord{name, ver}, Edges: []EdgeRecord{edge}}
}

const (
	orderNodeLine    = `{"type":"node","labels":["PkgName"],"props":{"_id":"pkg:n:golang/github.com/x/y","type":"golang","namespace":"github.com/x","name":"y"}}`
	orderVersionLine = `{"type":"node","labels":["PkgVersion"],"props":{"_id":"pkg:v:golang/github.com/x/y/v1.0.0++","type":"golang","namespace":"github.com/x","name":"y","version":"v1.0.0","purl":"pkg:golang/github.com/x/y@v1.0.0"}}`
	orderEdgeLine    = `{"type":"edge","label":"PkgHasVersion","src":"pkg:n:golang/github.com/x/y","dst":"pkg:v:golang/github.com/x/y/v1.0.0++","props":{"_id":"pkg:n:golang/github.com/x/y|PkgHasVersion|pkg:v:golang/github.com/x/y/v1.0.0++"}}`

	orderStreamNDJSON = orderNodeLine + "\n" + orderVersionLine + "\n" + orderEdgeLine + "\n"
)

func mustWrite(t *testing.T, s Stream) string {
	t.Helper()
	var b strings.Builder
	if err := WriteNDJSON(&b, s); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	return b.String()
}

func TestWriteNDJSONNode(t *testing.T) {
	s := Stream{Nodes: []NodeRecord{{
		ID:     "pkg:n:golang/github.com/x/y",
		Labels: []NodeLabel{"PkgName"},
		Props: []Prop{
			{"type", Str("golang")},
			{"namespace", Str("github.com/x")},
			{"name", Str("y")},
		},
	}}}
	got := mustWrite(t, s)
	want := orderNodeLine + "\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestWriteNDJSONScalarKinds(t *testing.T) {
	s := Stream{Nodes: []NodeRecord{{
		ID:     "a",
		Labels: []NodeLabel{"X"},
		Props: []Prop{
			{"i", Int(7)},
			{"f", Float(1.5)},
			{"b", Bool(true)},
		},
	}}}
	got := mustWrite(t, s)
	want := `{"type":"node","labels":["X"],"props":{"_id":"a","i":7,"f":1.5,"b":true}}` + "\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestWriteNDJSONEscaping(t *testing.T) {
	s := Stream{Nodes: []NodeRecord{{
		ID:     "a",
		Labels: []NodeLabel{"X"},
		Props:  []Prop{{"msg", Str(`he said "hi"\back`)}},
	}}}
	got := mustWrite(t, s)
	if !strings.Contains(got, `\"hi\"`) {
		t.Errorf("expected escaped quotes in %q", got)
	}
	if !strings.Contains(got, `\\back`) {
		t.Errorf("expected escaped backslash in %q", got)
	}
	line := strings.TrimRight(got, "\n")
	if !json.Valid([]byte(line)) {
		t.Errorf("line is not valid JSON: %q", line)
	}
}

func TestWriteNDJSONEmptyLabels(t *testing.T) {
	s := Stream{Nodes: []NodeRecord{{ID: "a"}}}
	got := mustWrite(t, s)
	want := `{"type":"node","labels":[],"props":{"_id":"a"}}` + "\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if strings.Contains(got, "null") {
		t.Errorf("nil labels must render [] not null: %q", got)
	}
}

func TestWriteNDJSONEdge(t *testing.T) {
	s := Stream{Edges: []EdgeRecord{{
		ID:    "pkg:n:golang/github.com/x/y|PkgHasVersion|pkg:v:golang/github.com/x/y/v1.0.0++",
		Label: "PkgHasVersion",
		Src:   "pkg:n:golang/github.com/x/y",
		Dst:   "pkg:v:golang/github.com/x/y/v1.0.0++",
	}}}
	got := mustWrite(t, s)
	want := orderEdgeLine + "\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestWriteNDJSONOrder(t *testing.T) {
	got := mustWrite(t, orderStream())
	if got != orderStreamNDJSON {
		t.Errorf("got  %q\nwant %q", got, orderStreamNDJSON)
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], `{"type":"node"`) || !strings.HasPrefix(lines[1], `{"type":"node"`) {
		t.Errorf("both node lines must come first: %q", got)
	}
	if !strings.HasPrefix(lines[2], `{"type":"edge"`) {
		t.Errorf("edge line must come last: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("output must end with newline: %q", got)
	}
}

func TestWriteNDJSONValidFrom(t *testing.T) {
	vf := time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC)
	s := Stream{
		Nodes: []NodeRecord{{
			ID:        "a",
			Labels:    []NodeLabel{"X"},
			Props:     []Prop{{"k", Str("v")}},
			ValidFrom: vf,
		}},
		Edges: []EdgeRecord{{
			ID:        "e",
			Label:     "L",
			Src:       "s",
			Dst:       "d",
			ValidFrom: vf,
		}},
	}
	got := mustWrite(t, s)
	wantNode := `{"type":"node","labels":["X"],"props":{"_id":"a","k":"v"},"valid_from":"2021-12-10T10:15:00Z"}`
	wantEdge := `{"type":"edge","label":"L","src":"s","dst":"d","props":{"_id":"e"},"valid_from":"2021-12-10T10:15:00Z"}`
	want := wantNode + "\n" + wantEdge + "\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestWriteNDJSONValidFromZeroOmitted(t *testing.T) {
	s := Stream{Nodes: []NodeRecord{{
		ID:     "a",
		Labels: []NodeLabel{"X"},
		Props:  []Prop{{"k", Str("v")}},
	}}}
	got := mustWrite(t, s)
	if strings.Contains(got, "valid_from") {
		t.Errorf("zero ValidFrom must be omitted: %q", got)
	}
	line := strings.TrimRight(got, "\n")
	if !json.Valid([]byte(line)) {
		t.Errorf("line is not valid JSON: %q", line)
	}
}

func TestWriteNDJSONValidFromUTC(t *testing.T) {
	zone := time.FixedZone("CET", 60*60)
	vf := time.Date(2021, 12, 10, 10, 15, 0, 0, zone)
	s := Stream{Nodes: []NodeRecord{{
		ID:        "a",
		Labels:    []NodeLabel{"X"},
		Props:     []Prop{{"k", Str("v")}},
		ValidFrom: vf,
	}}}
	got := mustWrite(t, s)
	if !strings.Contains(got, `"valid_from":"2021-12-10T09:15:00Z"`) {
		t.Errorf("expected UTC-rendered valid_from in %q", got)
	}
}

func TestWriteNDJSONNoNullBytes(t *testing.T) {
	streams := []Stream{
		orderStream(),
		{Nodes: []NodeRecord{{ID: "a", Labels: []NodeLabel{"X"}, Props: []Prop{{"i", Int(7)}, {"f", Float(1.5)}, {"b", Bool(true)}}}}},
		{Nodes: []NodeRecord{{ID: "a", Labels: []NodeLabel{"X"}, Props: []Prop{{"msg", Str(`he said "hi"\back`)}}}}},
		{Nodes: []NodeRecord{{ID: "a"}}},
		{Edges: []EdgeRecord{{ID: "e", Label: "L", Src: "s", Dst: "d"}}},
	}
	for i, s := range streams {
		got := mustWrite(t, s)
		if strings.Contains(got, "null") {
			t.Errorf("case %d contains substring null: %q", i, got)
		}
	}
}
