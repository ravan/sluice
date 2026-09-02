package varve

import (
	"testing"
	"time"
)

func TestMergeDedupsNodesKeepingEarliestValidFrom(t *testing.T) {
	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	a := Stream{Nodes: []NodeRecord{
		{ID: "n1", Labels: []NodeLabel{"A"}, Props: []Prop{{Key: "k", Value: Str("first")}}, ValidFrom: late},
		{ID: "n2", Labels: []NodeLabel{"B"}},
	}}
	b := Stream{Nodes: []NodeRecord{
		{ID: "n1", Labels: []NodeLabel{"A"}, Props: []Prop{{Key: "k", Value: Str("second")}}, ValidFrom: early},
		{ID: "n3", Labels: []NodeLabel{"C"}, ValidFrom: late},
	}}

	got := Merge(a, b)
	if len(got.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(got.Nodes))
	}
	if got.Nodes[0].ID != "n1" || got.Nodes[1].ID != "n2" || got.Nodes[2].ID != "n3" {
		t.Errorf("node order = %v %v %v, want n1 n2 n3 (first-seen)", got.Nodes[0].ID, got.Nodes[1].ID, got.Nodes[2].ID)
	}
	if !got.Nodes[0].ValidFrom.Equal(early) {
		t.Errorf("n1 ValidFrom = %v, want %v (earliest wins)", got.Nodes[0].ValidFrom, early)
	}
	if got.Nodes[0].Props[0].Value != Str("first") {
		t.Errorf("n1 props = %v, want the first record's props", got.Nodes[0].Props)
	}
	if !got.Nodes[1].ValidFrom.IsZero() {
		t.Errorf("n2 ValidFrom = %v, want zero", got.Nodes[1].ValidFrom)
	}
}

func TestMergeZeroValidFromDoesNotWin(t *testing.T) {
	late := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	a := Stream{Nodes: []NodeRecord{{ID: "n1"}}}
	b := Stream{Nodes: []NodeRecord{{ID: "n1", ValidFrom: late}}}
	got := Merge(a, b)
	if len(got.Nodes) != 1 || !got.Nodes[0].ValidFrom.Equal(late) {
		t.Errorf("got %+v, want one node with ValidFrom %v (zero is absent, not earliest)", got.Nodes, late)
	}
}

func TestMergeDedupsEdgesAndOrdersEdgesAfterNodes(t *testing.T) {
	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	a := Stream{
		Nodes: []NodeRecord{{ID: "n1"}},
		Edges: []EdgeRecord{{ID: "e1", Label: "L", Src: "n1", Dst: "n2", ValidFrom: late}},
	}
	b := Stream{
		Nodes: []NodeRecord{{ID: "n2"}},
		Edges: []EdgeRecord{
			{ID: "e2", Label: "L", Src: "n2", Dst: "n1"},
			{ID: "e1", Label: "L", Src: "n1", Dst: "n2", ValidFrom: early},
		},
	}
	got := Merge(a, b)
	if len(got.Edges) != 2 {
		t.Fatalf("edges = %d, want 2", len(got.Edges))
	}
	if got.Edges[0].ID != "e1" || got.Edges[1].ID != "e2" {
		t.Errorf("edge order = %v %v, want e1 e2 (first-seen)", got.Edges[0].ID, got.Edges[1].ID)
	}
	if !got.Edges[0].ValidFrom.Equal(early) {
		t.Errorf("e1 ValidFrom = %v, want %v", got.Edges[0].ValidFrom, early)
	}
	if len(got.Nodes) != 2 || got.Nodes[0].ID != "n1" || got.Nodes[1].ID != "n2" {
		t.Errorf("nodes = %+v, want n1 n2", got.Nodes)
	}
}

func TestMergeEmpty(t *testing.T) {
	got := Merge()
	if len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Errorf("Merge() = %+v, want empty", got)
	}
	got = Merge(Stream{}, Stream{})
	if len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Errorf("Merge(empty, empty) = %+v, want empty", got)
	}
}

func TestMergeDoesNotAliasInput(t *testing.T) {
	a := Stream{Nodes: []NodeRecord{{ID: "n1"}}}
	got := Merge(a)
	got.Nodes[0].ID = "changed"
	if a.Nodes[0].ID != "n1" {
		t.Errorf("Merge aliased its input slice")
	}
}
