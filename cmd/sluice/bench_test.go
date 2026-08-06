package main

import (
	"math"
	"testing"
	"time"
)

func TestBenchResultRecords(t *testing.T) {
	cases := []struct {
		r    benchResult
		want int
	}{
		{benchResult{Nodes: 6339, Edges: 9338}, 15677},
		{benchResult{Nodes: 0, Edges: 0}, 0},
		{benchResult{Nodes: 10, Edges: 5}, 15},
	}
	for _, c := range cases {
		if got := c.r.records(); got != c.want {
			t.Errorf("records() = %d, want %d (%+v)", got, c.want, c.r)
		}
	}
}

func TestBenchResultRates(t *testing.T) {
	const eps = 1e-6
	cases := []struct {
		r        benchResult
		wantRecs float64
		wantEdge float64
	}{
		{benchResult{Nodes: 6339, Edges: 9338, Elapsed: time.Second}, 15677.0, 9338.0},
		{benchResult{Nodes: 6339, Edges: 9338, Elapsed: 500 * time.Millisecond}, 31354.0, 18676.0},
		{benchResult{Nodes: 100, Edges: 400, Elapsed: 2 * time.Second}, 250.0, 200.0},
		{benchResult{Nodes: 0, Edges: 0, Elapsed: 0}, 0, 0},
	}
	for _, c := range cases {
		if got := c.r.recordsPerSec(); math.Abs(got-c.wantRecs) > eps {
			t.Errorf("recordsPerSec() = %v, want %v (%+v)", got, c.wantRecs, c.r)
		}
		if got := c.r.edgesPerSec(); math.Abs(got-c.wantEdge) > eps {
			t.Errorf("edgesPerSec() = %v, want %v (%+v)", got, c.wantEdge, c.r)
		}
	}
}

func TestBenchResultBeatsBranch(t *testing.T) {
	cases := []struct {
		r    benchResult
		want bool
	}{
		{benchResult{Edges: 409, Elapsed: time.Second}, true},
		{benchResult{Edges: 408, Elapsed: time.Second}, false},
		{benchResult{Edges: 9338, Elapsed: time.Second}, true},
		{benchResult{Edges: 100, Elapsed: time.Second}, false},
		{benchResult{Edges: 9338, Elapsed: 0}, false},
	}
	for _, c := range cases {
		if got := c.r.beatsBranch(); got != c.want {
			t.Errorf("beatsBranch() = %v, want %v (%+v)", got, c.want, c.r)
		}
	}
}
