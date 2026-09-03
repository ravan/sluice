// Assertions and fixtures the per-subject mapping tests share.

package assemble

import (
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/varve"
)

func countLabel(s varve.Stream, label varve.NodeLabel) int {
	n := 0
	for _, nd := range s.Nodes {
		for _, l := range nd.Labels {
			if l == label {
				n++
			}
		}
	}
	return n
}

func findEdge(s varve.Stream, id varve.EdgeID) (varve.EdgeRecord, bool) {
	for _, e := range s.Edges {
		if e.ID == id {
			return e, true
		}
	}
	return varve.EdgeRecord{}, false
}

func nodeLine(t *testing.T, n varve.NodeRecord) string {
	t.Helper()
	return ndjson(t, varve.Stream{Nodes: []varve.NodeRecord{n}})
}

var fixedTime = time.Date(2023, 5, 6, 7, 8, 9, 0, time.UTC)

const fixedTimeStr = "2023-05-06T07:08:09Z"
