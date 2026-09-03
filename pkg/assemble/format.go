// Scalar renderings shared by every mapping. A property value is always a
// Varve scalar, so a time or a float reaches the wire through one of these.

package assemble

import (
	"strconv"
	"time"

	"github.com/ravan/sluice/pkg/varve"
)

// fmtTime renders a required timestamp as a plain RFC3339 string property
// (guarded valid time is S2). Always non-empty, always in the id hash.
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// fmtTimePtr renders an optional timestamp: "" when nil (omitted from props,
// "" in the id hash).
func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func toNodeIDs(ids []string) []varve.NodeID {
	out := make([]varve.NodeID, len(ids))
	for i, s := range ids {
		out[i] = varve.NodeID(s)
	}
	return out
}
