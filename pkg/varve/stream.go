package varve

import "time"

// Merge unions streams into one. Nodes and edges dedup by ID; the first
// record's props win (content-derived ids make repeats byte-identical); the
// earliest non-zero ValidFrom wins. Output order: nodes in first-seen order,
// then edges in first-seen order. The result never aliases an input slice.
//
// This is the ONE dedup rule: assemble's builder and the pipeline's one-shot
// batch both call it, so per-document-then-merge equals one batched assembly.
func Merge(streams ...Stream) Stream {
	var out Stream
	nodeAt := map[NodeID]int{}
	edgeAt := map[EdgeID]int{}
	for _, s := range streams {
		for _, n := range s.Nodes {
			if i, ok := nodeAt[n.ID]; ok {
				out.Nodes[i].ValidFrom = earliest(out.Nodes[i].ValidFrom, n.ValidFrom)
				continue
			}
			nodeAt[n.ID] = len(out.Nodes)
			out.Nodes = append(out.Nodes, n)
		}
		for _, e := range s.Edges {
			if i, ok := edgeAt[e.ID]; ok {
				out.Edges[i].ValidFrom = earliest(out.Edges[i].ValidFrom, e.ValidFrom)
				continue
			}
			edgeAt[e.ID] = len(out.Edges)
			out.Edges = append(out.Edges, e)
		}
	}
	return out
}

// earliest returns the earlier of two times, treating zero as absent.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	default:
		return a
	}
}
