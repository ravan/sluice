package assemble

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/ravan/sluice/internal/varve"
)

// hashParts returns the sha256 hex of parts joined by the unit separator
// '\x1f'. Deterministic and injective across joins.
func hashParts(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// KVPair packs one small ordered (key,value) for encodeKV.
type KVPair struct{ Key, Value string }

// encodeKV packs pairs as "k\x1fv" joined by '\n' (order preserved). Empty
// slice → "".
func encodeKV(pairs []KVPair) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.Key+"\x1f"+p.Value)
	}
	return strings.Join(parts, "\n")
}

// joinIDs packs an id list into one newline-delimited scalar property. Empty
// slice → "".
func joinIDs(ids []varve.NodeID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, string(id))
	}
	return strings.Join(parts, "\n")
}

// sortedIDs returns a lexicographically sorted copy (never mutates input).
func sortedIDs(ids []varve.NodeID) []varve.NodeID {
	out := make([]varve.NodeID, len(ids))
	copy(out, ids)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
