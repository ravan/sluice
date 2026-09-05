package assemble

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/ravan/sluice/pkg/varve"
)

// frameParts length-prefixes each field in bytes. Empty fields retain their
// positions, and embedded separators cannot change field boundaries.
func frameParts(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return b.String()
}

// hashParts hashes the unambiguous field encoding.
func hashParts(parts ...string) string {
	sum := sha256.Sum256([]byte(frameParts(parts...)))
	return hex.EncodeToString(sum[:])
}

// KVPair packs one small ordered (key,value) for encodeKV.
type KVPair struct{ Key, Value string }

// encodeKV sorts pairs by key then value and length-prefixes every field.
// An empty slice produces an empty string.
func encodeKV(pairs []KVPair) string {
	sorted := append([]KVPair(nil), pairs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Key == sorted[j].Key {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].Key < sorted[j].Key
	})
	parts := make([]string, 0, 2*len(sorted))
	for _, p := range sorted {
		parts = append(parts, p.Key, p.Value)
	}
	return frameParts(parts...)
}

// joinIDs length-prefixes an ID list into one scalar property. Empty slices
// produce an empty string.
func joinIDs(ids []varve.NodeID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, string(id))
	}
	return frameParts(parts...)
}

// sortedIDs returns a lexicographically sorted copy (never mutates input).
func sortedIDs(ids []varve.NodeID) []varve.NodeID {
	out := make([]varve.NodeID, len(ids))
	copy(out, ids)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
