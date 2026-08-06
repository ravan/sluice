package assemble

import (
	"reflect"
	"testing"

	"github.com/ravan/sluice/internal/varve"
)

func TestHashPartsInjective(t *testing.T) {
	if hashParts("a", "b") == hashParts("ab") {
		t.Errorf("hashParts not injective: hashParts(a,b) == hashParts(ab)")
	}
	first := hashParts("a", "b")
	second := hashParts("a", "b")
	if first != second {
		t.Errorf("hashParts not deterministic: %q != %q", first, second)
	}
}

func TestEncodeKV(t *testing.T) {
	if got := encodeKV(nil); got != "" {
		t.Errorf("encodeKV(nil) = %q, want %q", got, "")
	}
	got := encodeKV([]KVPair{{"BinaryArtifacts", "10"}, {"CI-Tests", "9"}})
	want := "BinaryArtifacts\x1f10\nCI-Tests\x1f9"
	if got != want {
		t.Errorf("encodeKV = %q, want %q", got, want)
	}
}

func TestJoinIDs(t *testing.T) {
	if got := joinIDs(nil); got != "" {
		t.Errorf("joinIDs(nil) = %q, want %q", got, "")
	}
	if got := joinIDs([]varve.NodeID{"a", "b"}); got != "a\nb" {
		t.Errorf("joinIDs = %q, want %q", got, "a\nb")
	}
}

func TestSortedIDs(t *testing.T) {
	in := []varve.NodeID{"b", "a"}
	got := sortedIDs(in)
	want := []varve.NodeID{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedIDs = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(in, []varve.NodeID{"b", "a"}) {
		t.Errorf("sortedIDs mutated input: %v", in)
	}
}
