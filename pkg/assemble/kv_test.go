package assemble

import (
	"reflect"
	"testing"

	"github.com/ravan/sluice/pkg/varve"
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
	want := "15:BinaryArtifacts2:108:CI-Tests1:9"
	if got != want {
		t.Errorf("encodeKV = %q, want %q", got, want)
	}
}

func TestJoinIDs(t *testing.T) {
	if got := joinIDs(nil); got != "" {
		t.Errorf("joinIDs(nil) = %q, want %q", got, "")
	}
	if got := joinIDs([]varve.NodeID{"a", "b"}); got != "1:a1:b" {
		t.Errorf("joinIDs = %q, want %q", got, "1:a1:b")
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

// TestEncodeKVIsOrderIndependent pins that evidence ids built from GUAC
// map-ordered pairs do not change between runs.
func TestEncodeKVIsOrderIndependent(t *testing.T) {
	a := encodeKV([]KVPair{{"b", "2"}, {"a", "1"}, {"c", "3"}})
	b := encodeKV([]KVPair{{"c", "3"}, {"a", "1"}, {"b", "2"}})
	if a != b {
		t.Fatalf("encodeKV depends on input order:\n%q\n%q", a, b)
	}
	if a != "1:a1:11:b1:21:c1:3" {
		t.Fatalf("unexpected canonical form %q", a)
	}
}

func TestEvidenceFieldBoundaries(t *testing.T) {
	for _, fields := range [][2][]string{
		{{"a\x1fb", "c"}, {"a", "b\x1fc"}},
		{{""}, {}},
		{{"a", ""}, {"a"}},
		{{"1:a", "b"}, {"1", ":ab"}},
	} {
		if EvidenceID("HasMetadata", fields[0]...) == EvidenceID("HasMetadata", fields[1]...) {
			t.Fatalf("collision: %q / %q", fields[0], fields[1])
		}
	}
	if encodeKV([]KVPair{{"a\x1fb", "c"}}) == encodeKV([]KVPair{{"a", "b\x1fc"}}) {
		t.Fatal("KV field collision")
	}
	if encodeKV([]KVPair{{"a", "b\nc\x1fd"}}) == encodeKV([]KVPair{{"a", "b"}, {"c", "d"}}) {
		t.Fatal("KV pair collision")
	}
	if joinIDs([]varve.NodeID{"a\nb", "c"}) == joinIDs([]varve.NodeID{"a", "b\nc"}) {
		t.Fatal("ID list collision")
	}
}
