package varve

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func TestValueScalars(t *testing.T) {
	for _, tc := range []struct {
		value Value
		json  string
	}{
		{Str(""), `""`}, {String("x"), `"x"`}, {Int(0), `0`}, {Int(math.MaxInt64), `9223372036854775807`}, {Float(1.25), `1.25`}, {Bool(false), `false`},
	} {
		got, err := json.Marshal(tc.value)
		if err != nil || string(got) != tc.json {
			t.Fatalf("marshal %#v = %s, %v", tc.value, got, err)
		}
	}
	if v, ok := Str("x").AsString(); !ok || v != "x" {
		t.Fatal("string accessor")
	}
	if v, ok := Int(9).AsInt(); !ok || v != 9 {
		t.Fatal("int accessor")
	}
	if v, ok := Float(1.25).AsFloat(); !ok || v != 1.25 {
		t.Fatal("float accessor")
	}
	if v, ok := Bool(true).AsBool(); !ok || !v {
		t.Fatal("bool accessor")
	}
	if _, ok := Int(0).AsString(); ok {
		t.Fatal("int accepted as string")
	}
	if _, ok := (Value{}).AsBool(); ok {
		t.Fatal("zero accepted as bool")
	}
}

func TestInvalidValuesCannotReachWire(t *testing.T) {
	for _, v := range []Value{{}, Float(math.NaN()), Float(math.Inf(1)), Float(math.Inf(-1))} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatalf("marshal accepted %#v", v)
		}
		for _, stream := range []Stream{
			{Nodes: []NodeRecord{{ID: "n", Props: []Prop{{Key: "missing", Value: v}}}}},
			{Edges: []EdgeRecord{{ID: "e", Src: "a", Dst: "b", Label: "l", Props: []Prop{{Key: "missing", Value: v}}}}},
		} {
			var b bytes.Buffer
			if err := WriteNDJSON(&b, stream); err == nil || b.Len() != 0 {
				t.Fatalf("invalid scalar emitted: %q, %v", b.String(), err)
			}
		}
	}
}
