package varve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// NodeID is a node's deterministic, content-derived `_id` (§6 inv. 2).
type NodeID string

// EdgeID is an edge's deterministic `_id`: "<srcId>|<label>|<dstId>".
type EdgeID string

// NodeLabel and EdgeLabel are wire-level graph labels. The label *vocabulary*
// lives in internal/assemble; this package stays graph-model-blind.
type NodeLabel string
type EdgeLabel string

// Value is the closed set of scalar property values POST /v1/ingest accepts.
// Sealed by an unexported method: nested values and null are 422s on the wire,
// so they are unrepresentable here (§6 inv. 3).
type Value interface{ isValue() }

type Str string
type Int int64
type Float float64
type Bool bool

func (Str) isValue()   {}
func (Int) isValue()   {}
func (Float) isValue() {}
func (Bool) isValue()  {}

// Prop is one property. Props are emitted in slice order, so record bytes are
// deterministic and golden-testable.
type Prop struct {
	Key   string
	Value Value
}

// NodeRecord is one {"type":"node"} line; ID is emitted as props._id.
type NodeRecord struct {
	ID        NodeID
	Labels    []NodeLabel
	Props     []Prop
	ValidFrom time.Time // zero ⇒ omitted from the wire (Varve reads absent as
	// "valid from now to forever", per the bulk-ingest
	// contract); non-zero ⇒ emitted as top-level valid_from
}

// EdgeRecord is one {"type":"edge"} line; ID is emitted as props._id.
type EdgeRecord struct {
	ID        EdgeID
	Label     EdgeLabel
	Src       NodeID
	Dst       NodeID
	Props     []Prop
	ValidFrom time.Time // zero ⇒ omitted from the wire (Varve reads absent as
	// "valid from now to forever", per the bulk-ingest
	// contract); non-zero ⇒ emitted as top-level valid_from
}

// Stream is the record stream (§2.1): one assembly's nodes and edges,
// emitted nodes-first.
type Stream struct {
	Nodes []NodeRecord
	Edges []EdgeRecord
}

// WriteNDJSON writes s as bulk-ingest NDJSON: one '\n'-terminated JSON object
// per record, all nodes then all edges, each in slice order.
func WriteNDJSON(w io.Writer, s Stream) error {
	for _, n := range s.Nodes {
		if err := writeNode(w, n); err != nil {
			return err
		}
	}
	for _, e := range s.Edges {
		if err := writeEdge(w, e); err != nil {
			return err
		}
	}
	return nil
}

func writeNode(w io.Writer, n NodeRecord) error {
	labels := n.Labels
	if labels == nil {
		labels = []NodeLabel{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("marshal labels: %w", err)
	}
	var b bytes.Buffer
	b.WriteString(`{"type":"node","labels":`)
	b.Write(labelsJSON)
	b.WriteString(`,"props":`)
	if err := writeProps(&b, string(n.ID), n.Props); err != nil {
		return err
	}
	if !n.ValidFrom.IsZero() {
		vfJSON, err := json.Marshal(n.ValidFrom.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("marshal valid_from: %w", err)
		}
		b.WriteString(`,"valid_from":`)
		b.Write(vfJSON)
	}
	b.WriteString("}\n")
	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("write node record: %w", err)
	}
	return nil
}

func writeEdge(w io.Writer, e EdgeRecord) error {
	var b bytes.Buffer
	b.WriteString(`{"type":"edge",`)
	if err := writeKeyValue(&b, "label", string(e.Label)); err != nil {
		return err
	}
	b.WriteByte(',')
	if err := writeKeyValue(&b, "src", string(e.Src)); err != nil {
		return err
	}
	b.WriteByte(',')
	if err := writeKeyValue(&b, "dst", string(e.Dst)); err != nil {
		return err
	}
	b.WriteString(`,"props":`)
	if err := writeProps(&b, string(e.ID), e.Props); err != nil {
		return err
	}
	if !e.ValidFrom.IsZero() {
		vfJSON, err := json.Marshal(e.ValidFrom.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("marshal valid_from: %w", err)
		}
		b.WriteString(`,"valid_from":`)
		b.Write(vfJSON)
	}
	b.WriteString("}\n")
	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("write edge record: %w", err)
	}
	return nil
}

func writeProps(b *bytes.Buffer, id string, props []Prop) error {
	b.WriteString(`{"_id":`)
	idJSON, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("marshal _id: %w", err)
	}
	b.Write(idJSON)
	for _, p := range props {
		b.WriteByte(',')
		keyJSON, err := json.Marshal(p.Key)
		if err != nil {
			return fmt.Errorf("marshal prop key %q: %w", p.Key, err)
		}
		b.Write(keyJSON)
		b.WriteByte(':')
		valJSON, err := json.Marshal(p.Value)
		if err != nil {
			return fmt.Errorf("marshal prop value %q: %w", p.Key, err)
		}
		b.Write(valJSON)
	}
	b.WriteByte('}')
	return nil
}

func writeKeyValue(b *bytes.Buffer, key, value string) error {
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("marshal key %q: %w", key, err)
	}
	b.Write(keyJSON)
	b.WriteByte(':')
	valJSON, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal value for %q: %w", key, err)
	}
	b.Write(valJSON)
	return nil
}
