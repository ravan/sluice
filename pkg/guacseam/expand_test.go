package guacseam

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

type fakeRetriever struct {
	emit int
	err  error
}

func (f *fakeRetriever) RetrieveArtifacts(_ context.Context, ch chan<- *processor.Document) error {
	for i := 0; i < f.emit; i++ {
		ch <- &processor.Document{}
	}
	return f.err
}

func TestDrainExpansion(t *testing.T) {
	errBoom := errors.New("boom")

	cases := []struct {
		name          string
		emit          int
		retErr        error
		limit         int
		handleErrOn   int // 0 = handle always nil; N = return errBoom on the Nth call
		wantCollected int
		wantExhausted bool
		wantCalls     int
		wantErrIs     error
		wantErrSub    string
		wantNilErr    bool
	}{
		{name: "budget clamps overflow", emit: 5, limit: 3, wantCollected: 3, wantExhausted: true, wantCalls: 3, wantNilErr: true},
		{name: "below budget", emit: 2, limit: 3, wantCollected: 2, wantExhausted: false, wantCalls: 2, wantNilErr: true},
		{name: "zero budget", emit: 3, limit: 0, wantCollected: 0, wantExhausted: true, wantCalls: 0, wantNilErr: true},
		{name: "retriever error wrapped", emit: 3, retErr: errors.New("boom"), limit: 5, wantCollected: 3, wantCalls: 3, wantErrSub: "deps.dev expansion"},
		{name: "handle error stops without deadlock", emit: 5, limit: 5, handleErrOn: 2, wantCollected: 1, wantCalls: 2, wantErrIs: errBoom},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeRetriever{emit: tt.emit, err: tt.retErr}
			var calls int
			handle := func(context.Context, *processor.Document) error {
				calls++
				if tt.handleErrOn != 0 && calls == tt.handleErrOn {
					return errBoom
				}
				return nil
			}

			exp, err := drainExpansion(context.Background(), r, tt.limit, handle)

			if exp.Collected != tt.wantCollected {
				t.Errorf("Collected = %d, want %d", exp.Collected, tt.wantCollected)
			}
			if exp.Exhausted != tt.wantExhausted {
				t.Errorf("Exhausted = %v, want %v", exp.Exhausted, tt.wantExhausted)
			}
			if exp.Limit != tt.limit {
				t.Errorf("Limit = %d, want %d", exp.Limit, tt.limit)
			}
			if calls != tt.wantCalls {
				t.Errorf("handle called %d times, want %d", calls, tt.wantCalls)
			}
			if tt.wantNilErr && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("err = %v, want errors.Is %v", err, tt.wantErrIs)
			}
			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("err = nil, want it to contain %q", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("err = %q, want it to contain %q", err.Error(), tt.wantErrSub)
				}
			}
		})
	}
}
