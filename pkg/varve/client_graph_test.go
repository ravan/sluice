package varve

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const okReceipt = `{"nodes":2,"edges":1,"transactions":1,"basis":7,"system_time":"2026-08-06T20:06:52.999119Z"}`

func TestTokenProviderCalledOncePerAttempt(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if count.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"code":"rate_limited"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, okReceipt)
	}))
	defer srv.Close()

	var calls atomic.Int64
	provider := func(context.Context) (string, error) {
		n := calls.Add(1)
		return "tok" + string(rune('0'+n)), nil
	}
	c, err := NewClient(ClientConfig{Addr: srv.URL, TokenProvider: provider, MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC) }
	c.sleep = func(context.Context, time.Duration) error { return nil }

	if _, err := c.Ingest(context.Background(), orderStream()); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("provider called %d times, want 2 (once per attempt)", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != "Bearer tok1,Bearer tok2" {
		t.Errorf("Authorization headers = %v, want [Bearer tok1 Bearer tok2]", seen)
	}
}

func TestTokenProviderWinsOverToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer dynamic" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer dynamic")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, okReceipt)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "static", TokenProvider: StaticToken("dynamic")})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Ingest(context.Background(), orderStream()); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
}

func TestTokenProviderErrorAbortsWithoutRequest(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, okReceipt)
	}))
	defer srv.Close()

	boom := errors.New("no token")
	c, err := NewClient(ClientConfig{Addr: srv.URL, TokenProvider: func(context.Context) (string, error) { return "", boom }})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Ingest(context.Background(), orderStream())
	if !errors.Is(err, boom) {
		t.Fatalf("Ingest error = %v, want errors.Is(boom)", err)
	}
	if n := count.Load(); n != 0 {
		t.Errorf("server received %d requests, want 0", n)
	}
}

func TestNewClientRejectsGraphAndTokenConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ClientConfig
		wantErr bool
	}{
		{"both token and provider empty", ClientConfig{Addr: "http://h"}, true},
		{"provider only", ClientConfig{Addr: "http://h", TokenProvider: StaticToken("t")}, false},
		{"reserved graph", ClientConfig{Addr: "http://h", Token: "t", Graph: "__meta"}, true},
		{"named graph", ClientConfig{Addr: "http://h", Token: "t", Graph: "org_a"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewClient error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestIngestSendsGraphQuery(t *testing.T) {
	for _, tc := range []struct {
		graph, wantQuery string
	}{
		{"org_a", "graph=org_a"},
		{"", ""},
	} {
		t.Run("graph="+tc.graph, func(t *testing.T) {
			var gotPath, gotQuery string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, okReceipt)
			}))
			defer srv.Close()

			c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t", Graph: tc.graph})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, err := c.Ingest(context.Background(), orderStream()); err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			if gotPath != "/v1/ingest" {
				t.Errorf("path = %q, want /v1/ingest", gotPath)
			}
			if gotQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, tc.wantQuery)
			}
		})
	}
}

func TestIngestGraphQuerySurvives421Redirect(t *testing.T) {
	var gotQuery string
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, okReceipt)
	}))
	defer srvB.Close()
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = io.WriteString(w, `{"code":"misdirected_request","writer":"`+srvB.URL+`"}`)
	}))
	defer srvA.Close()

	c, err := NewClient(ClientConfig{Addr: srvA.URL, Token: "t", Graph: "org_a", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := c.Ingest(context.Background(), orderStream()); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if gotQuery != "graph=org_a" {
		t.Errorf("redirected query = %q, want graph=org_a", gotQuery)
	}
}

func TestIngestUnknownGraphIsTerminal404(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"code":"unknown_graph","message":"graph \"org_a\" does not exist"}`)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t", Graph: "org_a", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	_, err = c.Ingest(context.Background(), orderStream())
	var ie *IngestError
	if !errors.As(err, &ie) {
		t.Fatalf("error %v does not unwrap to *IngestError", err)
	}
	if ie.Status != 404 {
		t.Errorf("Status = %d, want 404", ie.Status)
	}
	if !strings.Contains(ie.Message, "org_a") {
		t.Errorf("Message = %q, want it to name the graph", ie.Message)
	}
	if n := count.Load(); n != 1 {
		t.Errorf("server received %d requests, want 1 (no retry)", n)
	}
}
