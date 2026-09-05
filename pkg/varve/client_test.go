package varve

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientIngestSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/v1/ingest" {
			t.Errorf("path = %q, want /v1/ingest", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer t0k" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer t0k")
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-ndjson" {
			t.Errorf("Content-Type = %q, want %q", got, "application/x-ndjson")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != orderStreamNDJSON {
			t.Errorf("body =\n%q\nwant\n%q", string(body), orderStreamNDJSON)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"nodes":2,"edges":1,"transactions":1,"basis":7,"system_time":"2026-08-06T20:06:52.999119Z","system_time_us":1786046812999119}`)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t0k"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := c.Ingest(context.Background(), orderStream())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if got.Nodes != 2 || got.Edges != 1 || got.Transactions != 1 || got.Basis != 7 {
		t.Errorf("receipt = %+v, want Nodes=2 Edges=1 Transactions=1 Basis=7", got)
	}
	want := time.Date(2026, 8, 6, 20, 6, 52, 999119000, time.UTC)
	if !got.SystemTime.Equal(want) {
		t.Errorf("SystemTime = %v, want %v", got.SystemTime, want)
	}
}

func TestNewClientRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ClientConfig
		wantErr bool
	}{
		{"no scheme", ClientConfig{Addr: "127.0.0.1:8080", Token: "t0k"}, true},
		{"empty addr", ClientConfig{Addr: "", Token: "t0k"}, true},
		{"empty token", ClientConfig{Addr: "http://127.0.0.1:8080", Token: ""}, true},
		{"valid", ClientConfig{Addr: "http://127.0.0.1:8080", Token: "t0k"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if c != nil {
					t.Errorf("expected nil client, got %v", c)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if c == nil {
				t.Errorf("expected non-nil client")
			}
		})
	}
}

func TestIngestRetriesOn429ThenSucceeds(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"code":"rate_limited","message":"slow down"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"nodes":2,"edges":1,"transactions":1,"basis":7,"system_time":"2026-08-06T20:06:52.999119Z"}`)
	}))
	defer srv.Close()

	var retries atomic.Int64
	c, err := NewClient(ClientConfig{
		Addr:        srv.URL,
		Token:       "t0k",
		MaxAttempts: 3,
		OnRetry:     func(attempt int, wait time.Duration) { retries.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var waits []time.Duration
	c.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC) }
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}

	got, err := c.Ingest(context.Background(), orderStream())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if got.Nodes != 2 || got.Basis != 7 {
		t.Errorf("receipt = %+v, want the 200 receipt", got)
	}
	if n := count.Load(); n != 2 {
		t.Errorf("server received %d requests, want exactly 2", n)
	}
	if len(waits) != 1 {
		t.Fatalf("waits = %v, want exactly one entry", waits)
	}
	if waits[0] != 1*time.Second {
		t.Errorf("waits[0] = %v, want 1s (Retry-After honoured)", waits[0])
	}
	if n := retries.Load(); n != 1 {
		t.Errorf("OnRetry fired %d times, want 1", n)
	}
}

func TestIngestFollows421ToWriter(t *testing.T) {
	var countB atomic.Int64
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		countB.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"nodes":2,"edges":1,"transactions":1,"basis":7,"system_time":"2026-08-06T20:06:52.999119Z"}`)
	}))
	defer srvB.Close()

	var countA atomic.Int64
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		countA.Add(1)
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = io.WriteString(w, `{"code":"misdirected_request","message":"request must be sent to writer","writer":"`+srvB.URL+`"}`)
	}))
	defer srvA.Close()

	c, err := NewClient(ClientConfig{Addr: srvA.URL, TrustedWriters: []string{srvB.URL}, Token: "t0k", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC) }
	c.sleep = func(ctx context.Context, d time.Duration) error { return nil }

	got, err := c.Ingest(context.Background(), orderStream())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if got.Nodes != 2 || got.Basis != 7 {
		t.Errorf("receipt = %+v, want server B's receipt", got)
	}
	if n := countA.Load(); n != 1 {
		t.Errorf("server A received %d requests, want exactly 1", n)
	}
	if n := countB.Load(); n != 1 {
		t.Errorf("server B received %d requests, want exactly 1", n)
	}
}

func TestIngestRetriesOn503(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"unavailable"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"nodes":2,"edges":1,"transactions":1,"basis":7,"system_time":"2026-08-06T20:06:52.999119Z"}`)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t0k", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var waits []time.Duration
	c.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC) }
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}

	got, err := c.Ingest(context.Background(), orderStream())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if got.Nodes != 2 {
		t.Errorf("receipt = %+v, want success", got)
	}
	if n := count.Load(); n != 3 {
		t.Errorf("server received %d requests, want exactly 3", n)
	}
	if len(waits) != 2 {
		t.Fatalf("waits = %v, want exactly two entries", waits)
	}
	for i, d := range waits {
		if d <= 0 {
			t.Errorf("waits[%d] = %v, want > 0 (backoff)", i, d)
		}
	}
}

func TestIngestNoRetryOn422(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"error":"line 1: missing field `+"`dst`"+`","committed":{"nodes":40000,"edges":0,"transactions":4,"basis":12290}}`)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t0k", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error { return nil }

	_, err = c.Ingest(context.Background(), orderStream())
	if err == nil {
		t.Fatal("Ingest: expected error, got nil")
	}
	var ie *IngestError
	if !errors.As(err, &ie) {
		t.Fatalf("error %v does not unwrap to *IngestError", err)
	}
	if ie.Status != 422 {
		t.Errorf("Status = %d, want 422", ie.Status)
	}
	wantMsg := "line 1: missing field `dst`"
	if ie.Message != wantMsg {
		t.Errorf("Message = %q, want %q", ie.Message, wantMsg)
	}
	if ie.Committed.Nodes != 40000 {
		t.Errorf("Committed.Nodes = %d, want 40000", ie.Committed.Nodes)
	}
	if n := count.Load(); n != 1 {
		t.Errorf("server received %d requests, want exactly 1", n)
	}
}

func TestIngestExhaustsRetries(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":"unavailable"}`)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t0k", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC) }
	c.sleep = func(ctx context.Context, d time.Duration) error { return nil }

	_, err = c.Ingest(context.Background(), orderStream())
	if err == nil {
		t.Fatal("Ingest: expected error, got nil")
	}
	var ie *IngestError
	if !errors.As(err, &ie) {
		t.Fatalf("error %v does not unwrap to *IngestError", err)
	}
	if ie.Status != 503 {
		t.Errorf("Status = %d, want 503", ie.Status)
	}
	if n := count.Load(); n != 3 {
		t.Errorf("server received %d requests, want exactly 3", n)
	}
}

func TestIngestContextCancelDuringRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":"unavailable"}`)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{Addr: srv.URL, Token: "t0k", MaxAttempts: 3})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = c.Ingest(ctx, orderStream())
	if err == nil {
		t.Fatal("Ingest: expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want errors.Is(context.Canceled)", err)
	}
}
