package varve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngestRedirectPolicy(t *testing.T) {
	for _, status := range []int{http.StatusMisdirectedRequest, http.StatusTemporaryRedirect, http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusPermanentRedirect} {
		for _, scenario := range []string{"untrusted", "trusted", "downgrade"} {
			t.Run(fmt.Sprintf("%d/%s", status, scenario), func(t *testing.T) {
				var calls atomic.Int64
				destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Authorization") != "Bearer secret" {
						t.Error("trusted destination missing bearer")
					}
					_, _ = io.WriteString(w, `{}`)
				}))
				defer destination.Close()
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if status == http.StatusMisdirectedRequest {
						w.WriteHeader(status)
						_, _ = fmt.Fprintf(w, `{"writer":%q}`, destination.URL)
					} else {
						http.Redirect(w, r, destination.URL, status)
					}
				})
				source := httptest.NewUnstartedServer(handler)
				if scenario == "downgrade" {
					source.StartTLS()
				} else {
					source.Start()
				}
				defer source.Close()
				cfg := ClientConfig{Addr: source.URL, Token: "secret", HTTP: source.Client(), MaxAttempts: 2}
				if scenario != "untrusted" {
					cfg.TrustedWriters = []string{destination.URL}
				}
				client, err := NewClient(cfg)
				if err != nil {
					t.Fatal(err)
				}
				client.sleep = func(context.Context, time.Duration) error { return nil }
				_, err = client.Ingest(context.Background(), orderStream())
				if scenario == "trusted" && (status == 421 || status == 307 || status == 308) {
					if err != nil || calls.Load() != 1 {
						t.Fatalf("trusted redirect: calls=%d err=%v", calls.Load(), err)
					}
				} else if err == nil || calls.Load() != 0 {
					t.Fatalf("unsafe redirect: calls=%d err=%v", calls.Load(), err)
				}
			})
		}
	}
}

func TestIngestResponseLimit(t *testing.T) {
	for _, status := range []int{200, 421, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				// Chunked responses have no trustworthy Content-Length.
				w.(http.Flusher).Flush()
				_, _ = io.Copy(w, strings.NewReader(strings.Repeat("x", maxResponseBytes+1)))
			}))
			defer source.Close()
			client, err := NewClient(ClientConfig{Addr: source.URL, Token: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.Ingest(context.Background(), orderStream()); err == nil || !strings.Contains(err.Error(), "response body exceeds") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestNewClientDoesNotMutateHTTPClient(t *testing.T) {
	shared := &http.Client{}
	_, err := NewClient(ClientConfig{Addr: "https://writer.example", Token: "secret", HTTP: shared})
	if err != nil {
		t.Fatal(err)
	}
	if shared.CheckRedirect != nil {
		t.Fatal("mutated shared HTTP client")
	}
	for _, origin := range []string{"https://user:secret@writer.example", "https://writer.example/path", "https://writer.example?x=y", "ftp://writer.example"} {
		if _, err := NewClient(ClientConfig{Addr: "https://writer.example", Token: "secret", TrustedWriters: []string{origin}}); err == nil {
			t.Errorf("accepted origin %q", origin)
		}
	}
}

func TestRedirectHookCannotBypassTrust(t *testing.T) {
	var leaked atomic.Int64
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer attacker.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	hc := source.Client()
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		parsed, err := http.NewRequest(http.MethodPost, attacker.URL, nil)
		if err != nil {
			return err
		}
		req.URL = parsed.URL
		return nil
	}
	client, err := NewClient(ClientConfig{Addr: source.URL, Token: "secret", HTTP: hc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Ingest(context.Background(), orderStream()); err == nil || leaked.Load() != 0 {
		t.Fatalf("hook bypass: calls=%d err=%v", leaked.Load(), err)
	}
}

func TestTrustedCrossHostnameRedirectPreservesPOST(t *testing.T) {
	var calls atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Method != http.MethodPost || string(body) != orderStreamNDJSON || r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("request lost method/body/token: %s %q %q", r.Method, body, r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer destination.Close()
	target := strings.Replace(destination.URL, "127.0.0.1", "localhost", 1)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := NewClient(ClientConfig{Addr: source.URL, Token: "secret", TrustedWriters: []string{target}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Ingest(context.Background(), orderStream()); err != nil || calls.Load() != 1 {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
}
