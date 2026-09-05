package varve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Receipt is the folded chunk receipt POST /v1/ingest returns.
type Receipt struct {
	Nodes        int64     `json:"nodes"`
	Edges        int64     `json:"edges"`
	Transactions int64     `json:"transactions"`
	Basis        int64     `json:"basis"`
	SystemTime   time.Time `json:"system_time"`
}

// IngestError is a non-2xx answer from POST /v1/ingest. The stream is
// chunk-atomic, not stream-atomic, so Committed reports the progress that
// survived (§2.6).
type IngestError struct {
	Status    int
	Message   string
	Committed Receipt
}

func (e *IngestError) Error() string {
	return fmt.Sprintf("varve ingest: status %d: %s", e.Status, e.Message)
}

// ingestErrorBody unions the two error shapes the endpoint returns: the
// bulk-ingest fast-fail body ({"error","committed"}) and varved's generic
// error body ({"code","message","writer"}).
type ingestErrorBody struct {
	Error     string  `json:"error"`
	Message   string  `json:"message"`
	Code      string  `json:"code"`
	Writer    string  `json:"writer"`
	Committed Receipt `json:"committed"`
}

// TokenProvider returns the bearer token for one HTTP attempt. It is called
// once per attempt, so a short-lived token can be minted or refreshed by the
// caller (a 421 redirect or a 429 retry may land after a 60 s token expired).
// It must be safe for concurrent use.
type TokenProvider func(ctx context.Context) (string, error)

// StaticToken wraps a constant token as a TokenProvider.
func StaticToken(token string) TokenProvider {
	return func(context.Context) (string, error) { return token, nil }
}

// ClientConfig is the untyped edge; Addr is parsed exactly once, in NewClient.
type ClientConfig struct {
	Addr string
	// TrustedWriters lists additional trusted HTTP origins (scheme, host, port).
	// Addr is always trusted. Redirects never permit HTTPS to HTTP downgrades.
	TrustedWriters []string
	Token          string        // convenience; wrapped by StaticToken when TokenProvider is nil
	TokenProvider  TokenProvider // wins over Token when both are set
	Graph          string        // "" ⇒ no ?graph= parameter ⇒ Varve default graph
	HTTP           *http.Client
	MaxAttempts    int
	OnRetry        func(attempt int, wait time.Duration)
}

// sleeper is the injected wait seam (real: sleepUntil; tests: a recording no-op).
type sleeper func(ctx context.Context, d time.Duration) error

// Client streams record streams to one Varve writer. It knows nothing of GUAC
// (§3 boundary).
type Client struct {
	base        *url.URL
	trusted     map[string]bool
	token       TokenProvider
	graph       string
	http        *http.Client
	maxAttempts int
	onRetry     func(attempt int, wait time.Duration)
	sleep       sleeper
	now         func() time.Time
}

const (
	maxResponseBytes = 1 << 20 // receipts and error responses are limited to 1 MiB
	retryBaseDelay   = 250 * time.Millisecond
	retryMaxDelay    = 30 * time.Second
)

// NewClient parses cfg. It errors when Addr is not an absolute http/https URL,
// when both Token and TokenProvider are empty, or when Graph starts with "__"
// (Varve reserves that prefix). A nil HTTP becomes
// &http.Client{Timeout: 2 * time.Minute}.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("parse addr %q: %w", cfg.Addr, err)
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("addr %q must be an absolute http/https URL", cfg.Addr)
	}
	trusted, err := trustedOrigins(u, cfg.TrustedWriters)
	if err != nil {
		return nil, err
	}
	token := cfg.TokenProvider
	if token == nil {
		if cfg.Token == "" {
			return nil, fmt.Errorf("token must not be empty")
		}
		token = StaticToken(cfg.Token)
	}
	if strings.HasPrefix(cfg.Graph, "__") {
		return nil, fmt.Errorf("graph %q: names starting with \"__\" are reserved", cfg.Graph)
	}
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	// Copy the caller's client so installing policy cannot mutate shared state.
	copyHTTP := *hc
	previousRedirect := hc.CheckRedirect
	copyHTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if err := checkDestination(trusted, via[len(via)-1].URL, req.URL); err != nil {
			return err
		}
		if previousRedirect != nil {
			if err := previousRedirect(req, via); err != nil {
				return err
			}
		}
		// A caller hook may mutate the destination or method. Validate the final request.
		if err := checkDestination(trusted, via[len(via)-1].URL, req.URL); err != nil {
			return err
		}
		if req.Method != http.MethodPost {
			return fmt.Errorf("%w: redirect changed POST method", errUnsafeRedirect)
		}
		setGraph(req.URL, cfg.Graph)
		// net/http strips credentials across hosts, including explicitly trusted writers.
		req.Header.Set("Authorization", via[0].Header.Get("Authorization"))
		return nil
	}
	hc = &copyHTTP
	maxAttempts := cfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 4
	}
	return &Client{
		base:        u,
		trusted:     trusted,
		token:       token,
		graph:       cfg.Graph,
		http:        hc,
		maxAttempts: maxAttempts,
		onRetry:     cfg.OnRetry,
		sleep:       sleepUntil,
		now:         time.Now,
	}, nil
}

// origin includes the port, so trust cannot silently expand to another service.
func origin(u *url.URL) string { return strings.ToLower(u.Scheme + "://" + u.Host) }

var errUnsafeRedirect = errors.New("untrusted or insecure writer redirect")

func checkDestination(trusted map[string]bool, from, to *url.URL) error {
	if to.User != nil || !trusted[origin(to)] || (from.Scheme == "https" && to.Scheme != "https") {
		return errUnsafeRedirect
	}
	return nil
}

// verbatim exception — Retry-After has two exact wire forms; the parse IS the rule.
// Reads an HTTP Retry-After (delta-seconds or HTTP-date) as a duration relative to
// now; empty/unparseable/past ⇒ 0.
func parseRetryAfter(h string, now time.Time) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// verbatim exception — capped exponential backoff; the overflow guard is subtle.
func backoff(attempt int) time.Duration {
	if attempt > 8 {
		return retryMaxDelay
	}
	d := retryBaseDelay << (attempt - 1)
	if d > retryMaxDelay {
		return retryMaxDelay
	}
	return d
}

// verbatim exception — ctx-aware wait so a shutdown mid-retry returns promptly.
func sleepUntil(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ingestURL is <base>/v1/ingest plus ?graph=<graph> when a graph is set.
func (c *Client) ingestURL(base *url.URL) string {
	u := base.JoinPath("/v1/ingest")
	setGraph(u, c.graph)
	return u.String()
}

// Ingest POSTs s to <Addr>/v1/ingest[?graph=<Graph>] as application/x-ndjson
// and returns the receipt. The bearer token is fetched from the TokenProvider
// once per attempt. Transient failures (transport error, 408, 429, 503) are
// retried with capped exponential backoff; a 421 can redirect to a trusted
// writer named in the error body within the same attempt budget. Any terminal non-2xx answer (including 404
// unknown_graph) is returned as *IngestError.
func (c *Client) Ingest(ctx context.Context, s Stream) (Receipt, error) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, s); err != nil {
		return Receipt{}, fmt.Errorf("serialise stream: %w", err)
	}

	target := c.base

	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		token, err := c.token(ctx)
		if err != nil {
			return Receipt{}, fmt.Errorf("fetch token: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ingestURL(target), bytes.NewReader(buf.Bytes()))
		if err != nil {
			return Receipt{}, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-ndjson")

		resp, err := c.http.Do(req)
		if err != nil {
			if attempt < c.maxAttempts && !errors.Is(err, errUnsafeRedirect) {
				wait := backoff(attempt)
				if c.onRetry != nil {
					c.onRetry(attempt, wait)
				}
				if serr := c.sleep(ctx, wait); serr != nil {
					return Receipt{}, fmt.Errorf("retry wait: %w", serr)
				}
				continue
			}
			return Receipt{}, fmt.Errorf("post /v1/ingest: %w", err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		closeErr := resp.Body.Close()
		if len(body) > maxResponseBytes {
			return Receipt{}, fmt.Errorf("response body exceeds %d bytes", maxResponseBytes)
		}
		if readErr != nil {
			return Receipt{}, fmt.Errorf("read response body: %w", readErr)
		}
		if closeErr != nil {
			return Receipt{}, fmt.Errorf("close response body: %w", closeErr)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var r Receipt
			if err := json.Unmarshal(body, &r); err != nil {
				return Receipt{}, fmt.Errorf("decode receipt: %w", err)
			}
			return r, nil
		}

		var eb ingestErrorBody
		if jerr := json.Unmarshal(body, &eb); jerr != nil {
			// Not one of the JSON error shapes. Discard any partial decode so
			// the message below falls back to the raw body.
			eb = ingestErrorBody{}
		}

		var wait time.Duration
		retry := false
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			wait = parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
			if wait <= 0 {
				wait = backoff(attempt)
			}
			retry = true
		case http.StatusMisdirectedRequest:
			if w, werr := url.Parse(eb.Writer); werr == nil && w.IsAbs() && (w.Scheme == "http" || w.Scheme == "https") && w.Host != "" && checkDestination(c.trusted, resp.Request.URL, w) == nil && attempt < c.maxAttempts {
				target = w
				wait = backoff(attempt)
				retry = true
			}
		case http.StatusRequestTimeout, http.StatusServiceUnavailable:
			wait = backoff(attempt)
			retry = true
		}

		if retry && attempt < c.maxAttempts {
			if c.onRetry != nil {
				c.onRetry(attempt, wait)
			}
			if serr := c.sleep(ctx, wait); serr != nil {
				return Receipt{}, fmt.Errorf("retry wait: %w", serr)
			}
			continue
		}

		msg := eb.Error
		if msg == "" {
			msg = eb.Message
		}
		if msg == "" {
			msg = eb.Code
		}
		if msg == "" {
			if len(body) > 200 {
				msg = string(body[:200])
			} else {
				msg = string(body)
			}
		}
		return Receipt{}, &IngestError{Status: resp.StatusCode, Message: msg, Committed: eb.Committed}
	}

	return Receipt{}, fmt.Errorf("ingest: exhausted %d attempts", c.maxAttempts)
}

func trustedOrigins(base *url.URL, writers []string) (map[string]bool, error) {
	trusted := map[string]bool{origin(base): true}
	for _, addr := range writers {
		w, err := url.Parse(addr)
		if err != nil || w.Host == "" || (w.Scheme != "http" && w.Scheme != "https") || w.User != nil || (w.Path != "" && w.Path != "/") || w.RawQuery != "" || w.Fragment != "" {
			return nil, fmt.Errorf("trusted writer %q must be an HTTP origin", addr)
		}
		trusted[origin(w)] = true
	}
	return trusted, nil
}

// setGraph keeps redirect responses and hooks from changing the selected graph.
func setGraph(u *url.URL, graph string) {
	query := u.Query()
	query.Del("graph")
	if graph != "" {
		query.Set("graph", graph)
	}
	u.RawQuery = query.Encode()
}
