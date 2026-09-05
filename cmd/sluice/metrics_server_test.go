package main

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestMetricsServerClosesIncompleteHeaders(t *testing.T) {
	srv := newMetricsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("incomplete request reached handler") }))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatal("metrics timeouts must be bounded")
	}
	srv.ReadHeaderTimeout = 30 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
	})
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost:")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = bufio.NewReader(conn).ReadByte()
	if err == nil {
		t.Fatal("expected incomplete request connection to close")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("server retained incomplete header connection")
	}
}
