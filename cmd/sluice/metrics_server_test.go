package main

import (
	"bufio"
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
	defer srv.Close()
	go srv.Serve(ln)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost:")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = bufio.NewReader(conn).ReadByte()
	if err == nil {
		t.Fatal("expected incomplete request connection to close")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("server retained incomplete header connection")
	}
}
