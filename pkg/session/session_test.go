package session

import (
	"context"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

func TestRedirectKeepsKeyHeaderOnSameHost(t *testing.T) {
	var got string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, server.URL+"/end", http.StatusFound)
			return
		}
		got = r.Header.Get("X-Api-Key")
	}))
	defer server.Close()

	get(t, server.URL+"/start")
	if got != "secret" {
		t.Fatalf("key header on same-host redirect = %q, want it kept", got)
	}
}

func TestRedirectDropsKeyHeaderOnOtherHost(t *testing.T) {
	var got, userAgent string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
		userAgent = r.Header.Get("User-Agent")
	}))
	defer other.Close()
	_, port, _ := net.SplitHostPort(other.Listener.Addr().String())
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// localhost and 127.0.0.1 reach the same listener but are different hosts
		http.Redirect(w, r, "http://localhost:"+port, http.StatusFound)
	}))
	defer origin.Close()

	get(t, origin.URL)
	if got != "" {
		t.Fatalf("key header reached the redirect target on another host: %q", got)
	}
	if userAgent == "" {
		t.Fatal("session headers should still be sent after a cross-host redirect")
	}
}

func get(t *testing.T, getURL string) {
	t.Helper()
	ctx := context.WithValue(context.Background(), CtxSourceArg, "test")
	limiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         "test",
		IsUnlimited: true,
		MaxCount:    math.MaxUint32,
		Duration:    time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create a rate limiter: %v", err)
	}
	t.Cleanup(func() { limiter.Stop() })
	sess, err := NewSession("example.com", "", limiter, 5)
	if err != nil {
		t.Fatalf("failed to create a session: %v", err)
	}
	resp, err := sess.Get(ctx, getURL, "", map[string]string{"X-Api-Key": "secret"})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	sess.DiscardHTTPResponse(resp)
}
