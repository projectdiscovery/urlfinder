package session

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

func TestRedirectKeepsKeyHeaderOnSameHost(t *testing.T) {
	var got string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			to := server.URL + "/end"
			if strings.HasPrefix(r.Host, "localhost") {
				to = r.URL.Query().Get("to")
			}
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		got = r.Header.Get("X-Api-Key")
	}))
	defer server.Close()

	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	for _, target := range []string{server.URL, "http://localhost:" + port} {
		got = ""
		// the redirect goes to the same host spelled in upper case
		get(t, target+"/start?to="+url.QueryEscape("http://LOCALHOST:"+port+"/end"))
		if got != "secret" {
			t.Fatalf("key header on same-host redirect from %s = %q, want it kept", target, got)
		}
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

func newTestSession(t *testing.T) (*Session, context.Context) {
	t.Helper()
	ctx := context.Background()
	limiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{Key: "test", IsUnlimited: true})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession("example.com", "", limiter, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	return sess, context.WithValue(ctx, CtxSourceArg, "test")
}

func TestSessionVerifiesCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("https://example.com/secret"))
	}))
	defer srv.Close()

	sess, ctx := newTestSession(t)
	resp, err := sess.SimpleGet(ctx, srv.URL)
	if err == nil {
		sess.DiscardHTTPResponse(resp)
		t.Fatal("request to a server with an untrusted certificate succeeded")
	}
	var verifyErr *tls.CertificateVerificationError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected a certificate verification error, got %v", err)
	}
}

func TestSessionPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	sess, ctx := newTestSession(t)
	resp, err := sess.SimpleGet(ctx, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sess.DiscardHTTPResponse(resp)
}
