package session

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/ratelimit"
)

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
