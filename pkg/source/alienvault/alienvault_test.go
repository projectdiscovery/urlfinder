package alienvault

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

func TestRunReturnsTypedErrors(t *testing.T) {
	tests := []struct {
		name      string
		transport roundTripFunc
	}{
		{
			name: "request error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("request failed")
			},
		},
		{
			name: "decode error",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("not-json")),
					Header:     make(http.Header),
				}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), session.CtxSourceArg, "alienvault")
			multiRateLimiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
				Key:         "alienvault",
				IsUnlimited: true,
				MaxCount:    math.MaxUint32,
				Duration:    time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer multiRateLimiter.Stop()

			src := &Source{}
			sess := &session.Session{
				Client:           &http.Client{Transport: test.transport},
				MultiRateLimiter: multiRateLimiter,
			}

			results := src.Run(ctx, "example.com", sess)
			result, ok := <-results
			if !ok {
				t.Fatal("expected an error result")
			}
			if result.Type != source.Error || result.Error == nil {
				t.Fatalf("result = %#v, want typed source error", result)
			}
			if result.Source != src.Name() {
				t.Fatalf("source = %q, want %q", result.Source, src.Name())
			}
			if _, ok := <-results; ok {
				t.Fatal("expected exactly one result")
			}
			if stats := src.Statistics(); stats.Errors != 1 {
				t.Fatalf("errors = %d, want 1", stats.Errors)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
