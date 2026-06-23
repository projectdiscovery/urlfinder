package urlscan

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/urlfinder/pkg/extractor"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

const searchPath = "/api/v1/search/"

func TestBuildSearchURL(t *testing.T) {
	src := &Source{
		searchURL: "http://127.0.0.1:3000" + searchPath,
	}

	const rootURL = "example.com"
	searchURL, err := src.buildSearchURL(rootURL, "123,abc")
	if err != nil {
		t.Fatalf("buildSearchURL returned an unexpected error: %v", err)
	}

	parsedURL, err := neturl.Parse(searchURL)
	if err != nil {
		t.Fatalf("failed to parse generated search URL: %v", err)
	}

	if parsedURL.Host != "127.0.0.1:3000" {
		t.Fatalf("expected generated URL host %q, got %q", "127.0.0.1:3000", parsedURL.Host)
	}

	if parsedURL.Path != searchPath {
		t.Fatalf("expected generated URL path %q, got %q", searchPath, parsedURL.Path)
	}

	query := parsedURL.Query()
	expectedQuery := "domain:" + rootURL
	if query.Get("q") != expectedQuery {
		t.Fatalf("expected q query parameter %q, got %q", expectedQuery, query.Get("q"))
	}

	if query.Get("size") != "10000" {
		t.Fatalf("expected size query parameter %q, got %q", "10000", query.Get("size"))
	}

	if query.Get("search_after") != "123,abc" {
		t.Fatalf("expected '123,abc' in search_after query parameter, got %q", query.Get("search_after"))
	}
}

func TestRunValidResponse(t *testing.T) {
	src := &Source{}
	src.AddApiKeys([]string{"test-key"})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != searchPath {
			t.Errorf("expected %q path, got %q path", searchPath, r.URL.Path)
			return
		}
		query := r.URL.Query()
		if query.Get("q") != "domain:example.com" {
			t.Errorf("expected %q query(q), got %q", "domain:example.com", query.Get("q"))
			return
		}
		if query.Get("size") != "10000" {
			t.Errorf("expected %q size, got %q", "10000", query.Get("size"))
			return
		}
		if r.Header.Get("API-Key") != "test-key" {
			t.Errorf("expected %q API Key, got %q", "test-key", r.Header.Get("API-Key"))
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected %q method, got %q", http.MethodGet, r.Method)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"results": [
				{
					"page": {
						"url": "https://blog.example.com/test"
					},
					"sort": [123, "abc"]
				}
			],
			"has_more": false
		}`))
	}))
	defer server.Close()

	src.searchURL = server.URL + searchPath
	ctx := context.WithValue(context.Background(), session.CtxSourceArg, src.Name())
	multiRateLimiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         src.Name(),
		IsUnlimited: true,
		MaxCount:    math.MaxUint32,
		Duration:    time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create a rate limiter: %v", err)
	}
	defer multiRateLimiter.Stop()

	urlExtractor, err := extractor.NewRegexUrlExtractor("example.com")
	if err != nil {
		t.Fatalf("failed to create a URL extractor: %v", err)
	}

	sess := &session.Session{
		Client:           server.Client(),
		Extractor:        urlExtractor,
		MultiRateLimiter: multiRateLimiter,
	}

	resultsChan := src.Run(ctx, "example.com", sess)

	var results []source.Result
	for result := range resultsChan {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Reference == "" {
		t.Fatalf("expected non-empty reference")
	}
	if results[0].Error != nil {
		t.Fatalf("expected nil error, got %v", results[0].Error)
	}
	if results[0].Source != src.Name() {
		t.Fatalf("expected %q source, got %v", src.Name(), results[0].Source)
	}
	if results[0].Value != "https://blog.example.com/test" {
		t.Fatalf("expected %q value, got %v", "https://blog.example.com/test", results[0].Value)
	}

	referenceURL, err := neturl.Parse(results[0].Reference)
	if err != nil {
		t.Fatalf("failed to parse result reference: %v", err)
	}

	if referenceURL.Path != searchPath {
		t.Fatalf("expected reference path %q, got %q", searchPath, referenceURL.Path)
	}

	referenceQuery := referenceURL.Query()
	if referenceQuery.Get("q") != "domain:example.com" {
		t.Fatalf("expected reference q query parameter %q, got %q", "domain:example.com", referenceQuery.Get("q"))
	}

	if referenceQuery.Get("size") != "10000" {
		t.Fatalf("expected reference size query parameter %q, got %q", "10000", referenceQuery.Get("size"))
	}

}

func TestRunPaginatesWithoutAccumulatingSearchAfter(t *testing.T) {
	src := &Source{}
	src.AddApiKeys([]string{"test-key"})

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != searchPath {
			t.Errorf("expected %q path, got %q path", searchPath, r.URL.Path)
			return
		}

		query := r.URL.Query()
		// Regardless of the page, there must never be more than one
		// search_after value: the previous implementation appended a new
		// search_after parameter on every iteration instead of replacing it.
		if got := query["search_after"]; len(got) > 1 {
			t.Errorf("expected at most one search_after value, got %d: %v", len(got), got)
			return
		}

		switch atomic.AddInt32(&requests, 1) {
		case 1:
			if query.Get("search_after") != "" {
				t.Errorf("expected empty search_after on first page, got %q", query.Get("search_after"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"results": [
					{"page": {"url": "https://blog.example.com/page1"}, "sort": [123, "abc"]}
				],
				"has_more": true
			}`))
		default:
			if query.Get("search_after") != "123,abc" {
				t.Errorf("expected search_after %q on second page, got %q", "123,abc", query.Get("search_after"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"results": [
					{"page": {"url": "https://blog.example.com/page2"}, "sort": [456, "def"]}
				],
				"has_more": false
			}`))
		}
	}))
	defer server.Close()

	src.searchURL = server.URL + searchPath
	ctx := context.WithValue(context.Background(), session.CtxSourceArg, src.Name())
	multiRateLimiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         src.Name(),
		IsUnlimited: true,
		MaxCount:    math.MaxUint32,
		Duration:    time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create a rate limiter: %v", err)
	}
	defer multiRateLimiter.Stop()

	urlExtractor, err := extractor.NewRegexUrlExtractor("example.com")
	if err != nil {
		t.Fatalf("failed to create a URL extractor: %v", err)
	}

	sess := &session.Session{
		Client:           server.Client(),
		Extractor:        urlExtractor,
		MultiRateLimiter: multiRateLimiter,
	}

	var results []source.Result
	for result := range src.Run(ctx, "example.com", sess) {
		if result.Error != nil {
			t.Fatalf("expected nil error, got %v", result.Error)
		}
		results = append(results, result)
	}

	if atomic.LoadInt32(&requests) != 2 {
		t.Fatalf("expected 2 paginated requests, got %d", atomic.LoadInt32(&requests))
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results across pages, got %d", len(results))
	}

	values := map[string]bool{}
	for _, result := range results {
		values[result.Value] = true
	}
	for _, expected := range []string{"https://blog.example.com/page1", "https://blog.example.com/page2"} {
		if !values[expected] {
			t.Fatalf("expected result value %q to be present, got %v", expected, results)
		}
	}
}
