package urlscan

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
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
					"sort": [123]
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

func TestRunRejectsInvalidPagination(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		expectedError string
		expectedURLs  int
	}{
		{
			name:          "has more without results",
			response:      `{"results":[],"has_more":true}`,
			expectedError: "has_more without results",
		},
		{
			name:          "missing sort",
			response:      `{"results":[{"page":{"url":"https://blog.example.com/test"}}],"has_more":true}`,
			expectedError: "expected at least 2 values",
			expectedURLs:  1,
		},
		{
			name:          "missing second sort value",
			response:      `{"results":[{"page":{"url":"https://blog.example.com/test"},"sort":[123]}],"has_more":true}`,
			expectedError: "expected at least 2 values",
			expectedURLs:  1,
		},
		{
			name:          "invalid first sort value",
			response:      `{"results":[{"page":{"url":"https://blog.example.com/test"},"sort":["123","cursor"]}],"has_more":true}`,
			expectedError: "first value must be a number",
			expectedURLs:  1,
		},
		{
			name:          "fractional first sort value",
			response:      `{"results":[{"page":{"url":"https://blog.example.com/test"},"sort":[123.5,"cursor"]}],"has_more":true}`,
			expectedError: "first value must be a finite integer",
			expectedURLs:  1,
		},
		{
			name:          "invalid second sort value",
			response:      `{"results":[{"page":{"url":"https://blog.example.com/test"},"sort":[123,456]}],"has_more":true}`,
			expectedError: "second value must be a string",
			expectedURLs:  1,
		},
		{
			name:          "empty second sort value",
			response:      `{"results":[{"page":{"url":"https://blog.example.com/test"},"sort":[123,""]}],"has_more":true}`,
			expectedError: "second value must not be empty",
			expectedURLs:  1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()

			src := &Source{searchURL: server.URL + searchPath}
			src.AddApiKeys([]string{"test-key"})
			sess := newTestSession(t, server.Client())

			var urls, errors int
			for result := range src.Run(context.WithValue(context.Background(), session.CtxSourceArg, src.Name()), "example.com", sess) {
				switch result.Type {
				case source.Url:
					urls++
				case source.Error:
					errors++
					if result.Error == nil || !strings.Contains(result.Error.Error(), test.expectedError) {
						t.Fatalf("error = %v, want error containing %q", result.Error, test.expectedError)
					}
				default:
					t.Fatalf("unexpected result type %d", result.Type)
				}
			}

			if requests.Load() != 1 {
				t.Fatalf("requests = %d, want 1", requests.Load())
			}
			if urls != test.expectedURLs {
				t.Fatalf("URL results = %d, want %d", urls, test.expectedURLs)
			}
			if errors != 1 {
				t.Fatalf("error results = %d, want 1", errors)
			}
			stats := src.Statistics()
			if stats.Results != test.expectedURLs || stats.Errors != 1 {
				t.Fatalf("statistics = {Results:%d Errors:%d}, want {Results:%d Errors:1}", stats.Results, stats.Errors, test.expectedURLs)
			}
		})
	}
}

func TestRunBuildSearchURLErrorIsTyped(t *testing.T) {
	src := &Source{searchURL: "%"}
	src.AddApiKeys([]string{"test-key"})

	results := src.Run(context.WithValue(context.Background(), session.CtxSourceArg, src.Name()), "example.com", nil)
	result, ok := <-results
	if !ok {
		t.Fatal("expected an error result")
	}
	if result.Type != source.Error || result.Error == nil {
		t.Fatalf("result = %#v, want typed source error", result)
	}
	if _, ok := <-results; ok {
		t.Fatal("expected exactly one result")
	}
	if stats := src.Statistics(); stats.Errors != 1 {
		t.Fatalf("errors = %d, want 1", stats.Errors)
	}
}

func TestRunResponseErrorsAreTyped(t *testing.T) {
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
			name: "unexpected status",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
					Header:     make(http.Header),
				}, nil
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
			src := &Source{searchURL: "https://example.invalid" + searchPath}
			src.AddApiKeys([]string{"test-key"})
			sess := newTestSession(t, &http.Client{Transport: test.transport})

			results := src.Run(context.WithValue(context.Background(), session.CtxSourceArg, src.Name()), "example.com", sess)
			result, ok := <-results
			if !ok {
				t.Fatal("expected an error result")
			}
			if result.Type != source.Error || result.Error == nil {
				t.Fatalf("result = %#v, want typed source error", result)
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

func TestBuildSearchAfter(t *testing.T) {
	tests := []struct {
		name      string
		sort      []interface{}
		expected  string
		shouldErr bool
	}{
		{
			name:     "valid values",
			sort:     []interface{}{float64(123), "abc"},
			expected: "123,abc",
		},
		{
			name:     "zero numeric value",
			sort:     []interface{}{float64(0), "abc"},
			expected: "0,abc",
		},
		{
			name:     "millisecond timestamp",
			sort:     []interface{}{float64(1788196934056), "cursor"},
			expected: "1788196934056,cursor",
		},
		{
			name:      "missing sort values",
			sort:      nil,
			shouldErr: true,
		},
		{
			name:      "missing second value",
			sort:      []interface{}{float64(123)},
			shouldErr: true,
		},
		{
			name:      "invalid first value type",
			sort:      []interface{}{"123", "abc"},
			shouldErr: true,
		},
		{
			name:      "invalid second value type",
			sort:      []interface{}{float64(123), 456},
			shouldErr: true,
		},
		{
			name:      "empty second value",
			sort:      []interface{}{float64(123), ""},
			shouldErr: true,
		},
		{
			name:      "fractional first value",
			sort:      []interface{}{123.5, "abc"},
			shouldErr: true,
		},
		{
			name:      "positive infinite first value",
			sort:      []interface{}{math.Inf(1), "abc"},
			shouldErr: true,
		},
		{
			name:      "negative infinite first value",
			sort:      []interface{}{math.Inf(-1), "abc"},
			shouldErr: true,
		},
		{
			name:      "NaN first value",
			sort:      []interface{}{math.NaN(), "abc"},
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := buildSearchAfter(Result{Sort: test.sort})

			if test.shouldErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}

			if value != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, value)
			}
		})
	}
}

func newTestSession(t *testing.T, client *http.Client) *session.Session {
	t.Helper()

	ctx := context.WithValue(context.Background(), session.CtxSourceArg, "urlscan")
	multiRateLimiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         "urlscan",
		IsUnlimited: true,
		MaxCount:    math.MaxUint32,
		Duration:    time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create a rate limiter: %v", err)
	}
	t.Cleanup(func() {
		multiRateLimiter.Stop()
	})

	urlExtractor, err := extractor.NewRegexUrlExtractor("example.com")
	if err != nil {
		t.Fatalf("failed to create a URL extractor: %v", err)
	}

	return &session.Session{
		Client:           client,
		Extractor:        urlExtractor,
		MultiRateLimiter: multiRateLimiter,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
