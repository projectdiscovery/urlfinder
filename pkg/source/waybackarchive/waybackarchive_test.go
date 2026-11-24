package waybackarchive

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/urlfinder/pkg/extractor"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

func TestRunFollowsResumeKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("showResumeKey") != "true" || query.Get("limit") == "" || query.Get("output") != "json" {
			t.Errorf("expected paged query, got %q", r.URL.RawQuery)
		}
		switch query.Get("resumeKey") {
		case "":
			_, _ = fmt.Fprint(w, cdxPage("key-1", "https://example.com/a", "https://example.com/b"))
		case "key-1":
			_, _ = fmt.Fprint(w, cdxPage("", "https://example.com/c"))
		default:
			t.Errorf("unexpected resumeKey %q", query.Get("resumeKey"))
		}
	}))
	defer server.Close()

	urls, errs := run(t, server)
	assertURLs(t, urls, "https://example.com/a", "https://example.com/b", "https://example.com/c")
	if errs != 0 {
		t.Fatalf("errors = %d, want 0", errs)
	}
}

func TestRunRetriesFailedPageWithoutDuplicates(t *testing.T) {
	var secondPageCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("resumeKey") {
		case "":
			_, _ = fmt.Fprint(w, cdxPage("key-1", "https://example.com/a"))
		case "key-1":
			if secondPageCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = fmt.Fprint(w, cdxPage("", "https://example.com/b"))
		}
	}))
	defer server.Close()

	urls, errs := run(t, server)
	assertURLs(t, urls, "https://example.com/a", "https://example.com/b")
	if errs != 0 {
		t.Fatalf("errors = %d, want 0", errs)
	}
	if got := secondPageCalls.Load(); got != 2 {
		t.Fatalf("second page requests = %d, want 2", got)
	}
}

func TestRunReportsPageThatKeepsFailing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resumeKey") == "" {
			_, _ = fmt.Fprint(w, cdxPage("key-1", "https://example.com/a"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	urls, errs := run(t, server)
	assertURLs(t, urls, "https://example.com/a")
	if errs != 1 {
		t.Fatalf("errors = %d, want 1", errs)
	}
}

func run(t *testing.T, server *httptest.Server) (urls []string, errs int) {
	t.Helper()
	src := &Source{baseURL: server.URL, retryDelay: time.Millisecond}
	ctx := context.WithValue(context.Background(), session.CtxSourceArg, src.Name())
	limiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
		Key:         src.Name(),
		IsUnlimited: true,
		MaxCount:    math.MaxUint32,
		Duration:    time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create a rate limiter: %v", err)
	}
	t.Cleanup(func() { limiter.Stop() })
	urlExtractor, err := extractor.NewRegexUrlExtractor("example.com")
	if err != nil {
		t.Fatalf("failed to create a URL extractor: %v", err)
	}
	sess := &session.Session{Client: server.Client(), Extractor: urlExtractor, MultiRateLimiter: limiter}

	for result := range src.Run(ctx, "example.com", sess) {
		switch result.Type {
		case source.Url:
			urls = append(urls, result.Value)
		case source.Error:
			errs++
		}
	}
	if stats := src.Statistics(); stats.Results != len(urls) || stats.Errors != errs {
		t.Fatalf("statistics = %+v, want %d results and %d errors", stats, len(urls), errs)
	}
	return urls, errs
}

func assertURLs(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("urls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("urls = %v, want %v", got, want)
		}
	}
}

func TestRunRetriesCutPage(t *testing.T) {
	for name, cut := range map[string]string{
		"mid rows":        "[[\"original\"],\n[\"https://example.com/a\"],\n",
		"after separator": "[[\"original\"],\n[\"https://example.com/a\"],\n[],\n",
		"html error page": "<html><body>We apologize for the inconvenience.</body></html>",
	} {
		t.Run(name, func(t *testing.T) { testRunRetriesCutPage(t, cut) })
	}
}

func testRunRetriesCutPage(t *testing.T, cut string) {
	var firstPageCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("resumeKey") {
		case "":
			if firstPageCalls.Add(1) == 1 {
				_, _ = fmt.Fprint(w, cut)
				return
			}
			_, _ = fmt.Fprint(w, cdxPage("key-1", "https://example.com/a"))
		case "key-1":
			_, _ = fmt.Fprint(w, cdxPage("", "https://example.com/b"))
		}
	}))
	defer server.Close()

	urls, errs := run(t, server)
	assertURLs(t, urls, "https://example.com/a", "https://example.com/b")
	if errs != 0 {
		t.Fatalf("errors = %d, want 0", errs)
	}
}

func TestRunStopsOnRepeatedResumeKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, cdxPage("key-1", "https://example.com/a"))
	}))
	defer server.Close()

	urls, errs := run(t, server)
	assertURLs(t, urls, "https://example.com/a")
	if errs != 1 {
		t.Fatalf("errors = %d, want 1", errs)
	}
}

// cdxPage renders a CDX JSON page: a header row, one row per URL, and on every
// page but the last an empty row followed by the resume key.
func cdxPage(resumeKey string, urls ...string) string {
	rows := [][]string{{"original"}}
	for _, u := range urls {
		rows = append(rows, []string{u})
	}
	if resumeKey != "" {
		rows = append(rows, []string{}, []string{resumeKey})
	}
	body, _ := json.Marshal(rows)
	return string(body)
}
