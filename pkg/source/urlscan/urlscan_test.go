package urlscan

import (
	neturl "net/url"
	"testing"
)

func TestBuildSearchURL(t *testing.T) {
	src := &Source{
		searchURL: "http://127.0.0.1:3000/api/v1/search/",
	}

	const rootURL = "example.com"
	searchURL, err := src.buildSearchURL(rootURL, "")
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

	if parsedURL.Path != "/api/v1/search/" {
		t.Fatalf("expected generated URL path %q, got %q", "/api/v1/search/", parsedURL.Path)
	}

	query := parsedURL.Query()
	expectedQuery := "domain:" + rootURL
	if query.Get("q") != expectedQuery {
		t.Fatalf("expected q query parameter %q, got %q", expectedQuery, query.Get("q"))
	}

	if query.Get("size") != "10000" {
		t.Fatalf("expected size query parameter %q, got %q", "10000", query.Get("size"))
	}

	if query.Get("search_after") != "" {
		t.Fatalf("expected empty search_after query parameter, got %q", query.Get("search_after"))
	}
}