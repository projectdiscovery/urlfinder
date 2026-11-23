package waybackarchive

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

const (
	defaultBaseURL = "https://web.archive.org"

	// cdx lines can exceed bufio.Scanner's 64KB default, which silently truncates results
	initialScanBuffer = 64 * 1024
	maxScanBuffer     = 4 * 1024 * 1024

	// A single unpaged CDX stream takes minutes for large domains and the server
	// cuts it short without an error, so fetch bounded pages chained by resume key.
	pageSize          = 50000
	maxAttempts       = 3
	defaultRetryDelay = 5 * time.Second
)

type Source struct {
	baseURL    string
	retryDelay time.Duration
	timeTaken  time.Duration
	errors     int
	results    int
}

func (s *Source) Run(ctx context.Context, rootUrl string, sess *session.Session) <-chan source.Result {
	results := make(chan source.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		var resumeKey string
		for {
			pageURL := s.pageURL(rootUrl, resumeKey)
			lines, nextKey, err := s.fetchPageWithRetry(ctx, sess, pageURL)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				return
			}

			// emit only after the whole page is read, so a retried page never duplicates output
			for _, line := range lines {
				for _, extractedURL := range sess.Extractor.Extract(line) {
					// fix for triple encoded URL
					extractedURL = strings.TrimPrefix(extractedURL, "25")
					extractedURL = strings.TrimPrefix(extractedURL, "2f")

					results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: pageURL}
					s.results++
				}
			}

			if nextKey == "" {
				return
			}
			resumeKey = nextKey
		}
	}()

	return results
}

func (s *Source) pageURL(rootUrl, resumeKey string) string {
	baseURL := defaultBaseURL
	if s.baseURL != "" {
		baseURL = s.baseURL
	}
	query := url.Values{}
	query.Set("url", "*."+rootUrl+"/*")
	query.Set("output", "txt")
	query.Set("fl", "original")
	query.Set("collapse", "urlkey")
	query.Set("limit", strconv.Itoa(pageSize))
	query.Set("showResumeKey", "true")
	if resumeKey != "" {
		query.Set("resumeKey", resumeKey)
	}
	return baseURL + "/cdx/search/cdx?" + query.Encode()
}

func (s *Source) fetchPageWithRetry(ctx context.Context, sess *session.Session, pageURL string) ([]string, string, error) {
	retryDelay := defaultRetryDelay
	if s.retryDelay > 0 {
		retryDelay = s.retryDelay
	}

	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var lines []string
		var nextKey string
		if lines, nextKey, err = fetchPage(ctx, sess, pageURL); err == nil {
			return lines, nextKey, nil
		}
		if attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(retryDelay * time.Duration(attempt)):
		}
	}
	return nil, "", fmt.Errorf("wayback page failed after %d attempts: %w", maxAttempts, err)
}

// fetchPage returns the URLs of one CDX page and the resume key for the next one,
// which the server sends after a blank line and omits on the last page.
func fetchPage(ctx context.Context, sess *session.Session, pageURL string) ([]string, string, error) {
	resp, err := sess.SimpleGet(ctx, pageURL)
	if err != nil {
		sess.DiscardHTTPResponse(resp)
		return nil, "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var lines []string
	var nextKey string
	afterBlank := false
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, initialScanBuffer), maxScanBuffer)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			afterBlank = true
		case afterBlank:
			nextKey = line
		default:
			line, _ = url.QueryUnescape(line)
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	return lines, nextKey, nil
}

func (s *Source) Name() string {
	return "waybackarchive"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
