package waybackarchive

import (
	"context"
	"encoding/json"
	"errors"
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
			if nextKey != "" && nextKey == resumeKey {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: fmt.Errorf("wayback returned the same resume key %q", nextKey)}
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
	query.Set("output", "json")
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
// which the server sends after an empty row and omits on the last page.
func fetchPage(ctx context.Context, sess *session.Session, pageURL string) ([]string, string, error) {
	resp, err := sess.SimpleGet(ctx, pageURL)
	if err != nil {
		sess.DiscardHTTPResponse(resp)
		return nil, "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// JSON rather than text output, because text has no end marker and a page cut
	// between rows reads as a complete last page; a cut JSON array fails to decode
	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, "", fmt.Errorf("could not decode wayback page: %w", err)
	}
	if len(rows) == 0 {
		return nil, "", nil
	}

	// rows[0] is the field header; a non-final page ends with an empty row and the key
	rows = rows[1:]
	var nextKey string
	if n := len(rows); n >= 2 && len(rows[n-2]) == 0 {
		if len(rows[n-1]) != 1 {
			return nil, "", errors.New("wayback page has a malformed resume key")
		}
		nextKey = rows[n-1][0]
		rows = rows[:n-2]
	}

	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		line, _ := url.QueryUnescape(row[0])
		lines = append(lines, line)
	}
	return lines, nextKey, nil
}

func (s *Source) Name() string {
	return "waybackarchive"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) KeyRequirement() source.KeyRequirement {
	return source.NoKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == source.RequiredKey
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
