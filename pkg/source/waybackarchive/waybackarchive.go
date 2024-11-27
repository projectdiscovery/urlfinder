package waybackarchive

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
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

		searchURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", rootUrl)
		resp, err := sess.SimpleGet(ctx, searchURL)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			sess.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			line, _ = url.QueryUnescape(line)
			for _, extractedURL := range sess.Extractor.Extract(line) {
				// fix for triple encoded URL
				extractedURL = (extractedURL)
				extractedURL = strings.TrimPrefix(extractedURL, "25")
				extractedURL = strings.TrimPrefix(extractedURL, "2f")

				results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: searchURL}
				s.results++
			}

		}
	}()

	return results
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
