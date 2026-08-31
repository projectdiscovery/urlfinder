package commoncrawl

import (
	"bufio"
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

const (
	indexURL     = "https://index.commoncrawl.org/collinfo.json"
	maxYearsBack = 5

	// cdx lines can exceed bufio.Scanner's 64KB default, which silently truncates results
	initialScanBuffer = 64 * 1024
	maxScanBuffer     = 4 * 1024 * 1024
)

var year = time.Now().Year()

type indexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

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

		resp, err := sess.SimpleGet(ctx, indexURL)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			sess.DiscardHTTPResponse(resp)
			return
		}

		var indexes []indexResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()

		years := make([]string, 0)
		for i := 0; i < maxYearsBack; i++ {
			years = append(years, strconv.Itoa(year-i))
		}

		searchIndexes := make(map[string]string)
		for _, year := range years {
			for _, index := range indexes {
				if strings.Contains(index.ID, year) {
					if _, ok := searchIndexes[year]; !ok {
						searchIndexes[year] = index.APIURL
						break
					}
				}
			}
		}

		// iterate over years rather than the map so the order is deterministic, and
		// keep going when an index errors out: the commoncrawl index frontend returns
		// intermittent 502/504s, and one bad index shouldn't discard the others.
		for _, year := range years {
			if ctx.Err() != nil {
				break
			}
			if apiURL, ok := searchIndexes[year]; ok {
				s.getURLs(ctx, apiURL, rootUrl, sess, results)
			}
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "commoncrawl"
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

func (s *Source) getURLs(ctx context.Context, searchURL, rootURL string, sess *session.Session, results chan source.Result) {
	var headers = map[string]string{"Host": "index.commoncrawl.org"}
	u, err := url.Parse(searchURL)
	if err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		return
	}
	q := u.Query()
	q.Set("url", "*."+rootURL)
	q.Set("output", "text")
	q.Set("fl", "url")
	u.RawQuery = q.Encode()
	currentSearchURL := u.String()
	resp, err := sess.Get(ctx, currentSearchURL, "", headers)
	if err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		sess.DiscardHTTPResponse(resp)
		return
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, initialScanBuffer), maxScanBuffer)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		line, _ = url.QueryUnescape(line)
		for _, extractedURL := range sess.Extractor.Extract(line) {
			if extractedURL != "" {
				results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: currentSearchURL}
				s.results++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
	}
}
