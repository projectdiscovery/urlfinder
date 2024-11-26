package commoncrawl

import (
	"bufio"
	"context"
	"fmt"
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
			results <- source.Result{Source: s.Name(), Error: err}
			s.errors++
			sess.DiscardHTTPResponse(resp)
			return
		}

		var indexes []indexResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			results <- source.Result{Source: s.Name(), Error: err}
			s.errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

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

		for _, apiURL := range searchIndexes {
			further := s.getURLs(ctx, apiURL, rootUrl, sess, results)
			if !further {
				break
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

func (s *Source) getURLs(ctx context.Context, searchURL, rootURL string, sess *session.Session, results chan source.Result) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			var headers = map[string]string{"Host": "index.commoncrawl.org"}
			currentSearchURL := fmt.Sprintf("%s?url=*.%s", searchURL, rootURL)
			resp, err := sess.Get(ctx, currentSearchURL, "", headers)
			if err != nil {
				results <- source.Result{Source: s.Name(), Error: err}
				s.errors++
				sess.DiscardHTTPResponse(resp)
				return false
			}

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
					if extractedURL != "" {
						results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: currentSearchURL}
						s.results++
					}
				}
			}
			resp.Body.Close()
			return true
		}
	}
}
