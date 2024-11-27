package alienvault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
	urlutil "github.com/projectdiscovery/utils/url"
)

type alienvaultResponse struct {
	URLList []url `json:"url_list"`
	HasNext bool  `json:"has_next"`
}

type url struct {
	URL string `json:"url"`
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

		if parsedRootUrl, err := urlutil.Parse(rootUrl); err == nil {
			rootUrl = parsedRootUrl.Hostname()
		}

		page := 1
		for {
			apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?page=%d", rootUrl, page)
			resp, err := sess.SimpleGet(ctx, apiURL)
			if err != nil && resp == nil {
				results <- source.Result{Source: s.Name(), Error: err}
				sess.DiscardHTTPResponse(resp)
				return
			}

			var response alienvaultResponse
			// Get the response body and decode
			err = json.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- source.Result{Source: s.Name(), Error: err}
				s.errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			for _, record := range response.URLList {
				for _, extractedURL := range sess.Extractor.Extract(record.URL) {
					results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: apiURL}
					s.results++
				}
			}

			if !response.HasNext {
				break
			}
			page++
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "alienvault"
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
