package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
	"github.com/projectdiscovery/urlfinder/pkg/utils"
)

type response struct {
	DetectedUrls []struct {
		URL string `json:"url"`
	} `json:"detected_urls"`
	Subdomains     []string        `json:"subdomains"`
	UndetectedUrls [][]interface{} `json:"undetected_urls"`
}

type Source struct {
	apiKeys   []string
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

		randomApiKey := utils.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		searchURL := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", randomApiKey, rootUrl)
		resp, err := sess.SimpleGet(ctx, searchURL)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			sess.DiscardHTTPResponse(resp)
			return
		}
		defer resp.Body.Close()

		var data response
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return
		}

		for _, detectedUrl := range data.DetectedUrls {
			for _, extractedURL := range sess.Extractor.Extract(detectedUrl.URL) {
				results <- source.Result{Source: s.Name(), Value: extractedURL}
				s.results++
			}
		}
		for _, subdomain := range data.Subdomains {
			for _, extractedURL := range sess.Extractor.Extract(subdomain) {
				results <- source.Result{Source: s.Name(), Value: extractedURL}
				s.results++
			}
		}

		for _, undetectedUrl := range data.UndetectedUrls {
			if len(undetectedUrl) > 0 {
				if urlString, ok := undetectedUrl[0].(string); ok {
					for _, extractedURL := range sess.Extractor.Extract(urlString) {
						results <- source.Result{Source: s.Name(), Value: extractedURL}
						s.results++
					}
				}
			}
		}

	}()
	return results
}

func (s *Source) Name() string {
	return "virustotal"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
