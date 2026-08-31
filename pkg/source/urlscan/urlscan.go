package urlscan

import (
	"context"
	"fmt"
	"math"
	"net/http"
	neturl "net/url"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
	"github.com/projectdiscovery/urlfinder/pkg/utils"
	urlutil "github.com/projectdiscovery/utils/url"
)

type response struct {
	Results []Result `json:"results"`
	HasMore bool     `json:"has_more"`
}

type Result struct {
	Page Page          `json:"page"`
	Sort []interface{} `json:"sort"`
}

type Page struct {
	Url string `json:"url"`
}

type Source struct {
	searchURL string

	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
}

const defaultSearchURL = "https://urlscan.io/api/v1/search/"

func (s *Source) buildSearchURL(rootURL, searchAfter string) (string, error) {
	baseURL := defaultSearchURL
	if s.searchURL != "" {
		baseURL = s.searchURL
	}

	parsedURL, err := neturl.Parse(baseURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Set("q", "domain:"+rootURL)
	query.Set("size", "10000")

	if searchAfter != "" {
		query.Set("search_after", searchAfter)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func buildSearchAfter(result Result) (string, error) {
	if len(result.Sort) < 2 {
		return "", fmt.Errorf("invalid urlscan sort: expected at least 2 values, got %d", len(result.Sort))
	}

	firstValue, ok := result.Sort[0].(float64)
	if !ok {
		return "", fmt.Errorf("invalid urlscan sort: first value must be a number")
	}

	if math.IsNaN(firstValue) || math.IsInf(firstValue, 0) || firstValue != math.Trunc(firstValue) {
		return "", fmt.Errorf("invalid urlscan sort: first value must be a finite integer")
	}

	secondValue, ok := result.Sort[1].(string)
	if !ok {
		return "", fmt.Errorf("invalid urlscan sort: second value must be a string")
	}

	if secondValue == "" {
		return "", fmt.Errorf("invalid urlscan sort: second value must not be empty")
	}

	formattedFirstValue := strconv.FormatFloat(firstValue, 'f', -1, 64)
	return fmt.Sprintf("%s,%s", formattedFirstValue, secondValue), nil
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

		randomApiKey := utils.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		var searchAfter string
		headers := map[string]string{"API-Key": randomApiKey}
		for {
			apiURL, err := s.buildSearchURL(rootUrl, searchAfter)
			if err != nil {
				results <- source.Result{
					Source: s.Name(),
					Type:   source.Error,
					Error:  err,
				}
				s.errors++
				return
			}

			resp, err := sess.Get(ctx, apiURL, "", headers)
			if err != nil {
				results <- source.Result{Source: s.Name(), Error: err, Type: source.Error}
				s.errors++
				sess.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				results <- source.Result{Source: s.Name(), Error: err, Type: source.Error}
				s.errors++
				_ = resp.Body.Close()
				return
			}
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusTooManyRequests {
				results <- source.Result{
					Source: s.Name(),
					Error:  fmt.Errorf("urlscan rate limited"),
					Type:   source.Error,
				}
				s.errors++
				return
			}

			for _, url := range data.Results {
				for _, extractedURL := range sess.Extractor.Extract(url.Page.Url) {
					results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: apiURL}
					s.results++
				}
			}
			if !data.HasMore {
				break
			}

			if len(data.Results) == 0 {
				results <- source.Result{
					Source: s.Name(),
					Type:   source.Error,
					Error:  fmt.Errorf("urlscan returned has_more without results"),
				}
				s.errors++
				return
			}

			lastResult := data.Results[len(data.Results)-1]

			searchAfter, err = buildSearchAfter(lastResult)
			if err != nil {
				results <- source.Result{
					Source: s.Name(),
					Type:   source.Error,
					Error:  err,
				}
				s.errors++
				return
			}
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "urlscan"
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
