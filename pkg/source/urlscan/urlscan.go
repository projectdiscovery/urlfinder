package urlscan

import (
	"context"
	"fmt"
	"net/http"
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

		if parsedRootUrl, err := urlutil.Parse(rootUrl); err == nil {
			rootUrl = parsedRootUrl.Hostname()
		}

		randomApiKey := utils.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		var searchAfter string
		hasMore := true
		headers := map[string]string{"API-Key": randomApiKey}
		apiURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", rootUrl)
		for hasMore {
			if searchAfter != "" {
				apiURL = fmt.Sprintf("%s&search_after=%s", apiURL, searchAfter)
			}

			resp, err := sess.Get(ctx, apiURL, "", headers)
			if err != nil {
				results <- source.Result{Source: s.Name(), Error: err}
				s.errors++
				sess.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				results <- source.Result{Source: s.Name(), Error: err}
				s.errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusTooManyRequests {
				results <- source.Result{Source: s.Name(), Error: fmt.Errorf("urlscan rate limited")}
				s.errors++
				return
			}

			for _, url := range data.Results {
				for _, extractedURL := range sess.Extractor.Extract(url.Page.Url) {
					results <- source.Result{Source: s.Name(), Value: extractedURL, Reference: apiURL}
					s.results++
				}
			}
			if len(data.Results) > 0 {
				lastResult := data.Results[len(data.Results)-1]
				if len(lastResult.Sort) > 0 {
					sort1 := strconv.Itoa(int(lastResult.Sort[0].(float64)))
					sort2, _ := lastResult.Sort[1].(string)

					searchAfter = fmt.Sprintf("%s,%s", sort1, sort2)
				}
			}
			hasMore = data.HasMore
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
