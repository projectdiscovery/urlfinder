package runner

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/urlfinder/pkg/agent"
	"github.com/projectdiscovery/urlfinder/pkg/resolve"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

const maxNumCount = 2

var replacer = strings.NewReplacer(
	"*.", "",
)

// EnumerateSingleQuery wraps EnumerateSingleQuerynWithCtx with an empty context
func (r *Runner) EnumerateSingleQuery(query string, writers []io.Writer) error {
	return r.EnumerateSingleQueryWithCtx(context.Background(), query, writers)
}

// EnumerateSingleQueryWithCtx performs url enumeration against a single query
func (r *Runner) EnumerateSingleQueryWithCtx(ctx context.Context, query string, writers []io.Writer) error {
	gologger.Info().Msgf("Enumerating urls for %s\n", query)

	// Run the url enumeration
	now := time.Now()
	results := r.agent.EnumerateUrlsWithCtx(ctx, query, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute, agent.WithCustomRateLimit(r.rateLimit))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate urls out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	// Process the results in a separate goroutine
	go func() {
		for result := range results {
			switch result.Type {
			case source.Error:
				gologger.Warning().Msgf("Could not run source %s: %s\n", result.Source, result.Error)
			case source.Url:

				url := replacer.Replace(result.Value)

				if matchUrl := r.filterAndMatchUrl(url); matchUrl {
					if _, ok := uniqueMap[url]; !ok {
						sourceMap[url] = make(map[string]struct{})
					}

					// Log the verbose message about the found url per source
					if _, ok := sourceMap[url][result.Source]; !ok {
						gologger.Verbose().Label(result.Source).Msg(url)
					}

					sourceMap[url][result.Source] = struct{}{}

					// Check if the url is a duplicate. If not,
					// send the url for resolution.
					if _, ok := uniqueMap[url]; ok {
						continue
					}

					hostEntry := resolve.HostEntry{Query: query, Host: url, Source: result.Source}
					uniqueMap[url] = hostEntry
				}
			}
		}
		wg.Done()
	}()
	wg.Wait()

	outputWriter := NewOutputWriter(r.options.JSON)
	// Now output all results in output writers
	var err error
	for _, writer := range writers {
		if r.options.CaptureSources {
			err = outputWriter.WriteSourceHost(query, sourceMap, writer)
		} else {
			err = outputWriter.WriteHost(query, uniqueMap, writer)
		}

		if err != nil {
			gologger.Error().Msgf("Could not write results for %s: %s\n", query, err)
			return err
		}
	}

	// Show found url count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	numberOfUrls := len(uniqueMap)

	if r.options.ResultCallback != nil {
		for _, v := range uniqueMap {
			r.options.ResultCallback(&v)
		}
	}
	gologger.Info().Msgf("Found %d urls for %s in %s\n", numberOfUrls, query, duration)

	if r.options.Statistics {
		gologger.Info().Msgf("Printing source statistics for %s", query)
		printStatistics(r.agent.GetStatistics())
	}

	return nil
}

func (r *Runner) filterAndMatchUrl(url string) bool {
	if r.options.filterRegexes != nil {
		for _, filter := range r.options.filterRegexes {
			if m := filter.MatchString(url); m {
				return false
			}
		}
	}
	if r.options.matchRegexes != nil {
		for _, match := range r.options.matchRegexes {
			if m := match.MatchString(url); m {
				return true
			}
		}
		return false
	}
	return true
}
