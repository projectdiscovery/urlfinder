package agent

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Agent is a struct for running url enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources []source.Source
}

// New creates a new agent for url discovery
func New(sourceNames, excludedSourceNames []string, useAllSources bool) *Agent {
	sources := make(map[string]source.Source, len(AllSources))

	if useAllSources {
		maps.Copy(sources, AllSources)
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				if AllSources[source] == nil {
					gologger.Warning().Msgf("There is no source with the name: %s", source)
				} else {
					sources[source] = AllSources[source]
				}
			}
		} else {
			for _, currentSource := range AllSources {
				if currentSource.IsDefault() {
					sources[currentSource.Name()] = currentSource
				}
			}
		}
	}

	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if len(sources) == 0 {
		gologger.Fatal().Msg("No sources selected for this search")
	}

	gologger.Debug().Msg(fmt.Sprintf("Selected source(s) for this search: %s", strings.Join(maps.Keys(sources), ", ")))

	for _, currentSource := range sources {
		if warning, ok := sourceWarnings.Get((currentSource.Name())); ok {
			gologger.Warning().Msg(warning)
		}
	}

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: maps.Values(sources)}

	return agent
}

// ContainsAny checks if any of the elements in s2 are in s1
func ContainsAny[T comparable](s1, s2 []T) bool {
	for _, a := range s2 {
		return slices.Contains(s1, a)
	}
	return false
}

type CustomRateLimit struct {
	Custom mapsutil.SyncLockMap[string, uint]
}

type EnumerationOptions struct {
	customRateLimiter *CustomRateLimit
}

type EnumerateOption func(opts *EnumerationOptions)

func WithCustomRateLimit(crl *CustomRateLimit) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.customRateLimiter = crl
	}
}

// EnumerateQueries wraps EnumerateQueriesWithCtx with an empty context
func (a *Agent) EnumerateQueries(query string, proxy string, rateLimit int, timeout int, maxEnumTime time.Duration, options ...EnumerateOption) chan source.Result {
	return a.EnumerateUrlsWithCtx(context.Background(), query, proxy, rateLimit, timeout, maxEnumTime, options...)
}

// EnumerateUrlsWithCtx enumerates all the urls for a given query
func (a *Agent) EnumerateUrlsWithCtx(ctx context.Context, query string, proxy string, rateLimit int, timeout int, maxEnumTime time.Duration, options ...EnumerateOption) chan source.Result {
	results := make(chan source.Result)

	go func() {
		defer close(results)

		var enumerateOptions EnumerationOptions
		for _, enumerateOption := range options {
			enumerateOption(&enumerateOptions)
		}

		multiRateLimiter, err := a.buildMultiRateLimiter(ctx, rateLimit, enumerateOptions.customRateLimiter)
		if err != nil {
			results <- source.Result{
				Type: source.Error, Error: fmt.Errorf("could not init multi rate limiter for %s: %s", query, err),
			}
			return
		}
		sess, err := session.NewSession(query, proxy, multiRateLimiter, timeout)
		if err != nil {
			results <- source.Result{
				Type: source.Error, Error: fmt.Errorf("could not init passive session for %s: %s", query, err),
			}
			return
		}
		defer sess.Close()

		ctx, cancel := context.WithTimeout(ctx, maxEnumTime)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target url
		for _, runner := range a.sources {
			wg.Add(1)
			go func(source source.Source) {
				ctxWithValue := context.WithValue(ctx, session.CtxSourceArg, source.Name())
				for resp := range source.Run(ctxWithValue, query, sess) {
					results <- resp
				}
				wg.Done()
			}(runner)
		}
		wg.Wait()
		cancel()
	}()
	return results
}

func (a *Agent) buildMultiRateLimiter(ctx context.Context, globalRateLimit int, rateLimit *CustomRateLimit) (*ratelimit.MultiLimiter, error) {
	var multiRateLimiter *ratelimit.MultiLimiter
	var err error
	for _, source := range a.sources {
		var rl uint
		if sourceRateLimit, ok := rateLimit.Custom.Get((source.Name())); ok {
			rl = sourceRateLimitOrDefault(uint(globalRateLimit), sourceRateLimit)
		}

		if rl > 0 {
			multiRateLimiter, err = addRateLimiter(ctx, multiRateLimiter, source.Name(), rl, time.Second)
		} else {
			multiRateLimiter, err = addRateLimiter(ctx, multiRateLimiter, source.Name(), math.MaxUint32, time.Millisecond)
		}

		if err != nil {
			break
		}
	}
	return multiRateLimiter, err
}

func sourceRateLimitOrDefault(defaultRateLimit uint, sourceRateLimit uint) uint {
	if sourceRateLimit > 0 {
		return sourceRateLimit
	}
	return defaultRateLimit
}

func addRateLimiter(ctx context.Context, multiRateLimiter *ratelimit.MultiLimiter, key string, maxCount uint, duration time.Duration) (*ratelimit.MultiLimiter, error) {
	if multiRateLimiter == nil {
		mrl, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{
			Key:         key,
			IsUnlimited: maxCount == math.MaxUint32,
			MaxCount:    maxCount,
			Duration:    duration,
		})
		return mrl, err
	}
	err := multiRateLimiter.Add(&ratelimit.Options{
		Key:         key,
		IsUnlimited: maxCount == math.MaxUint32,
		MaxCount:    maxCount,
		Duration:    duration,
	})
	return multiRateLimiter, err
}

func (a *Agent) GetStatistics() map[string]source.Statistics {
	stats := make(map[string]source.Statistics)
	sort.Slice(a.sources, func(i, j int) bool {
		return a.sources[i].Name() > a.sources[j].Name()
	})

	for _, source := range a.sources {
		stats[source.Name()] = source.Statistics()
	}
	return stats
}
