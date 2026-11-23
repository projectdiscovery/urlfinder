package agent

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

func TestBuildMultiRateLimiter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		global int
		custom *CustomRateLimit
		want   uint
	}{
		{name: "global without custom options", global: 1, want: 1},
		{name: "global with empty overrides", global: 1, custom: &CustomRateLimit{}, want: 1},
		{name: "global with unrelated override", global: 1, custom: testRateLimit("urlscan", 5), want: 1},
		{name: "source override", global: 1, custom: testRateLimit("alienvault", 5), want: 5},
		{name: "zero override uses global", global: 1, custom: testRateLimit("alienvault", 0), want: 1},
		{name: "unlimited without custom options", want: math.MaxUint32},
		{name: "unlimited with empty overrides", custom: &CustomRateLimit{}, want: math.MaxUint32},
		{name: "override without global", custom: testRateLimit("alienvault", 5), want: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("building rate limiter panicked: %v", r)
				}
			}()
			a := &Agent{sources: []source.Source{AllSources["alienvault"]}}
			limiter, err := a.buildMultiRateLimiter(context.Background(), tc.global, tc.custom)
			if err != nil {
				t.Fatal(err)
			}
			defer limiter.Stop()
			got, err := limiter.GetLimit("alienvault")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("rate limit = %d, want %d", got, tc.want)
			}
		})
	}
}

func testRateLimit(name string, limit uint) *CustomRateLimit {
	custom := &CustomRateLimit{}
	custom.Custom.Map = map[string]uint{name: limit}
	return custom
}

// stubSource is an in-process source. It never dials out.
type stubSource struct {
	name string
	run  func(ctx context.Context, query string, sess *session.Session) <-chan source.Result
}

func (s *stubSource) Run(ctx context.Context, query string, sess *session.Session) <-chan source.Result {
	return s.run(ctx, query, sess)
}

func (s *stubSource) Name() string { return s.name }

func (s *stubSource) IsDefault() bool { return false }

func (s *stubSource) NeedsKey() bool { return false }

func (s *stubSource) AddApiKeys([]string) {}

func (s *stubSource) Statistics() source.Statistics { return source.Statistics{} }

func emptyRateLimit() *CustomRateLimit {
	return &CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
	}
}

func collect(ch <-chan source.Result) []source.Result {
	var out []source.Result
	for result := range ch {
		out = append(out, result)
	}
	return out
}

func hasMaxTimeNotice(results []source.Result) bool {
	for _, result := range results {
		if result.Type == source.Error && errors.Is(result.Error, ErrMaxTimeReached) {
			return true
		}
	}
	return false
}

// blockingSource waits out the enumeration deadline, then yields one URL.
func blockingSource() source.Source {
	return &stubSource{
		name: "slow",
		run: func(ctx context.Context, _ string, _ *session.Session) <-chan source.Result {
			out := make(chan source.Result)
			go func() {
				defer close(out)
				<-ctx.Done()
				out <- source.Result{Type: source.Url, Source: "slow", Value: "https://example.com/partial"}
			}()
			return out
		},
	}
}

func TestEnumerateUrlsWithCtxWarnsWhenMaxTimeExceeded(t *testing.T) {
	agent := &Agent{sources: []source.Source{blockingSource()}}
	results := collect(agent.EnumerateUrlsWithCtx(context.Background(), "example.com", "", 0, 1, 50*time.Millisecond, WithCustomRateLimit(emptyRateLimit())))

	if !hasMaxTimeNotice(results) {
		t.Fatalf("results = %#v, want a max-time partial-results error", results)
	}
	urls := 0
	for _, result := range results {
		if result.Type == source.Url {
			urls++
		}
	}
	if urls != 1 {
		t.Fatalf("urls = %d, want the partial result kept", urls)
	}
}

func TestEnumerateUrlsWithCtxNoNoticeWhenSourcesFinish(t *testing.T) {
	src := &stubSource{
		name: "fast",
		run: func(context.Context, string, *session.Session) <-chan source.Result {
			out := make(chan source.Result, 1)
			out <- source.Result{Type: source.Url, Source: "fast", Value: "https://example.com/ok"}
			close(out)
			return out
		},
	}
	agent := &Agent{sources: []source.Source{src}}
	results := collect(agent.EnumerateUrlsWithCtx(context.Background(), "example.com", "", 0, 1, 5*time.Second, WithCustomRateLimit(emptyRateLimit())))

	if hasMaxTimeNotice(results) {
		t.Fatalf("finished before max-time, got notice: %#v", results)
	}
	if len(results) != 1 || results[0].Type != source.Url {
		t.Fatalf("results = %#v, want the one url", results)
	}
}

func TestEnumerateUrlsWithCtxParentCancelIsNotMaxTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent := &Agent{sources: []source.Source{blockingSource()}}
	ch := agent.EnumerateUrlsWithCtx(ctx, "example.com", "", 0, 1, time.Minute, WithCustomRateLimit(emptyRateLimit()))
	time.Sleep(30 * time.Millisecond)
	cancel()
	results := collect(ch)

	if hasMaxTimeNotice(results) {
		t.Fatalf("parent cancel reported as max-time: %#v", results)
	}
}

func TestEnumerateUrlsWithCtxParentDeadlineIsNotMaxTime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	agent := &Agent{sources: []source.Source{blockingSource()}}
	results := collect(agent.EnumerateUrlsWithCtx(ctx, "example.com", "", 0, 1, time.Minute, WithCustomRateLimit(emptyRateLimit())))

	if hasMaxTimeNotice(results) {
		t.Fatalf("parent deadline reported as max-time: %#v", results)
	}
}
