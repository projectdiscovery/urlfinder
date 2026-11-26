package agent

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
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

func TestEnumerateReportsSourcesCutOffByMaxEnumTime(t *testing.T) {
	a := &Agent{sources: []source.Source{&fakeSource{name: "slow", block: true}, &fakeSource{name: "fast"}}}

	var cutOff []string
	for result := range a.EnumerateUrlsWithCtx(context.Background(), "example.com", "", 0, 5, 100*time.Millisecond) {
		if result.Type == source.Error && errors.Is(result.Error, ErrMaxEnumTime) {
			cutOff = append(cutOff, result.Source)
		}
	}
	if !slices.Equal(cutOff, []string{"slow"}) {
		t.Errorf("cut off sources = %v, want [slow]", cutOff)
	}
}

func TestEnumerateDoesNotReportParentCancellation(t *testing.T) {
	a := &Agent{sources: []source.Source{&fakeSource{name: "slow", block: true}}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	for result := range a.EnumerateUrlsWithCtx(ctx, "example.com", "", 0, 5, time.Minute) {
		if errors.Is(result.Error, ErrMaxEnumTime) {
			t.Errorf("got %v for a cancelled parent context", result.Error)
		}
	}
}

type fakeSource struct {
	name  string
	block bool
}

func (s *fakeSource) Run(ctx context.Context, _ string, _ *session.Session) <-chan source.Result {
	results := make(chan source.Result)
	go func() {
		defer close(results)
		if s.block {
			<-ctx.Done()
		}
	}()
	return results
}

func (s *fakeSource) Name() string                          { return s.name }
func (s *fakeSource) IsDefault() bool                       { return true }
func (s *fakeSource) KeyRequirement() source.KeyRequirement { return source.NoKey }
func (s *fakeSource) NeedsKey() bool                        { return false }
func (s *fakeSource) AddApiKeys([]string)                   {}
func (s *fakeSource) Statistics() source.Statistics         { return source.Statistics{} }

func testRateLimit(name string, limit uint) *CustomRateLimit {
	custom := &CustomRateLimit{}
	custom.Custom.Map = map[string]uint{name: limit}
	return custom
}
