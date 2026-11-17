package agent

import (
	"context"
	"math"
	"testing"

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

func testRateLimit(name string, limit uint) *CustomRateLimit {
	custom := &CustomRateLimit{}
	custom.Custom.Map = map[string]uint{name: limit}
	return custom
}
