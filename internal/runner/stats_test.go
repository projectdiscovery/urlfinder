package runner

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

func TestPrintStatisticsIgnoresSilentLevel(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	t.Cleanup(func() { gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo) })

	var out bytes.Buffer
	printStatistics(&out, map[string]source.Statistics{
		"urlscan":    {Results: 36, Errors: 1, TimeTaken: 289 * time.Millisecond},
		"alienvault": {Skipped: true},
	})

	got := out.String()
	for _, want := range []string{"Source", "urlscan", "36", "skipped", "alienvault"} {
		if !strings.Contains(got, want) {
			t.Fatalf("statistics output missing %q:\n%s", want, got)
		}
	}
}
