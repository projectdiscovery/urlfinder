package runner

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"

	"github.com/projectdiscovery/urlfinder/pkg/source"
)

// captureStderr runs fn with -silent output configured and returns what it
// wrote to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	options := &Options{Silent: true}
	options.configureOutput()
	t.Cleanup(func() { gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo) })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = stderr
	_ = w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSilentKeepsStatistics(t *testing.T) {
	out := captureStderr(t, func() {
		printStatistics(map[string]source.Statistics{
			"alienvault": {Errors: 1, TimeTaken: time.Second},
			"urlscan":    {Skipped: true},
		})
	})
	for _, want := range []string{"Source", "alienvault", "included but skipped", "urlscan"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats output with -silent is missing %q:\n%s", want, out)
		}
	}
}

func TestSilentKeepsSourceErrors(t *testing.T) {
	runner := &Runner{options: &Options{Silent: true}}
	out := captureStderr(t, func() {
		runner.reportSourceError(source.Result{
			Source: "alienvault",
			Type:   source.Error,
			Error:  errors.New("unexpected status code 429"),
		})
	})
	if want := "Could not run source alienvault: unexpected status code 429"; !strings.Contains(out, want) {
		t.Errorf("source error with -silent = %q, want it to contain %q", out, want)
	}
}
