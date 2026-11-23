package runner

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/urlfinder/pkg/agent"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

type bufWriter struct {
	buf *bytes.Buffer
}

func (w *bufWriter) Write(data []byte, _ levels.Level) {
	_, _ = w.buf.Write(data)
}

// stubSource blocks until the enumeration context ends, then yields one URL.
type stubSource struct {
	name string
}

func (s *stubSource) Run(ctx context.Context, _ string, _ *session.Session) <-chan source.Result {
	out := make(chan source.Result)
	go func() {
		defer close(out)
		<-ctx.Done()
		out <- source.Result{Type: source.Url, Source: s.name, Value: "https://example.com/partial"}
	}()
	return out
}

func (s *stubSource) Name() string { return s.name }

func (s *stubSource) IsDefault() bool { return false }

func (s *stubSource) NeedsKey() bool { return false }

func (s *stubSource) AddApiKeys([]string) {}

func (s *stubSource) Statistics() source.Statistics { return source.Statistics{} }

// maxTimeResultFromAgent returns the error result EnumerateUrlsWithCtx emits
// when -max-time fires, not a locally built error with the same text.
func maxTimeResultFromAgent(t *testing.T) source.Result {
	t.Helper()
	const name = "maxtime-stub"
	agent.AllSources[name] = &stubSource{name: name}
	t.Cleanup(func() { delete(agent.AllSources, name) })

	ag := agent.New([]string{name}, nil, false)
	var notice source.Result
	found := false
	for result := range ag.EnumerateUrlsWithCtx(context.Background(), "example.com", "", 0, 1, 50*time.Millisecond) {
		if result.Type == source.Error {
			notice = result
			found = true
		}
	}
	if !found {
		t.Fatal("agent returned no error result at max-time")
	}
	return notice
}

func TestLogResultErrorShowsMaxTimeAtDefaultLevel(t *testing.T) {
	notice := maxTimeResultFromAgent(t)
	if !errors.Is(notice.Error, agent.ErrMaxTimeReached) {
		t.Fatalf("agent error = %v, want ErrMaxTimeReached", notice.Error)
	}

	var buf bytes.Buffer
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.DefaultLogger.SetWriter(&bufWriter{buf: &buf})
	t.Cleanup(func() {
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	logResultError(notice)
	got := buf.String()
	if !strings.Contains(got, "max-time reached, returning partial results") {
		t.Fatalf("default log level hid the cutoff notice: %q", got)
	}
	if strings.Contains(got, "Could not run source") {
		t.Fatalf("cutoff notice formatted as a source failure: %q", got)
	}

	buf.Reset()
	logResultError(source.Result{
		Type:   source.Error,
		Source: "waybackarchive",
		Error:  errors.New("max-time reached, returning partial results"),
	})
	if strings.Contains(buf.String(), "max-time reached") {
		t.Fatalf("same text on another error was logged at info: %q", buf.String())
	}

	buf.Reset()
	logResultError(source.Result{
		Type:   source.Error,
		Source: "waybackarchive",
		Error:  errors.New("context deadline exceeded"),
	})
	if strings.Contains(buf.String(), "waybackarchive") {
		t.Fatalf("source error was logged at info: %q", buf.String())
	}

	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	logResultError(source.Result{
		Type:   source.Error,
		Source: "waybackarchive",
		Error:  errors.New("context deadline exceeded"),
	})
	if !strings.Contains(buf.String(), "Could not run source waybackarchive: context deadline exceeded") {
		t.Fatalf("source error not logged at verbose: %q", buf.String())
	}
}
