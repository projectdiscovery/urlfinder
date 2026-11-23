package runner

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/urlfinder/pkg/source"
)

type bufWriter struct {
	buf *bytes.Buffer
}

func (w *bufWriter) Write(data []byte, _ levels.Level) {
	_, _ = w.buf.Write(data)
}

func TestLogResultErrorShowsMaxTimeAtDefaultLevel(t *testing.T) {
	var buf bytes.Buffer
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.DefaultLogger.SetWriter(&bufWriter{buf: &buf})
	t.Cleanup(func() {
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})

	logResultError(source.Result{
		Type:  source.Error,
		Error: errors.New("max-time reached, returning partial results"),
	})
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
