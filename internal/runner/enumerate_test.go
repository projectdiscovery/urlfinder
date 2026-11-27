package runner

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/urlfinder/pkg/agent"
	"github.com/projectdiscovery/urlfinder/pkg/session"
	"github.com/projectdiscovery/urlfinder/pkg/source"
	"github.com/projectdiscovery/urlfinder/pkg/utils/scope"
)

type fakeSource struct {
	source.Source
	query string
}

func (s *fakeSource) Name() string { return "fake" }

func (s *fakeSource) Run(_ context.Context, query string, _ *session.Session) <-chan source.Result {
	s.query = query
	results := make(chan source.Result, 1)
	results <- source.Result{Source: s.Name(), Type: source.Url, Value: "https://www.example.com/login"}
	close(results)
	return results
}

func TestEnumerateMultipleUrlsNamesOutputFileAfterHost(t *testing.T) {
	fake := &fakeSource{}
	agent.AllSources[fake.Name()] = fake
	t.Cleanup(func() { delete(agent.AllSources, fake.Name()) })

	dir := t.TempDir()
	runner := &Runner{
		options: &Options{Timeout: 5, MaxEnumerationTime: 1, OutputDirectory: dir},
		agent:   agent.New([]string{fake.Name()}, nil, false),
	}
	if err := runner.EnumerateMultipleUrls(strings.NewReader("https://example.com/\n"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "example.com.txt")); err != nil {
		t.Error(err)
	}
}

func TestEnumerateSingleQueryAcceptsURLInput(t *testing.T) {
	fake := &fakeSource{}
	agent.AllSources[fake.Name()] = fake
	t.Cleanup(func() { delete(agent.AllSources, fake.Name()) })

	scopeManager, err := scope.NewManager(nil, nil, "rdn", false)
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{"example.com", "https://example.com", "http://example.com:8080/path?q=1"} {
		runner := &Runner{
			options:      &Options{Timeout: 5, MaxEnumerationTime: 1},
			agent:        agent.New([]string{fake.Name()}, nil, false),
			scopeManager: scopeManager,
		}
		var output bytes.Buffer
		if err := runner.EnumerateSingleQuery(input, []io.Writer{&output}); err != nil {
			t.Fatal(err)
		}
		if fake.query != "example.com" {
			t.Errorf("input %q: source got query %q", input, fake.query)
		}
		if got, want := output.String(), "https://www.example.com/login\n"; got != want {
			t.Errorf("input %q: output %q, want %q", input, got, want)
		}
	}
}
