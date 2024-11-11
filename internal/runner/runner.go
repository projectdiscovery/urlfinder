package runner

import (
	"bufio"
	"context"
	"io"
	"math"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	contextutil "github.com/projectdiscovery/utils/context"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"

	"github.com/projectdiscovery/urlfinder/pkg/agent"
)

// Runner is an instance of the url enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options   *Options
	agent     *agent.Agent
	rateLimit *agent.CustomRateLimit
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the url enumeration engine
	runner.initializeAgent()

	// Initialize the custom rate limit
	runner.rateLimit = &agent.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
	}

	for source, sourceRateLimit := range options.RateLimits.AsMap() {
		if sourceRateLimit.MaxCount > 0 && sourceRateLimit.MaxCount <= math.MaxUint {
			_ = runner.rateLimit.Custom.Set(source, sourceRateLimit.MaxCount)
		}
	}

	return runner, nil
}

func (r *Runner) initializeAgent() {
	r.agent = agent.New(r.options.Sources, r.options.ExcludeSources, r.options.All)
}

// RunEnumeration wraps RunEnumerationWithCtx with an empty context
func (r *Runner) RunEnumeration() error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.RunEnumerationWithCtx(ctx)
}

// RunEnumerationWithCtx runs the url enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.URLs) > 0 {
		urlsReader := strings.NewReader(strings.Join(r.options.URLs, "\n"))
		return r.EnumerateMultipleUrlsWithCtx(ctx, urlsReader, outputs)
	}

	// If we have STDIN input, treat it as multiple urls
	if r.options.Stdin {
		return r.EnumerateMultipleUrlsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleUrls wraps EnumerateMultipleUrlsWithCtx with an empty context
func (r *Runner) EnumerateMultipleUrls(reader io.Reader, writers []io.Writer) error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.EnumerateMultipleUrlsWithCtx(ctx, reader, writers)
}

// EnumerateMultipleUrlsWithCtx enumerates urls for multiple queries
// We keep enumerating urls for a given query until we reach an error
func (r *Runner) EnumerateMultipleUrlsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		url, err := normalizeLowercase(scanner.Text())
		if errors.Is(err, ErrEmptyInput) {
			continue
		}

		var file *os.File
		// If the user has specified an output file, use that output file instead
		// of creating a new output file for each url. Else create a new file
		// for each url in the directory.
		if r.options.OutputFile != "" {
			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(r.options.OutputFile, true)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.URLs, err)
				return err
			}

			err = r.EnumerateSingleQueryWithCtx(ctx, url, append(writers, file))

			file.Close()
		} else if r.options.OutputDirectory != "" {
			outputFile := path.Join(r.options.OutputDirectory, url)
			if r.options.JSON {
				outputFile += ".json"
			} else {
				outputFile += ".txt"
			}

			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(outputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.URLs, err)
				return err
			}

			err = r.EnumerateSingleQueryWithCtx(ctx, url, append(writers, file))

			file.Close()
		} else {
			err = r.EnumerateSingleQueryWithCtx(ctx, url, writers)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
