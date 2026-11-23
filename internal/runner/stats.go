package runner

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/source"
)

// printStatistics writes the -stats table to stderr. It does not go through
// gologger so that -silent, which only keeps stdout to urls, still shows it.
func printStatistics(stats map[string]source.Statistics) {

	sources := slices.Sorted(maps.Keys(stats))

	var lines []string
	var skipped []string

	for _, source := range sources {
		sourceStats := stats[source]
		if sourceStats.Skipped {
			skipped = append(skipped, fmt.Sprintf(" %s", source))
		} else {
			lines = append(lines, fmt.Sprintf(" %-20s %-10s %10d %10d", source, sourceStats.TimeTaken.Round(time.Millisecond).String(), sourceStats.Results, sourceStats.Errors))
		}
	}

	if len(lines) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "\n Source               Duration      Results     Errors\n%s\n", strings.Repeat("─", 56))
		_, _ = fmt.Fprintln(os.Stderr, strings.Join(lines, "\n"))
		_, _ = fmt.Fprintln(os.Stderr)
	}

	if len(skipped) > 0 {
		_, _ = fmt.Fprint(os.Stderr, "\n The following sources were included but skipped...\n\n")
		_, _ = fmt.Fprintln(os.Stderr, strings.Join(skipped, "\n"))
		_, _ = fmt.Fprint(os.Stderr, "\n\n")
	}
}
