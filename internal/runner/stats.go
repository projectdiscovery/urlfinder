package runner

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/urlfinder/pkg/source"
)

// printStatistics writes to w directly instead of through gologger, so an explicit
// -stats still prints under -silent, which only raises the logger level.
func printStatistics(w io.Writer, stats map[string]source.Statistics) {

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
		_, _ = fmt.Fprintf(w, "\n Source               Duration      Results     Errors\n%s\n", strings.Repeat("─", 56))
		_, _ = fmt.Fprintln(w, strings.Join(lines, "\n"))
		_, _ = fmt.Fprintln(w)
	}

	if len(skipped) > 0 {
		_, _ = fmt.Fprint(w, "\n The following sources were included but skipped...\n\n")
		_, _ = fmt.Fprintln(w, strings.Join(skipped, "\n"))
		_, _ = fmt.Fprintln(w)
	}
}
