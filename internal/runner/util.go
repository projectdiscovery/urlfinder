package runner

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

var (
	ErrEmptyInput = errors.New("empty data")
)

func sanitize(data string) (string, error) {
	data = strings.Trim(data, "\n\t\"'` ")
	if data == "" {
		return "", ErrEmptyInput
	}
	return data, nil
}

// normalizeQuery reduces URL input such as https://example.com/path to its
// hostname, which is what sources and scope validation expect.
func normalizeQuery(query string) string {
	if !strings.Contains(query, "://") {
		return query
	}
	parsed, err := url.Parse(query)
	if err != nil || parsed.Hostname() == "" {
		return query
	}
	return parsed.Hostname()
}
