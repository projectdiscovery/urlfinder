package extractor

import (
	"regexp"
)

// RegexUrlExtractor is a concrete implementation of the RegexUrlExtractor interface, using regex for extraction.
type RegexUrlExtractor struct {
	extractor *regexp.Regexp
}

// NewRegexUrlExtractor creates a new regular expression to extract urls
func NewRegexUrlExtractor() (*RegexUrlExtractor, error) {
	extractor, err := regexp.Compile(`(?:http|https)?://(?:www\.)?[a-zA-Z0-9./?=_%:-]*`)
	if err != nil {
		return nil, err
	}
	return &RegexUrlExtractor{extractor: extractor}, nil
}

// Extract implements the UrlExtractor interface, using the regex to find urls in the given text.
func (re *RegexUrlExtractor) Extract(text string) []string {
	matches := re.extractor.FindAllString(text, -1)
	// The copy step is unnecessary here; you can directly return matches
	return matches
}
