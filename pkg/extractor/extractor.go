package extractor

// UrlExtractor is an interface that defines the contract for url extraction.
type UrlExtractor interface {
	Extract(text string) []string
}
