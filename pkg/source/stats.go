package source

import "time"

// Statistics contains statistics about the scraping process
type Statistics struct {
	TimeTaken time.Duration
	Errors    int
	Results   int
	Skipped   bool
}
