package source

import (
	"context"

	"github.com/projectdiscovery/urlfinder/pkg/session"
)

// KeyRequirement is how much a source depends on API keys
type KeyRequirement int

const (
	NoKey KeyRequirement = iota
	// OptionalKey sources work without a key, and a key lifts their limits
	OptionalKey
	RequiredKey
)

// Source is an interface inherited by each passive source
type Source interface {
	// Run takes a query as argument and a session object
	// which contains the extractor for url, http client
	// and other stuff.
	Run(context.Context, string, *session.Session) <-chan Result

	// Name returns the name of the source. It is preferred to use lower case names.
	Name() string

	// IsDefault returns true if the current source should be
	// used as part of the default execution.
	IsDefault() bool

	// KeyRequirement returns how much the source depends on API keys
	KeyRequirement() KeyRequirement

	// NeedsKey returns true if the source requires an API key.
	// Deprecated: use KeyRequirement, which also covers optional keys.
	NeedsKey() bool

	AddApiKeys([]string)

	// Statistics returns the scrapping statistics for the source
	Statistics() Statistics
}
