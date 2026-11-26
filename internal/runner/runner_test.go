package runner

import (
	"context"
	"errors"
	"testing"
	"testing/iotest"
)

func TestEnumerateMultipleUrlsWithCtxReturnsReaderError(t *testing.T) {
	readErr := errors.New("input read failed")
	runner := &Runner{}

	err := runner.EnumerateMultipleUrlsWithCtx(context.Background(), iotest.ErrReader(readErr), nil)
	if !errors.Is(err, readErr) {
		t.Fatalf("EnumerateMultipleUrlsWithCtx returned %v, want %v", err, readErr)
	}
}
