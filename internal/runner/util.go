package runner

import (
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

func normalizeLowercase(s string) (string, error) {
	data, err := sanitize(s)
	return strings.ToLower(data), err
}
