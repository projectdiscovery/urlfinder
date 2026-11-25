package runner

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const parseOptionsArgsEnv = "URLFINDER_TEST_PARSE_ARGS"

// ParseOptions terminates the process, so it is run in a child test process.
func TestParseOptionsExitCode(t *testing.T) {
	if args, ok := os.LookupEnv(parseOptionsArgsEnv); ok {
		os.Args = append([]string{"urlfinder"}, strings.Fields(args)...)
		ParseOptions()
		os.Exit(0)
	}

	tests := []struct {
		name string
		args string
		code int
	}{
		{name: "invalid match regex", args: "-d example.invalid -m=[", code: 1},
		{name: "invalid filter regex", args: "-d example.invalid -f=[", code: 1},
		{name: "zero timeout", args: "-d example.invalid -timeout=0", code: 1},
		{name: "verbose and silent", args: "-d example.invalid -v -silent", code: 1},
		{name: "unknown rate limit source", args: "-d example.invalid -rls unknown=1/s", code: 1},
		{name: "version", args: "-version", code: 0},
		{name: "list sources", args: "-ls", code: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestParseOptionsExitCode$")
			cmd.Env = append(os.Environ(),
				"HOME="+home,
				"XDG_CONFIG_HOME="+home,
				parseOptionsArgsEnv+"=-duc -nc "+tt.args,
			)
			output, err := cmd.CombinedOutput()

			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.code, code, "output: %s", output)
		})
	}
}
