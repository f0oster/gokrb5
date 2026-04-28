package framework

import (
	"context"
	"fmt"
	"io"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

// execIn runs cmd inside c. Returns an error if the process exits
// non-zero, including the captured output.
func execIn(ctx context.Context, c testcontainers.Container, cmd []string) error {
	exitCode, reader, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		return fmt.Errorf("exec %v: %w", cmd, err)
	}
	if exitCode != 0 {
		out, _ := io.ReadAll(reader)
		return fmt.Errorf("%v exited %d: %s", cmd, exitCode, string(out))
	}
	return nil
}
