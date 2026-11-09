//go:build !linux

package webhook

import (
	"os/exec"
	"syscall"
)

// runToEnd runs cmd and kills its process group once it has exited (Q86). Outside
// Linux, the group is killed after the program is reaped: its pid could, in theory, be
// another's by then. The image runs on Linux.
func runToEnd(cmd *exec.Cmd) error {
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return err
}
