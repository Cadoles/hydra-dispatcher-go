package webhook

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// runToEnd runs cmd, a process group of its own, and kills the group once the program
// has exited, as at the timeout (Q86): what it started and left behind dies with it,
// rather than live on, and end a zombie under a PID 1 that does not reap. A program
// that leaves a daemon behind loses it. The program is waited for without being
// reaped, its pid held until the group is killed: the group cannot be another's by
// then.
func runToEnd(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	return cmd.Wait()
}
