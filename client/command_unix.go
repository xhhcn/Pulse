//go:build !windows
// +build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killProcessGroupOnCancel starts cmd as the leader of a process group of its
// own and makes the context's cancellation SIGKILL that whole group, so a
// timed-out `sh -c` pipeline takes every process in it down (see
// runCommandOutput).
func killProcessGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The group id is the leader's pid; a negative pid signals the group.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.ESRCH):
			// Everyone already exited: what exec expects from a Cancel that
			// found nothing left to stop.
			return os.ErrProcessDone
		default:
			// macOS answers EPERM when the group holds only the leader,
			// exited but not yet reaped. Fall back to exec's own default,
			// which reports an exited process as os.ErrProcessDone.
			return cmd.Process.Kill()
		}
	}
}
