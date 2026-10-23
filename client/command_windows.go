//go:build windows
// +build windows

package main

import "os/exec"

// killProcessGroupOnCancel keeps the default cancellation on Windows, which
// kills the process itself. The probes there (wmic) run directly, not through a
// shell pipeline, so nothing else holds their output pipe; runCommandOutput's
// WaitDelay still bounds the wait if something does.
func killProcessGroupOnCancel(cmd *exec.Cmd) {}
