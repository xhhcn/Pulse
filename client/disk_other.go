//go:build !windows
// +build !windows

package main

// localFixedDrive only matters on Windows (see disk_windows.go).
func localFixedDrive(string) bool { return true }
