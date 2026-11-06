//go:build windows
// +build windows

package main

import (
	"syscall"
	"unsafe"
)

var procGetDriveTypeW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW")

const driveFixed = 3 // DRIVE_FIXED

// localFixedDrive is true for a drive letter on one of this machine's own
// disks (DRIVE_FIXED). A network share, a USB stick, a CD or a mounted ISO
// (always full) is not the machine's disk.
func localFixedDrive(mountpoint string) bool {
	root, err := syscall.UTF16PtrFromString(mountpoint + `\`)
	if err != nil {
		return false
	}
	t, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(root)))
	return t == driveFixed
}
