//go:build windows
// +build windows

// Errno classification for TCPing dials on Windows. See tcping_errno_unix.go
// for what the classification is for; this file only supplies the Windows
// spelling of the three "the probe was never attempted" error codes.
//
// Windows is awkward here. Go's syscall package for windows *does* export
// portable-looking ENETUNREACH / EAFNOSUPPORT / EADDRNOTAVAIL constants, but
// those are synthetic placeholders carved out of the APPLICATION_ERROR range
// so that portable code compiles — they are not what a failing connect gives
// you. A real Winsock failure surfaces as the raw WSA* code (10051 etc.)
// wrapped in *os.SyscallError{Syscall: "connectex"}. Go's syscall package does
// not export WSAENETUNREACH / WSAEAFNOSUPPORT / WSAEADDRNOTAVAIL (it only
// declares a handful of WSAE* constants: WSAEACCES, WSAENOPROTOOPT,
// WSAECONNABORTED, WSAECONNRESET), so the numeric Winsock values are spelled
// out below.
//
// Both spellings are accepted: the WSA values are what the network stack
// actually returns, and the portable aliases cost nothing and keep the
// behaviour correct if an error ever arrives through a Go shim that uses them.

package main

import "syscall"

// Winsock error codes. These are the values connect/connectex reports; Go's
// syscall package for windows does not name them.
const (
	wsaeAFNoSupport  syscall.Errno = 10047 // WSAEAFNOSUPPORT
	wsaeAddrNotAvail syscall.Errno = 10049 // WSAEADDRNOTAVAIL
	wsaeNetUnreach   syscall.Errno = 10051 // WSAENETUNREACH
)

// isUnattemptableErrno reports whether errno means the local host could not
// attempt the connection, as opposed to the connection having been attempted
// and failed.
func isUnattemptableErrno(errno syscall.Errno) bool {
	switch errno {
	case wsaeNetUnreach, wsaeAFNoSupport, wsaeAddrNotAvail:
		return true
	case syscall.ENETUNREACH, syscall.EAFNOSUPPORT, syscall.EADDRNOTAVAIL:
		// Portable aliases; distinct APPLICATION_ERROR values, so matching
		// them cannot collide with a real Winsock code.
		return true
	}
	return false
}
