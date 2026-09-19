//go:build !windows
// +build !windows

// Errno classification for TCPing dials on Unix-like platforms (Linux, macOS,
// the BSDs).
//
// A TCPing failure means one of two very different things:
//
//   - The target is down / unreachable *over a network this host actually has*.
//     That is real packet loss and must be reported as such.
//   - This host could not even put the SYN on the wire, because it has no route
//     or no address of the target's address family at all. The classic case is
//     an IPv6 tcping target configured for a machine with no IPv6 connectivity:
//     connect(2) fails in ~0 ms with ENETUNREACH and every single probe
//     "fails", painting a permanent 50 % loss on the dashboard for a target the
//     agent was never able to test.
//
// The three errnos below are the second case — the probe was never attempted:
//
//	ENETUNREACH    (Linux 101) no route to the destination's network at all;
//	               what a v6 literal gives you on a v4-only host.
//	EAFNOSUPPORT   (Linux 97)  the kernel refuses the address family outright,
//	               e.g. IPv6 disabled via sysctl / ipv6.disable=1.
//	EADDRNOTAVAIL  (Linux 99)  no local source address of that family to bind.
//
// Deliberately NOT in the set, because they are genuine loss signals about a
// reachable network: EHOSTUNREACH (the network is reachable, that host is not),
// ECONNREFUSED (the host answered with RST — it is very much up), EINVAL (a
// malformed target, e.g. a link-local literal without a zone) and timeouts.

package main

import "syscall"

// isUnattemptableErrno reports whether errno means the local host could not
// attempt the connection, as opposed to the connection having been attempted
// and failed.
func isUnattemptableErrno(errno syscall.Errno) bool {
	switch errno {
	case syscall.ENETUNREACH, syscall.EAFNOSUPPORT, syscall.EADDRNOTAVAIL:
		return true
	}
	return false
}
