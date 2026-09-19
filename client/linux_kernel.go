//go:build linux
// +build linux

// Linux kernel-data readers that bypass /proc/meminfo and /proc/uptime.
//
// Inside a broken / restricted LXC container, lxcfs can mask the standard
// /proc files (returning ENOTCONN or zeroed data). These helpers reach
// around that by either:
//
//   - Calling the sysinfo(2) syscall directly — the kernel answers without
//     going through any FUSE layer.
//   - Reading /proc/[pid]/stat, which is kernel-synthesized per-process
//     and never touched by lxcfs (lxcfs only intercepts a fixed list of
//     /proc files: meminfo, stat, cpuinfo, uptime, loadavg, diskstats,
//     slabinfo — PID-specific stat files are not in that list).

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ─── sysinfo(2) ─────────────────────────────────────────────────────────

// readSysinfo invokes the Linux sysinfo(2) syscall directly. Unlike
// /proc/meminfo, sysinfo cannot be masked by lxcfs, a zeroed-out bind
// mount, or a custom procfs filter — it always reports the kernel's view
// of host-level memory. This makes it the only reliable memory source on
// LXC containers that strip /proc/meminfo.
//
// Returns (memTotalBytes, memUsedBytes, swapTotalBytes, swapUsedBytes, ok).
// ok=false on syscall error or when Totalram is 0 (which would only happen
// on a very broken kernel — not something callers should have to ignore).
//
// Caveats:
//   - sysinfo reports HOST memory, not cgroup-limited memory. That's why
//     callers should try cgroup-direct reads first; sysinfo is the
//     fallback for "no cgroup limit set AND /proc/meminfo is masked".
//   - sysinfo has no Cached / MemAvailable concept, so "used" is the
//     coarse (Totalram - Freeram - Bufferram) — slightly higher than
//     /proc/meminfo's MemAvailable-based calculation, but non-zero and
//     usable.
func readSysinfo() (memTotal, memUsed, swapTotal, swapUsed uint64, ok bool) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, 0, 0, 0, false
	}
	if si.Totalram == 0 {
		return 0, 0, 0, 0, false
	}
	unit := uint64(si.Unit)
	if unit == 0 {
		unit = 1
	}
	// syscall.Sysinfo_t fields are uint32 on 32-bit archs and uint64 on
	// 64-bit archs — cast explicitly so this builds for both.
	total := uint64(si.Totalram)
	free := uint64(si.Freeram)
	buffer := uint64(si.Bufferram)
	totalSw := uint64(si.Totalswap)
	freeSw := uint64(si.Freeswap)

	memTotal = total * unit
	// Coarse "used" = total - free - buffers (sysinfo exposes no cache field).
	freeAndBuffers := (free + buffer) * unit
	if freeAndBuffers > memTotal {
		memUsed = 0
	} else {
		memUsed = memTotal - freeAndBuffers
	}
	swapTotal = totalSw * unit
	if totalSw >= freeSw {
		swapUsed = (totalSw - freeSw) * unit
	}
	return memTotal, memUsed, swapTotal, swapUsed, true
}

// readSysinfoUptime returns (host uptime in seconds, ok). This is the
// time the kernel has been running, which in a container is the HOST's
// uptime — not necessarily the container's. Use readContainerUptime for
// the container-local value; this is the safer of the two fallbacks when
// /proc/uptime is masked.
func readSysinfoUptime() (int64, bool) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, false
	}
	if si.Uptime <= 0 {
		return 0, false
	}
	return int64(si.Uptime), true
}

// ─── /proc/[pid]/stat ──────────────────────────────────────────────────

// readPid1StartTicks parses /proc/1/stat and returns field 22 (starttime,
// USER_HZ ticks since system boot). In a container, PID 1 is the init
// process that starts when the container boots, so this is the container's
// birth time relative to host boot.
//
// /proc/[pid]/stat format:
//
//	pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt
//	majflt cmajflt utime stime cutime cstime priority nice num_threads
//	itrealvalue starttime ...
//
// The tricky bit is that `comm` can contain spaces and parentheses (e.g.
// "(my proc)" or "(weird name)"), so we anchor at the LAST ')' in the
// line. After that, fields are space-separated and well-defined. starttime
// is the 20th field after the closing paren (index 19, 0-based).
func readPid1StartTicks() (int64, bool) {
	data, err := os.ReadFile("/proc/1/stat")
	if err != nil || len(data) == 0 {
		return 0, false
	}
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 || closeParen+1 >= len(s) {
		return 0, false
	}
	rest := strings.Fields(s[closeParen+1:])
	// Need field 22 = state(1) + ppid(2) + ... + starttime(20). After the
	// ')' we have state at index 0 through starttime at index 19.
	if len(rest) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseInt(rest[19], 10, 64)
	if err != nil || ticks < 0 {
		return 0, false
	}
	return ticks, true
}

// readContainerUptime returns (seconds since container init started, ok).
// In a Linux container, the init process (PID 1) is started when the
// container boots, so "now - init_start_time" gives true container uptime.
// We compute this by subtracting PID 1's start offset (from /proc/1/stat
// field 22, in USER_HZ ticks) from the host uptime reported by sysinfo(2).
//
// This is lxcfs-independent: /proc/[pid]/stat is kernel-synthesized per
// process and is not covered by the lxcfs FUSE mounts (which only touch
// /proc/meminfo, /proc/stat, /proc/cpuinfo, /proc/uptime, /proc/loadavg,
// /proc/diskstats, /proc/slabinfo). It therefore works even when
// /proc/uptime returns ENOTCONN.
//
// USER_HZ is always 100 on Linux for user-visible APIs regardless of the
// kernel's CONFIG_HZ setting (the kernel converts internally), so we use
// that constant without needing cgo / sysconf.
func readContainerUptime() (int64, bool) {
	hostUp, ok := readSysinfoUptime()
	if !ok {
		return 0, false
	}
	startTicks, ok := readPid1StartTicks()
	if !ok {
		return hostUp, true // fall back to host uptime; better than nothing
	}
	const userHZ = 100
	initStartSecs := startTicks / userHZ
	if initStartSecs > hostUp {
		return hostUp, true // clock skew; use host uptime
	}
	return hostUp - initStartSecs, true
}
