package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Startup probe for the database file.
//
// The store opens bbolt with NoFreelistSync, so on every open bbolt rebuilds
// its free-page list by walking the whole tree — and on a damaged tree (keys
// out of order, a page referenced twice, a broken stored freelist) it panics
// from a goroutine of its own, beyond any recover. Without a guard the server
// would die the same way on every start. So before the real open, the same
// open runs once in a short-lived child process (this binary, re-executed
// with dbOpenProbeEnv set). If that child dies inside bbolt, the file is
// salvaged: every bucket and key/value is copied from a read-only open (which
// does not rebuild the freelist) into a fresh file, the damaged original is
// kept next to it as <path>.damaged-<timestamp>, and the copy takes its place.
// Damage the copy cannot get past (an unreadable page) is left alone and
// reported, exactly as before this probe existed.

const dbOpenProbeEnv = "PULSE_DB_OPEN_PROBE"

// dbProbeTimeout bounds the child's open. A cold walk of a few hundred MB
// on a slow disk takes tens of seconds; the parent's own open would pay the
// same, so this is only a guard against a stuck child.
const dbProbeTimeout = 10 * time.Minute

// runDBOpenProbeIfRequested must run first thing in main (and TestMain). In
// the probe child it opens the database exactly as the server does and
// exits: 0 when the open succeeds, 3 when it returns an error. A panic inside
// bbolt ends the process with Go's exit code 2 and a stack trace on stderr.
func runDBOpenProbeIfRequested() {
	path := os.Getenv(dbOpenProbeEnv)
	if path == "" {
		return
	}
	db, err := openBolt(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe open: %v\n", err)
		os.Exit(3)
	}
	_ = db.Close()
	os.Exit(0)
}

// boundedBuffer keeps the first max bytes written to it and drops the rest.
type boundedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

// preflightDB runs the open probe for an existing database file and salvages
// the file when bbolt dies on it. Any other probe outcome (no file, the probe
// could not run, a timeout, an ordinary open error) leaves the file alone and
// lets the normal open report it.
func preflightDB(path string) {
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		log.Printf("⚠️  database probe skipped: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(), dbOpenProbeEnv+"="+path)
	cmd.Stdout = io.Discard
	stderr := &boundedBuffer{max: 64 << 10}
	cmd.Stderr = stderr
	err = cmd.Run()
	if err == nil {
		return
	}
	if ctx.Err() != nil {
		log.Printf("⚠️  database probe timed out after %v; opening normally", dbProbeTimeout)
		return
	}
	var exitErr *exec.ExitError
	out := stderr.buf.String()
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 || !strings.Contains(out, "go.etcd.io/bbolt") {
		log.Printf("⚠️  database probe failed (%v); opening normally", err)
		return
	}
	log.Printf("⚠️  bbolt stopped while opening %s: %s", path, firstLine(out))
	damaged, err := salvageDB(path)
	if err != nil {
		log.Printf("❌ database salvage failed, the file is left as it is: %v", err)
		return
	}
	log.Printf("🩹 Database salvaged into a fresh file; the damaged original is kept as %s", damaged)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// salvageDB copies every bucket and key/value of path, read through a
// read-only open, into a fresh file and swaps it in. It returns the name the
// damaged original was moved to. A read that trips over an unreadable page
// panics inside bbolt's cursor code on this goroutine and is reported as an
// error; nothing is swapped in that case.
func salvageDB(path string) (damagedPath string, err error) {
	src, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return "", fmt.Errorf("open read-only: %w", err)
	}
	tmpPath := path + ".salvage"
	_ = os.Remove(tmpPath)
	dst, err := bolt.Open(tmpPath, 0600, &bolt.Options{
		Timeout:        5 * time.Second,
		FreelistType:   bolt.FreelistMapType,
		NoFreelistSync: true,
	})
	if err != nil {
		src.Close()
		return "", fmt.Errorf("open salvage file: %w", err)
	}
	copyErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("copy stopped on an unreadable page: %v", r)
			}
		}()
		return bolt.Compact(dst, src, compactTxMaxBytes)
	}()
	closeErr := dst.Close()
	src.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", copyErr
	}
	damagedPath = fmt.Sprintf("%s.damaged-%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(path, damagedPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("move damaged file aside: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Put the original back rather than leave no database at all.
		_ = os.Rename(damagedPath, path)
		return "", fmt.Errorf("swap in salvaged file: %w", err)
	}
	return damagedPath, nil
}
