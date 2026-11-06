package main

import (
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
)

// Disk: df's Use% (used / (used + avail)), ZFS pools counted once, a device
// once however often it is mounted, network and pseudo filesystems left out.
func TestParseDfTotals(t *testing.T) {
	full := `Filesystem     Type     1B-blocks        Used Available Use% Mounted on
udev           devtmpfs 1004453888           0 1004453888   0% /dev
tmpfs          tmpfs     203763712      966656  202797056   1% /run
/dev/vda1      ext4     41555521536 39477743616         0 100% /
tmpfs          tmpfs    1018802176           0 1018802176   0% /dev/shm`
	d, ok := parseDfTotals(full)
	if !ok || d.percent() != 100 || d.info() != "36.77 GiB / 38.7 GiB" {
		t.Fatalf("full ext4 disk: %v%% %q (ok %v), want 100%% as df", d.percent(), d.info(), ok)
	}

	zfs := `Filesystem                 Type        1B-blocks         Used      Available Use% Mounted on
tmpfs                      tmpfs      3354611712      2101248     3352510464   1% /run
rpool/ROOT/ubuntu_k3x1az   zfs      943718400000  12884901888   930833498112   2% /
tmpfs                      tmpfs     16773058560            0    16773058560   0% /dev/shm
bpool/BOOT/ubuntu_k3x1az   zfs        1879048192    268435456     1610612736  15% /boot
/dev/nvme0n1p1             vfat        535801856      6291456      529510400   2% /boot/efi
rpool/USERDATA/root_k3x1az zfs      930833498112       524288   930832973824   1% /root
rpool/data                 zfs     1730000000000 799166501888   930833498112  47% /data`
	d, ok = parseDfTotals(zfs)
	wantUsed := uint64(12884901888 + 524288 + 799166501888 + 268435456 + 6291456)
	wantAvail := uint64(930833498112 + 1610612736 + 529510400)
	if !ok || d.used != wantUsed || d.avail != wantAvail {
		t.Fatalf("ZFS root: used %d avail %d, want %d / %d (each pool's free space once)", d.used, d.avail, wantUsed, wantAvail)
	}
	if p := d.percent(); math.Abs(p-46.54) > 0.01 {
		t.Fatalf("ZFS root: %.2f%%, want 46.54%% (was 1.2%%: the EFI partition alone)", p)
	}

	mixed := `Filesystem          Type   1B-blocks       Used  Available Use% Mounted on
/dev/sda2           btrfs  500000000000 200000000000 300000000000 40% /
/dev/sda2           btrfs  500000000000 200000000000 300000000000 40% /home
/dev/sdb1           ext4   100000000000  10000000000  85000000000 11% /data
nas:/export         nfs4   900000000000 800000000000 100000000000 89% /mnt/nas
/dev/loop3          squashfs  50000000   50000000          0 100% /snap/core/1
overlay             overlay 500000000000 200000000000 300000000000 40% /var/lib/docker/overlay2/x/merged`
	d, ok = parseDfTotals(mixed)
	if !ok || d.used != 210000000000 || d.avail != 385000000000 || d.size != 600000000000 {
		t.Fatalf("btrfs twice, NFS, snap, overlay: %+v", d)
	}

	if _, ok := parseDfTotals("Filesystem Type 1B-blocks Used Available Use% Mounted on\noverlay overlay 100 50 50 50% /"); ok {
		t.Fatal("an overlay root alone is not a local disk: the root fallback reads it")
	}
	if _, ok := parseDfTotals(""); ok {
		t.Fatal("empty df output")
	}
}

func TestParseDfRoot(t *testing.T) {
	d, ok := parseDfRoot("Filesystem     1024-blocks    Used Available Capacity Mounted on\noverlay           40581564 9877516  28618304      26% /\n")
	if !ok || d.used != 9877516*1024 || d.avail != 28618304*1024 || d.size != 40581564*1024 {
		t.Fatalf("root: %+v %v", d, ok)
	}
	if p := d.percent(); math.Abs(p-25.66) > 0.01 {
		t.Fatalf("root: %.2f%%, want df's 26%%", p)
	}
	if _, ok := parseDfRoot("df: /: No such file"); ok {
		t.Fatal("garbage")
	}
}

// Network: device-backed interfaces only; without any (containers), names.
func TestCountedInterfaces(t *testing.T) {
	dir := t.TempDir()
	orig := sysClassNetDir
	sysClassNetDir = dir
	t.Cleanup(func() { sysClassNetDir = orig })
	mk := func(name string, device bool) {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if device {
			if err := os.MkdirAll(filepath.Join(dir, name, "device"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, n := range []string{"eno1", "eno2", "wlan0"} {
		mk(n, true)
	}
	for _, n := range []string{"lo", "bond0", "vmbr0", "fwbr100i0", "fwpr100p0", "fwln100i0", "tap100i0", "eno1.100", "ppp0", "wg0", "docker0", "veth1a2b"} {
		mk(n, false)
	}
	names := []string{"lo", "eno1", "eno2", "wlan0", "bond0", "vmbr0", "fwbr100i0", "fwpr100p0", "fwln100i0", "tap100i0", "eno1.100", "ppp0", "wg0", "docker0", "veth1a2b"}
	got := countedInterfaces(names)
	if len(got) != 3 || !got["eno1"] || !got["eno2"] || !got["wlan0"] {
		t.Fatalf("a Proxmox host with a bond, a VLAN and PPPoE counts its NICs only: %v", got)
	}

	// A container: no device anywhere, so the names decide.
	empty := t.TempDir()
	sysClassNetDir = empty
	got = countedInterfaces([]string{"lo", "eth0", "venet0", "docker0", "bond0"})
	if len(got) != 2 || !got["eth0"] || !got["venet0"] {
		t.Fatalf("container: %v", got)
	}
}

func TestNetRatesPerInterface(t *testing.T) {
	const mib = 1024 * 1024
	prev := map[string]netInterfaceStats{"eth0": {RxBytes: 1000, TxBytes: 2000}, "ppp0": {RxBytes: 50 * mib, TxBytes: 50 * mib}, "eth1": {RxBytes: 10 * mib, TxBytes: 0}}
	cur := map[string]netInterfaceStats{
		"eth0": {RxBytes: 1000 + 6*mib, TxBytes: 2000 + 3*mib}, // 2 MiB/s down, 1 up over 3 s
		"eth1": {RxBytes: 3 * mib, TxBytes: 0},                 // reset: counted from 0 → 1 MiB/s
		"new0": {RxBytes: 900 * mib, TxBytes: 900 * mib},       // appeared: from its next reading
		// ppp0 went away: its counters drop out, the others still count
	}
	in, out := netRates(prev, cur, 3)
	if math.Abs(in-3) > 1e-9 || math.Abs(out-1) > 1e-9 {
		t.Fatalf("rates %v / %v MiB/s, want 3 / 1", in, out)
	}
	if in, out := netRates(nil, cur, 3); in != 0 || out != 0 {
		t.Fatal("no previous reading: 0")
	}
}

func TestReadLinuxInterfaces(t *testing.T) {
	f := filepath.Join(t.TempDir(), "dev")
	data := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567     100    0    0    0     0          0         0  1234567     100    0    0    0     0       0          0
  eth0: 98765432100 5000    0    0    0     0          0         0 12345678901 4000    0    0    0     0       0          0
`
	if err := os.WriteFile(f, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := procNetDevPath
	procNetDevPath = f
	t.Cleanup(func() { procNetDevPath = orig })
	all, ok := readLinuxInterfaces()
	if !ok || len(all) != 2 || all["eth0"].RxBytes != 98765432100 || all["eth0"].TxBytes != 12345678901 {
		t.Fatalf("parsed %+v", all)
	}
}

func TestIsOtherVirtualInterface(t *testing.T) {
	for _, n := range []string{"lo0", "lo", "utun3", "awdl0", "llw0", "bridge0", "gif0", "stf0", "anpi1", "Loopback Pseudo-Interface 1", "vEthernet (WSL)", "isatap.{1234}", "Teredo Tunneling Pseudo-Interface"} {
		if !isOtherVirtualInterface(n) {
			t.Errorf("%q should not be counted", n)
		}
	}
	for _, n := range []string{"en0", "en1", "Ethernet", "Ethernet 2", "Wi-Fi", "Local Area Connection", "Local Area Connection* 2"} {
		if isOtherVirtualInterface(n) {
			t.Errorf("%q should be counted", n)
		}
	}
}

// Memory in a container: the whole page cache less shmem is reclaimable.
func TestMemoryStatReclaimable(t *testing.T) {
	v2 := "anon 20971520\nfile 262144000\nshmem 10485760\nslab_reclaimable 4194304\nactive_file 209715200\ninactive_file 52428800\n"
	if got := memoryStatReclaimable(v2); got != 262144000-10485760+4194304 {
		t.Fatalf("v2: %d", got)
	}
	v1 := "cache 300000000\nshmem 1000000\ninactive_file 1000\nslab_reclaimable 0\ntotal_cache 300000000\ntotal_shmem 1000000\ntotal_inactive_file 1000\ntotal_slab_reclaimable 5000\n"
	if got := memoryStatReclaimable(v1); got != 300000000-1000000+5000 {
		t.Fatalf("v1 hierarchical (total_ values, never both): %d", got)
	}
	v1plain := "cache 300000000\nshmem 1000000\ninactive_file 1000\nslab_reclaimable 7000\n"
	if got := memoryStatReclaimable(v1plain); got != 300000000-1000000+7000 {
		t.Fatalf("v1: %d", got)
	}
	old := "inactive_file 4096\nslab_reclaimable 1024\n"
	if got := memoryStatReclaimable(old); got != 4096+1024 {
		t.Fatalf("no cache key: inactive_file as before: %d", got)
	}
	if got := memoryStatReclaimable("file 100\nshmem 500\n"); got != 0 {
		t.Fatalf("shmem above the cache: %d", got)
	}
}

// Memory on a ZFS host: the ARC is not counted as used; in a container it is
// the host's and stays.
func TestProcMeminfoZFSARC(t *testing.T) {
	dir := t.TempDir()
	meminfo := filepath.Join(dir, "meminfo")
	arc := filepath.Join(dir, "arcstats")
	if err := os.WriteFile(meminfo, []byte("MemTotal:       16777216 kB\nMemFree:          524288 kB\nMemAvailable:    2097152 kB\nBuffers:           10240 kB\nCached:          1048576 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(arc, []byte("13 1 0x01 123 33456 1234 5678\nname                            type data\nhits                            4    123456\nsize                            4    10737418240\nc_max                           4    16000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	origM, origA, origC := procMeminfoPath, zfsARCStatsPath, inLinuxContainer
	t.Cleanup(func() { procMeminfoPath, zfsARCStatsPath, inLinuxContainer = origM, origA, origC })
	procMeminfoPath, zfsARCStatsPath = meminfo, arc

	inLinuxContainer = func() bool { return false }
	used, total, ok := procMeminfo()
	if !ok || total != 16777216 || used != 16777216-2097152-10485760 {
		t.Fatalf("host: used %d of %d (%v), want 14 GiB less the 10 GiB ARC", used, total, ok)
	}
	inLinuxContainer = func() bool { return true }
	if used, _, _ := procMeminfo(); used != 16777216-2097152 {
		t.Fatalf("container: used %d, the host's ARC must stay", used)
	}
	zfsARCStatsPath = filepath.Join(dir, "none")
	inLinuxContainer = func() bool { return false }
	if used, _, _ := procMeminfo(); used != 16777216-2097152 {
		t.Fatalf("no ZFS: used %d", used)
	}
	if err := os.WriteFile(meminfo, []byte("MemTotal: 0 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, total, ok := procMeminfo(); !ok || total != 0 {
		t.Fatal("zeroed meminfo: readable, total 0")
	}
	procMeminfoPath = filepath.Join(dir, "missing")
	if _, _, ok := procMeminfo(); ok {
		t.Fatal("unreadable meminfo")
	}
}

// TCPing: every probe of a round is stamped when its dial starts, so a lost
// probe lands with the rest of its round, not when its timeout ran out.
func TestMeasureTCPingOnceStampsDialStart(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	pendingTCPingResultsMu.Lock()
	saved := pendingTCPingResults
	pendingTCPingResults = nil
	pendingTCPingResultsMu.Unlock()
	t.Cleanup(func() {
		pendingTCPingResultsMu.Lock()
		pendingTCPingResults = saved
		pendingTCPingResultsMu.Unlock()
	})

	lost := "192.0.2.1:9" // TEST-NET-1: no answer, the dial times out
	before := time.Now()
	measureTCPingOnce([]string{ln.Addr().String(), lost})
	took := time.Since(before)
	pendingTCPingResultsMu.Lock()
	res := append([]ClientTCPingResult(nil), pendingTCPingResults...)
	pendingTCPingResultsMu.Unlock()
	if len(res) != 2 {
		t.Fatalf("%d results", len(res))
	}
	var okAt, lostAt time.Time
	var lostResult ClientTCPingResult
	for _, r := range res {
		if strings.HasPrefix(r.Target, "127.0.0.1") {
			okAt = r.MeasuredAt
		} else {
			lostAt, lostResult = r.MeasuredAt, r
		}
	}
	if took < 2*time.Second && !lostResult.Skipped {
		t.Skipf("the lost target did not time out here (%v, %+v)", took, lostResult)
	}
	if d := lostAt.Sub(okAt); d > 200*time.Millisecond || d < -200*time.Millisecond {
		t.Fatalf("lost probe stamped %v after the answered one (the round took %v); want both at the dial start", d, took)
	}
}

func TestWindowsDriveTotals(t *testing.T) {
	parts := []disk.PartitionStat{{Mountpoint: "C:"}, {Mountpoint: "D:"}, {Mountpoint: "E:"}, {Mountpoint: "Z:"}, {Mountpoint: "c:"}, {Mountpoint: `\\?\Volume{x}\`}}
	usage := map[string]*disk.UsageStat{
		"C:": {Total: 100, Used: 60, Free: 40},
		"E:": {Total: 50, Used: 50, Free: 0}, // a mounted ISO: always full
		"Z:": {Total: 1000, Used: 10, Free: 990},
	}
	usageOf := func(mp string) (*disk.UsageStat, error) {
		if u, ok := usage[mp]; ok {
			return u, nil
		}
		return nil, errors.New("the device is not ready") // D: a locked BitLocker volume
	}
	fixed := func(mp string) bool { return mp == "C:" || mp == "D:" } // E: CD-ROM, Z: network
	got := windowsDriveTotals(parts, usageOf, fixed)
	if got != (diskTotals{used: 60, avail: 40, size: 100}) {
		t.Fatalf("got %+v: only C: counts (D: unreadable, E: an ISO, Z: a share; c: is C: again)", got)
	}
	if got := windowsDriveTotals(parts, usageOf, func(string) bool { return true }); got.size != 1150 {
		t.Fatalf("an unreadable drive must not zero the others: %+v", got)
	}
}
