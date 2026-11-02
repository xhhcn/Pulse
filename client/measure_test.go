package main

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// A TCPing sample is the TCP handshake alone: a host name's lookup is not
// part of it (it used to be, adding a resolver round trip to every sample).
func TestTCPingTimesHandshakeOnly(t *testing.T) {
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
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, target := range []string{"127.0.0.1:" + port, "localhost:" + port} {
		ms, err := executeTCPing(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if ms <= 0 || ms > 50 {
			t.Fatalf("%s: loopback handshake took %.3f ms", target, ms)
		}
	}
}

// Traffic counts the host's own interfaces: container and VM bridges,
// veth/tap ends, tunnels, overlays and ifb mirrors carry traffic that
// already crosses a real interface.
func TestVirtualInterfacesAreNotCounted(t *testing.T) {
	for _, name := range []string{"lo", "docker0", "br-1a2b3c", "veth9f2e", "virbr0", "vmbr0", "vnet3", "lxcbr0", "tap0", "tun0", "wg0", "tailscale0", "zt5u4y", "kube-ipvs0", "cni0", "flannel.1", "cali1234", "cilium_host", "vxlan.calico", "ifb0"} {
		if !isVirtualInterface(name) {
			t.Errorf("%s should not be counted", name)
		}
	}
	for _, name := range []string{"eth0", "ens3", "enp1s0", "eno1", "venet0", "ppp0", "bond0", "wlan0", "enx001122334455"} {
		if isVirtualInterface(name) {
			t.Errorf("%s should be counted", name)
		}
	}
}

// A known address is looked up again after ipCacheTTL; when the last lookup
// found nothing it is retried after ipRetryTTL.
func TestPublicAddressRefreshInterval(t *testing.T) {
	ipCacheMutex.Lock()
	origV4, origV6, origTime, origDetected := ipv4Cache, ipv6Cache, ipCacheTime, ipDetectedAt
	ipCacheMutex.Unlock()
	origFn := detectIPAddressesFn
	t.Cleanup(func() {
		detectIPAddressesFn = origFn
		ipCacheMutex.Lock()
		ipv4Cache, ipv6Cache, ipCacheTime, ipDetectedAt = origV4, origV6, origTime, origDetected
		ipRefreshInFlight = false
		ipCacheMutex.Unlock()
	})
	var detections int32
	detectIPAddressesFn = func() (string, string) {
		atomic.AddInt32(&detections, 1)
		return "203.0.113.5", ""
	}
	set := func(v4 string, age time.Duration) {
		ipCacheMutex.Lock()
		ipv4Cache, ipv6Cache = v4, ""
		ipCacheTime = time.Now().Add(-age)
		ipDetectedAt = ipCacheTime
		ipRefreshInFlight = false
		ipCacheMutex.Unlock()
	}
	waitIdle := func() {
		for i := 0; i < 200; i++ {
			ipCacheMutex.RLock()
			busy := ipRefreshInFlight
			ipCacheMutex.RUnlock()
			if !busy {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	set("198.51.100.7", 2*time.Minute)
	getIPAddresses()
	waitIdle()
	if n := atomic.LoadInt32(&detections); n != 0 {
		t.Fatalf("a known address two minutes old was looked up again (%d lookups)", n)
	}

	set("", 2*time.Minute)
	getIPAddresses()
	waitIdle()
	if n := atomic.LoadInt32(&detections); n != 1 {
		t.Fatalf("an empty cache two minutes old: %d lookups, want 1", n)
	}

	set("198.51.100.7", ipCacheTTL+time.Minute)
	getIPAddresses()
	waitIdle()
	if n := atomic.LoadInt32(&detections); n != 2 {
		t.Fatalf("a known address older than ipCacheTTL: %d lookups in total, want 2", n)
	}
}
