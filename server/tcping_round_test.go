package main

import "testing"

// A history answer carries latencies to a microsecond, as the stream does;
// a timeout (nil) stays a timeout.
func TestRoundTCPingLatencies(t *testing.T) {
	a, b := 153.71973110749093, 9.4449999
	results := []TCPingResult{{Latency: &a}, {Latency: nil}, {Latency: &b}}
	roundTCPingLatencies(results)
	if results[0].Latency == nil || *results[0].Latency != 153.72 {
		t.Fatalf("153.7197… → %v, want 153.72", results[0].Latency)
	}
	if results[1].Latency != nil {
		t.Fatalf("a timeout became %v", *results[1].Latency)
	}
	if *results[2].Latency != 9.445 {
		t.Fatalf("9.4449999 → %v, want 9.445", *results[2].Latency)
	}
	if a != 153.71973110749093 {
		t.Fatalf("the value the pointer had was changed: %v", a)
	}
}
