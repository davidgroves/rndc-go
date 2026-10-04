package rndc

import (
	"strings"
	"testing"
)

const sampleStatusText = `version: BIND 9.20.15-2-Debian (Stable Release) <id:>
running on localhost: Linux x86_64 6.17.11+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.17.11-1 (2025-12-07)
boot time: Thu, 18 Dec 2025 20:11:58 GMT
last configured: Thu, 18 Dec 2025 20:11:58 GMT
configuration file: /etc/bind/named.conf
CPUs found: 16
worker threads: 16
number of zones: 101 (100 automatic)
debug level: 0
xfers running: 0
xfers deferred: 0
xfers first refresh: 0
soa queries in progress: 0
query logging is OFF
response logging is OFF
memory profiling is INACTIVE
recursive clients: 0/900/1000
recursive high-water: 0
tcp clients: 0/150
TCP high-water: 0
server is up and running
`

func TestStatusParsing(t *testing.T) {
	st, err := ParseStatus(sampleStatusText)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "BIND 9.20.15-2-Debian (Stable Release) <id:>" {
		t.Fatalf("version %q", st.Version)
	}
	if st.RunningOn == "" || st.BootTime.Year() != 2025 || st.BootTime.Month() != 12 || st.BootTime.Day() != 18 {
		t.Fatalf("boot %+v running %q", st.BootTime, st.RunningOn)
	}
	if st.BootTime.Hour() != 20 || st.BootTime.Minute() != 11 || st.BootTime.Second() != 58 {
		t.Fatalf("time %+v", st.BootTime)
	}
	if st.LastConfigured.Year() != 2025 {
		t.Fatal("last configured")
	}
	if st.ConfigurationFile != "/etc/bind/named.conf" {
		t.Fatal(st.ConfigurationFile)
	}
	if st.CPUsFound != 16 || st.WorkerThreads != 16 {
		t.Fatal("cpu/threads")
	}
	if st.NumberOfZones != 101 || st.AutomaticZones != 100 {
		t.Fatal("zones")
	}
	if st.DebugLevel != 0 || st.QueryLogging || st.ResponseLogging || st.MemoryProfilingActive {
		t.Fatal("flags")
	}
	if st.XfersRunning != 0 || st.XfersDeferred != 0 || st.XfersFirstRefresh != 0 || st.SOAQueriesInProgress != 0 {
		t.Fatal("xfers")
	}
	if st.RecursiveClientsCurrent != 0 || st.RecursiveClientsSoftLimit != 900 || st.RecursiveClientsHardLimit != 1000 {
		t.Fatal("recursive")
	}
	if st.RecursiveHighWater != 0 || st.TCPClientsCurrent != 0 || st.TCPClientsLimit != 150 || st.TCPHighWater != 0 {
		t.Fatal("tcp")
	}
	if !st.ServerIsUp || st.RawText != sampleStatusText {
		t.Fatal("up/raw")
	}
}

func TestStatusToggles(t *testing.T) {
	on := strings.Replace(sampleStatusText, "query logging is OFF", "query logging is ON", 1)
	on = strings.Replace(on, "memory profiling is INACTIVE", "memory profiling is ACTIVE", 1)
	st, _ := ParseStatus(on)
	if !st.QueryLogging || !st.MemoryProfilingActive {
		t.Fatal("toggles")
	}
	down := strings.Replace(sampleStatusText, "server is up and running", "server is shutting down", 1)
	st, _ = ParseStatus(down)
	if st.ServerIsUp {
		t.Fatal("should be down")
	}
}

func TestStatusDefaults(t *testing.T) {
	st, _ := ParseStatus("")
	if st.Version != "" || st.CPUsFound != 0 || st.NumberOfZones != 0 || st.QueryLogging || st.ServerIsUp {
		t.Fatalf("%+v", st)
	}
	partial := "version: BIND 9.18.0\nCPUs found: 4\nserver is up and running\n"
	st, _ = ParseStatus(partial)
	if st.Version != "BIND 9.18.0" || st.CPUsFound != 4 || !st.ServerIsUp || st.WorkerThreads != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestStatusZoneCounts(t *testing.T) {
	cases := []struct {
		text  string
		total int
		auto  int
	}{
		{"number of zones: 5", 5, 0},
		{"number of zones: 100 (50 automatic)", 100, 50},
		{"number of zones: 0", 0, 0},
	}
	for _, tc := range cases {
		st, _ := ParseStatus("version: test\n" + tc.text + "\n")
		if st.NumberOfZones != tc.total || st.AutomaticZones != tc.auto {
			t.Fatalf("%s -> %d %d", tc.text, st.NumberOfZones, st.AutomaticZones)
		}
	}
}

func TestStatusRecursiveClients(t *testing.T) {
	cases := []struct {
		text            string
		cur, soft, hard int
	}{
		{"recursive clients: 10/100/200", 10, 100, 200},
		{"recursive clients: 0/500/1000", 0, 500, 1000},
	}
	for _, tc := range cases {
		st, _ := ParseStatus("version: test\n" + tc.text + "\n")
		if st.RecursiveClientsCurrent != tc.cur || st.RecursiveClientsSoftLimit != tc.soft || st.RecursiveClientsHardLimit != tc.hard {
			t.Fatalf("%+v", st)
		}
	}
}
