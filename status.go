package rndc

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Status is a parsed BIND `rndc status` response.
type Status struct {
	Version                   string
	RunningOn                 string
	BootTime                  time.Time
	LastConfigured            time.Time
	ConfigurationFile         string
	CPUsFound                 int
	WorkerThreads             int
	NumberOfZones             int
	AutomaticZones            int
	DebugLevel                int
	QueryLogging              bool
	ResponseLogging           bool
	MemoryProfilingActive     bool
	XfersRunning              int
	XfersDeferred             int
	XfersFirstRefresh         int
	SOAQueriesInProgress      int
	RecursiveClientsCurrent   int
	RecursiveClientsSoftLimit int
	RecursiveClientsHardLimit int
	RecursiveHighWater        int
	TCPClientsCurrent         int
	TCPClientsLimit           int
	TCPHighWater              int
	ServerIsUp                bool
	RawText                   string
}

const statusDateLayout = "Mon, 02 Jan 2006 15:04:05 MST"

var (
	reValue = func(pattern string) *regexp.Regexp {
		return regexp.MustCompile(pattern)
	}
	reVersion        = reValue(`(?m)^version:\s*(.+)$`)
	reRunningOn      = reValue(`(?m)^running on [^:]+:\s*(.+)$`)
	reBootTime       = reValue(`(?m)^boot time:\s*(.+)$`)
	reLastConfigured = reValue(`(?m)^last configured:\s*(.+)$`)
	reConfigFile     = reValue(`(?m)^configuration file:\s*(.+)$`)
	reCPUs           = reValue(`(?m)^CPUs found:\s*(\d+)`)
	reWorkers        = reValue(`(?m)^worker threads:\s*(\d+)`)
	reZones          = reValue(`number of zones:\s*(\d+)\s*(?:\((\d+)\s*automatic\))?`)
	reDebug          = reValue(`(?m)^debug level:\s*(\d+)`)
	reQueryLog       = reValue(`(?m)^query logging is\s*(\w+)`)
	reResponseLog    = reValue(`(?m)^response logging is\s*(\w+)`)
	reMemProf        = reValue(`(?m)^memory profiling is\s*(\w+)`)
	reXfersRunning   = reValue(`(?m)^xfers running:\s*(\d+)`)
	reXfersDeferred  = reValue(`(?m)^xfers deferred:\s*(\d+)`)
	reXfersFirst     = reValue(`(?m)^xfers first refresh:\s*(\d+)`)
	reSOA            = reValue(`(?m)^soa queries in progress:\s*(\d+)`)
	reRecursive      = reValue(`recursive clients:\s*(\d+)/(\d+)/(\d+)`)
	reRecHigh        = reValue(`(?m)^recursive high-water:\s*(\d+)`)
	reTCP            = reValue(`(?i)tcp clients:\s*(\d+)/(\d+)`)
	reTCPHigh        = reValue(`(?m)^TCP high-water:\s*(\d+)`)
)

func firstGroup(re *regexp.Regexp, text string) string {
	m := re.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func firstInt(re *regexp.Regexp, text string) int {
	s := firstGroup(re, text)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func parseStatusTime(re *regexp.Regexp, text string) time.Time {
	s := firstGroup(re, text)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(statusDateLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseOnOff(re *regexp.Regexp, text string) bool {
	return strings.EqualFold(firstGroup(re, text), "ON")
}

func parseActive(re *regexp.Regexp, text string) bool {
	return strings.EqualFold(firstGroup(re, text), "ACTIVE")
}

// ParseStatus parses BIND status text.
func ParseStatus(text string) (*Status, error) {
	st := &Status{RawText: text}
	st.Version = firstGroup(reVersion, text)
	st.RunningOn = firstGroup(reRunningOn, text)
	st.BootTime = parseStatusTime(reBootTime, text)
	st.LastConfigured = parseStatusTime(reLastConfigured, text)
	st.ConfigurationFile = firstGroup(reConfigFile, text)
	st.CPUsFound = firstInt(reCPUs, text)
	st.WorkerThreads = firstInt(reWorkers, text)

	if m := reZones.FindStringSubmatch(text); len(m) >= 2 {
		st.NumberOfZones, _ = strconv.Atoi(m[1])
		if len(m) >= 3 && m[2] != "" {
			st.AutomaticZones, _ = strconv.Atoi(m[2])
		}
	}

	st.DebugLevel = firstInt(reDebug, text)
	st.QueryLogging = parseOnOff(reQueryLog, text)
	st.ResponseLogging = parseOnOff(reResponseLog, text)
	st.MemoryProfilingActive = parseActive(reMemProf, text)
	st.XfersRunning = firstInt(reXfersRunning, text)
	st.XfersDeferred = firstInt(reXfersDeferred, text)
	st.XfersFirstRefresh = firstInt(reXfersFirst, text)
	st.SOAQueriesInProgress = firstInt(reSOA, text)

	if m := reRecursive.FindStringSubmatch(text); len(m) == 4 {
		st.RecursiveClientsCurrent, _ = strconv.Atoi(m[1])
		st.RecursiveClientsSoftLimit, _ = strconv.Atoi(m[2])
		st.RecursiveClientsHardLimit, _ = strconv.Atoi(m[3])
	}
	st.RecursiveHighWater = firstInt(reRecHigh, text)
	if m := reTCP.FindStringSubmatch(text); len(m) == 3 {
		st.TCPClientsCurrent, _ = strconv.Atoi(m[1])
		st.TCPClientsLimit, _ = strconv.Atoi(m[2])
	}
	st.TCPHighWater = firstInt(reTCPHigh, text)
	st.ServerIsUp = strings.Contains(strings.ToLower(text), "server is up and running")
	return st, nil
}
