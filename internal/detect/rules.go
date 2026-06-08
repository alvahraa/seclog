// Package detect holds the detection rules and the background engine that runs
// them over newly ingested events.
package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"seclog/internal/store"
)

const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

const (
	RuleAuthFailures   = "auth_failures"
	RuleRateSpike      = "rate_spike"
	RuleSuspiciousPath = "suspicious_path"
	RuleSuspiciousUA   = "suspicious_user_agent"
)

// Candidate is an alert the rules want to raise. The engine persists it after a
// deduplication check.
type Candidate struct {
	Rule      string
	Severity  string
	IP        string
	Title     string
	Detail    string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type Config struct {
	AuthFailLimit   int
	RateLimit       int
	RateWindow      time.Duration
	SuspiciousPaths []string
	ScannerAgents   []string
}

func DefaultConfig() Config {
	return Config{
		AuthFailLimit: 5,
		RateLimit:     100,
		RateWindow:    time.Minute,
		SuspiciousPaths: []string{
			"/admin", "/wp-login.php", "/wp-admin", "/.env", "/.git",
			"/phpmyadmin", "/xmlrpc.php", "/.aws", "/config.php",
			"/vendor/phpunit", "/actuator", "/server-status", "/.ssh",
		},
		ScannerAgents: []string{
			"sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
			"wpscan", "nuclei", "zgrab", "fuzz", "python-requests", "curl",
			"libwww-perl", "go-http-client",
		},
	}
}

// Evaluate runs every rule over events and returns at most one candidate per
// (rule, ip). It is pure: the engine handles persistence and dedup.
func Evaluate(events []store.Event, cfg Config) []Candidate {
	byIP := map[string][]store.Event{}
	for _, e := range events {
		byIP[e.IP] = append(byIP[e.IP], e)
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	var out []Candidate
	for _, ip := range ips {
		evs := byIP[ip]
		if c, ok := authFailures(ip, evs, cfg); ok {
			out = append(out, c)
		}
		if c, ok := rateSpike(ip, evs, cfg); ok {
			out = append(out, c)
		}
		if c, ok := suspiciousPaths(ip, evs, cfg); ok {
			out = append(out, c)
		}
		if c, ok := suspiciousUA(ip, evs, cfg); ok {
			out = append(out, c)
		}
	}
	return out
}

func authFailures(ip string, evs []store.Event, cfg Config) (Candidate, bool) {
	var hits []store.Event
	for _, e := range evs {
		if e.Status == 401 || e.Status == 403 {
			hits = append(hits, e)
		}
	}
	if len(hits) < cfg.AuthFailLimit {
		return Candidate{}, false
	}
	first, last := timeRange(hits)
	sev := SeverityMedium
	if len(hits) >= cfg.AuthFailLimit*2 {
		sev = SeverityHigh
	}
	detail := fmt.Sprintf("%d responses with status 401/403 across paths: %s",
		len(hits), strings.Join(distinctPaths(hits, 5), ", "))
	return Candidate{
		Rule: RuleAuthFailures, Severity: sev, IP: ip,
		Title: "Repeated authentication failures", Detail: detail,
		Count: len(hits), FirstSeen: first, LastSeen: last,
	}, true
}

func rateSpike(ip string, evs []store.Event, cfg Config) (Candidate, bool) {
	if len(evs) < cfg.RateLimit {
		return Candidate{}, false
	}
	sorted := make([]store.Event, len(evs))
	copy(sorted, evs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Time.Before(sorted[j].Time) })

	best, lo := 0, 0
	var bestStart, bestEnd time.Time
	for hi := range sorted {
		for sorted[hi].Time.Sub(sorted[lo].Time) >= cfg.RateWindow {
			lo++
		}
		if c := hi - lo + 1; c > best {
			best = c
			bestStart, bestEnd = sorted[lo].Time, sorted[hi].Time
		}
	}
	if best < cfg.RateLimit {
		return Candidate{}, false
	}
	detail := fmt.Sprintf("%d requests within %s (peak %s to %s)",
		best, cfg.RateWindow, bestStart.Format(time.RFC3339), bestEnd.Format(time.RFC3339))
	return Candidate{
		Rule: RuleRateSpike, Severity: SeverityHigh, IP: ip,
		Title: "Request rate spike", Detail: detail,
		Count: best, FirstSeen: bestStart, LastSeen: bestEnd,
	}, true
}

func suspiciousPaths(ip string, evs []store.Event, cfg Config) (Candidate, bool) {
	matched := map[string]bool{}
	var hits []store.Event
	for _, e := range evs {
		if pat, ok := matchPrefix(e.Path, cfg.SuspiciousPaths); ok {
			matched[pat] = true
			hits = append(hits, e)
		}
	}
	if len(hits) == 0 {
		return Candidate{}, false
	}
	first, last := timeRange(hits)
	patterns := sortedKeys(matched)
	sev := SeverityMedium
	if matched["/.env"] || matched["/.git"] || matched["/.aws"] || matched["/.ssh"] {
		sev = SeverityHigh
	}
	detail := fmt.Sprintf("%d requests to sensitive paths: %s", len(hits), strings.Join(patterns, ", "))
	return Candidate{
		Rule: RuleSuspiciousPath, Severity: sev, IP: ip,
		Title: "Access to sensitive paths", Detail: detail,
		Count: len(hits), FirstSeen: first, LastSeen: last,
	}, true
}

func suspiciousUA(ip string, evs []store.Event, cfg Config) (Candidate, bool) {
	matched := map[string]bool{}
	var hits []store.Event
	empty := false
	for _, e := range evs {
		ua := strings.TrimSpace(e.UserAgent)
		if ua == "" {
			empty = true
			hits = append(hits, e)
			continue
		}
		if name, ok := matchContains(ua, cfg.ScannerAgents); ok {
			matched[name] = true
			hits = append(hits, e)
		}
	}
	if len(hits) == 0 {
		return Candidate{}, false
	}
	first, last := timeRange(hits)
	names := sortedKeys(matched)
	if empty {
		names = append([]string{"(empty)"}, names...)
	}
	sev := SeverityMedium
	if matched["sqlmap"] || matched["nikto"] || matched["nuclei"] || matched["wpscan"] {
		sev = SeverityHigh
	}
	detail := fmt.Sprintf("%d requests with suspicious user agents: %s", len(hits), strings.Join(names, ", "))
	return Candidate{
		Rule: RuleSuspiciousUA, Severity: sev, IP: ip,
		Title: "Suspicious user agent", Detail: detail,
		Count: len(hits), FirstSeen: first, LastSeen: last,
	}, true
}

func matchPrefix(path string, list []string) (string, bool) {
	lp := strings.ToLower(path)
	for _, s := range list {
		if strings.HasPrefix(lp, s) {
			return s, true
		}
	}
	return "", false
}

func matchContains(ua string, list []string) (string, bool) {
	lua := strings.ToLower(ua)
	for _, s := range list {
		if strings.Contains(lua, s) {
			return s, true
		}
	}
	return "", false
}

func timeRange(evs []store.Event) (first, last time.Time) {
	for i, e := range evs {
		if i == 0 || e.Time.Before(first) {
			first = e.Time
		}
		if i == 0 || e.Time.After(last) {
			last = e.Time
		}
	}
	return first, last
}

func distinctPaths(evs []store.Event, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range evs {
		if seen[e.Path] {
			continue
		}
		seen[e.Path] = true
		out = append(out, e.Path)
		if len(out) >= max {
			break
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
