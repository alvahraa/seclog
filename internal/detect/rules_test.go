package detect

import (
	"testing"
	"time"

	"seclog/internal/store"
)

var base = time.Date(2026, time.June, 8, 12, 0, 0, 0, time.UTC)

func ev(ip string, offset time.Duration, status int, path, ua string) store.Event {
	return store.Event{IP: ip, Time: base.Add(offset), Method: "GET", Path: path, Status: status, UserAgent: ua}
}

// candidate returns the candidate for a rule/ip from a result set, if present.
func candidate(cands []Candidate, rule, ip string) (Candidate, bool) {
	for _, c := range cands {
		if c.Rule == rule && c.IP == ip {
			return c, true
		}
	}
	return Candidate{}, false
}

func TestEvaluate(t *testing.T) {
	cfg := DefaultConfig()
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

	tests := []struct {
		name      string
		events    []store.Event
		wantRule  string
		wantIP    string
		wantHit   bool
		wantSever string
	}{
		{
			name: "auth failures over limit",
			events: []store.Event{
				ev("198.51.100.1", 0, 401, "/login", browser),
				ev("198.51.100.1", time.Second, 401, "/login", browser),
				ev("198.51.100.1", 2*time.Second, 403, "/login", browser),
				ev("198.51.100.1", 3*time.Second, 401, "/login", browser),
				ev("198.51.100.1", 4*time.Second, 401, "/login", browser),
			},
			wantRule: RuleAuthFailures, wantIP: "198.51.100.1", wantHit: true, wantSever: SeverityMedium,
		},
		{
			name: "auth failures under limit",
			events: []store.Event{
				ev("198.51.100.2", 0, 401, "/login", browser),
				ev("198.51.100.2", time.Second, 401, "/login", browser),
			},
			wantRule: RuleAuthFailures, wantIP: "198.51.100.2", wantHit: false,
		},
		{
			name: "auth failures high severity at double limit",
			events: func() []store.Event {
				var out []store.Event
				for i := 0; i < 10; i++ {
					out = append(out, ev("198.51.100.3", time.Duration(i)*time.Second, 401, "/admin", browser))
				}
				return out
			}(),
			wantRule: RuleAuthFailures, wantIP: "198.51.100.3", wantHit: true, wantSever: SeverityHigh,
		},
		{
			name: "rate spike inside window",
			events: func() []store.Event {
				var out []store.Event
				for i := 0; i < 120; i++ {
					out = append(out, ev("203.0.113.7", time.Duration(i*400)*time.Millisecond, 200, "/", browser))
				}
				return out
			}(),
			wantRule: RuleRateSpike, wantIP: "203.0.113.7", wantHit: true, wantSever: SeverityHigh,
		},
		{
			name: "rate under threshold when spread out",
			events: func() []store.Event {
				var out []store.Event
				for i := 0; i < 120; i++ {
					out = append(out, ev("203.0.113.8", time.Duration(i*2)*time.Second, 200, "/", browser))
				}
				return out
			}(),
			wantRule: RuleRateSpike, wantIP: "203.0.113.8", wantHit: false,
		},
		{
			name: "suspicious path secrets is high",
			events: []store.Event{
				ev("192.0.2.10", 0, 404, "/.env", browser),
			},
			wantRule: RuleSuspiciousPath, wantIP: "192.0.2.10", wantHit: true, wantSever: SeverityHigh,
		},
		{
			name: "suspicious path admin is medium",
			events: []store.Event{
				ev("192.0.2.11", 0, 200, "/admin/dashboard", browser),
			},
			wantRule: RuleSuspiciousPath, wantIP: "192.0.2.11", wantHit: true, wantSever: SeverityMedium,
		},
		{
			name: "scanner user agent is high",
			events: []store.Event{
				ev("192.0.2.12", 0, 404, "/", "sqlmap/1.7.2#stable (http://sqlmap.org)"),
			},
			wantRule: RuleSuspiciousUA, wantIP: "192.0.2.12", wantHit: true, wantSever: SeverityHigh,
		},
		{
			name: "empty user agent flagged",
			events: []store.Event{
				ev("192.0.2.13", 0, 200, "/", ""),
			},
			wantRule: RuleSuspiciousUA, wantIP: "192.0.2.13", wantHit: true, wantSever: SeverityMedium,
		},
		{
			name: "normal browser traffic is clean",
			events: []store.Event{
				ev("192.0.2.14", 0, 200, "/", browser),
				ev("192.0.2.14", time.Second, 200, "/about", browser),
			},
			wantRule: RuleSuspiciousUA, wantIP: "192.0.2.14", wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cands := Evaluate(tt.events, cfg)
			got, ok := candidate(cands, tt.wantRule, tt.wantIP)
			if ok != tt.wantHit {
				t.Fatalf("rule %s for %s: hit = %v, want %v (candidates: %+v)", tt.wantRule, tt.wantIP, ok, tt.wantHit, cands)
			}
			if tt.wantHit && tt.wantSever != "" && got.Severity != tt.wantSever {
				t.Errorf("severity = %s, want %s", got.Severity, tt.wantSever)
			}
		})
	}
}

func TestEvaluateMultipleRules(t *testing.T) {
	cfg := DefaultConfig()
	var events []store.Event
	for i := 0; i < 8; i++ {
		events = append(events, ev("203.0.113.66", time.Duration(i)*time.Second, 401, "/wp-login.php", "sqlmap/1.7"))
	}
	cands := Evaluate(events, cfg)

	for _, rule := range []string{RuleAuthFailures, RuleSuspiciousPath, RuleSuspiciousUA} {
		if _, ok := candidate(cands, rule, "203.0.113.66"); !ok {
			t.Errorf("expected rule %s to fire for the host", rule)
		}
	}
}
