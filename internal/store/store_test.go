package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInsertAndListEvents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, time.June, 8, 12, 0, 0, 0, time.UTC)

	events := []Event{
		{IP: "10.0.0.1", Time: base, Method: "GET", Path: "/", Status: 200, Parsed: true},
		{IP: "10.0.0.2", Time: base.Add(time.Minute), Method: "GET", Path: "/admin", Status: 403, Parsed: true},
		{IP: "10.0.0.1", Time: base.Add(2 * time.Minute), Method: "POST", Path: "/login", Status: 401, Parsed: true},
	}
	n, err := s.InsertEvents(ctx, events)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if n != 3 {
		t.Fatalf("inserted %d, want 3", n)
	}

	all, total, err := s.ListEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("got %d events (total %d), want 3", len(all), total)
	}
	if all[0].Path != "/login" {
		t.Errorf("newest first ordering broken: got %q", all[0].Path)
	}

	byIP, total, err := s.ListEvents(ctx, EventFilter{IP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("list by ip: %v", err)
	}
	if total != 2 || len(byIP) != 2 {
		t.Errorf("ip filter: got %d rows, total %d, want 2 and 2", len(byIP), total)
	}

	byStatus, _, err := s.ListEvents(ctx, EventFilter{Status: 403})
	if err != nil {
		t.Fatalf("list by status: %v", err)
	}
	if len(byStatus) != 1 || byStatus[0].IP != "10.0.0.2" {
		t.Errorf("status filter wrong: %+v", byStatus)
	}
}

func TestStatsAndSummary(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-30 * time.Minute).Truncate(time.Second)

	var events []Event
	for i := 0; i < 10; i++ {
		events = append(events, Event{
			IP: "203.0.113.5", Time: base.Add(time.Duration(i) * time.Second),
			Method: "GET", Path: "/", Status: 200, Parsed: true,
		})
	}
	events = append(events, Event{IP: "203.0.113.6", Time: base, Method: "GET", Path: "/.env", Status: 404, Parsed: true})
	if _, err := s.InsertEvents(ctx, events); err != nil {
		t.Fatalf("insert: %v", err)
	}

	st, err := s.Stats(ctx, time.Now().Add(-time.Hour), time.Now(), 60)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.TotalEvents != 11 {
		t.Errorf("total events = %d, want 11", st.TotalEvents)
	}
	if st.UniqueIPs != 2 {
		t.Errorf("unique ips = %d, want 2", st.UniqueIPs)
	}
	if len(st.TopIPs) == 0 || st.TopIPs[0].IP != "203.0.113.5" {
		t.Errorf("top ip wrong: %+v", st.TopIPs)
	}

	sum, err := s.IPSummary(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.TotalEvents != 10 {
		t.Errorf("summary events = %d, want 10", sum.TotalEvents)
	}
}

func TestAlertDedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := s.InsertAlert(ctx, Alert{
		Rule: "auth_failures", Severity: "high", IP: "198.51.100.9",
		Title: "Repeated authentication failures", Count: 12,
		FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("insert alert: %v", err)
	}

	exists, err := s.RecentAlertExists(ctx, "auth_failures", "198.51.100.9", 10*time.Minute)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if !exists {
		t.Error("expected recent alert to exist")
	}

	exists, err = s.RecentAlertExists(ctx, "rate_spike", "198.51.100.9", 10*time.Minute)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if exists {
		t.Error("did not expect a rate_spike alert")
	}
}
