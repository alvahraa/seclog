package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seclog/internal/store"
)

func newAPI(t *testing.T) (*API, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return New(s), s
}

func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func logLine(ip string, ts time.Time, method, path string, status int, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 0 "-" "%s"`,
		ip, ts.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, ua)
}

func TestIngestAndQuery(t *testing.T) {
	api, _ := newAPI(t)
	router := api.Router()
	now := time.Now().UTC()

	lines := []string{
		logLine("203.0.113.5", now.Add(-5*time.Second), "POST", "/admin/login", 401, "sqlmap/1.7"),
		logLine("203.0.113.5", now.Add(-4*time.Second), "POST", "/admin/login", 401, "sqlmap/1.7"),
		logLine("198.51.100.9", now.Add(-3*time.Second), "GET", "/", 200, "Mozilla/5.0"),
		"this line does not parse",
	}
	body, _ := json.Marshal(map[string][]string{"lines": lines})

	rr := do(t, router, "POST", "/api/ingest", string(body))
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest status = %d, body %s", rr.Code, rr.Body.String())
	}
	var ing ingestResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &ing); err != nil {
		t.Fatalf("decode ingest: %v", err)
	}
	if ing.Received != 4 || ing.Parsed != 3 || ing.Failed != 1 || ing.Stored != 4 {
		t.Fatalf("ingest = %+v, want received 4 parsed 3 failed 1 stored 4", ing)
	}

	rr = do(t, router, "GET", "/api/events?ip=203.0.113.5", "")
	var ev eventsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &ev); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if ev.Total != 2 {
		t.Errorf("events total for IP = %d, want 2", ev.Total)
	}

	rr = do(t, router, "GET", "/api/stats?window=86400", "")
	var st store.Stats
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if st.TotalEvents != 4 {
		t.Errorf("stats total_events = %d, want 4", st.TotalEvents)
	}
	if st.UniqueIPs != 3 {
		t.Errorf("stats unique_ips = %d, want 3 (includes the unparsed empty IP)", st.UniqueIPs)
	}

	rr = do(t, router, "GET", "/api/ips/203.0.113.5", "")
	var sum store.IPSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &sum); err != nil {
		t.Fatalf("decode ip summary: %v", err)
	}
	if sum.TotalEvents != 2 {
		t.Errorf("ip summary total = %d, want 2", sum.TotalEvents)
	}
}

func TestAlertsEndpoint(t *testing.T) {
	api, s := newAPI(t)
	router := api.Router()
	now := time.Now().UTC()

	if _, err := s.InsertAlert(t.Context(), store.Alert{
		Rule: "auth_failures", Severity: "high", IP: "203.0.113.66",
		Title: "Repeated authentication failures", Detail: "12x 401", Count: 12,
		FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("insert alert: %v", err)
	}

	rr := do(t, router, "GET", "/api/alerts?severity=high", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("alerts status = %d", rr.Code)
	}
	var resp alertsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode alerts: %v", err)
	}
	if resp.Total != 1 || len(resp.Alerts) != 1 || resp.Alerts[0].IP != "203.0.113.66" {
		t.Fatalf("alerts = %+v, want one high alert for 203.0.113.66", resp)
	}
}

func TestHealthz(t *testing.T) {
	api, _ := newAPI(t)
	rr := do(t, api.Router(), "GET", "/healthz", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ok") {
		t.Fatalf("healthz = %d %s", rr.Code, rr.Body.String())
	}
}
