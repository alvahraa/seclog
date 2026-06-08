// Package mcp exposes the dashboard data to an LLM through Model Context
// Protocol tools. Each tool is a thin wrapper over the store layer so an agent
// can pull exactly the slice of data it needs.
package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"seclog/internal/store"
)

// New builds an MCP server with the seclog tools registered.
func New(s *store.Store) *mcpsdk.Server {
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "seclog",
		Version: "0.1.0",
	}, nil)

	h := &handlers{store: s}

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_recent_alerts",
		Description: "List the most recent detection alerts, newest first. Optionally filter by severity (low, medium, high).",
	}, h.listRecentAlerts)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "query_events",
		Description: "Query stored access-log events. Filter by source ip, HTTP status, path substring, and an RFC3339 time range. Returns matching events newest first.",
	}, h.queryEvents)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "get_ip_summary",
		Description: "Summarise one source IP: total requests, first and last seen, status-code breakdown, top paths, and any alerts raised against it.",
	}, h.getIPSummary)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "get_stats",
		Description: "Aggregate traffic over a recent window: totals, request-volume buckets, top source IPs, and status-code breakdown.",
	}, h.getStats)

	return srv
}

type handlers struct {
	store *store.Store
}

type listAlertsInput struct {
	Limit    int    `json:"limit,omitempty" jsonschema:"maximum number of alerts to return (default 20)"`
	Severity string `json:"severity,omitempty" jsonschema:"optional severity filter: low, medium, or high"`
}

type listAlertsOutput struct {
	Alerts []store.Alert `json:"alerts"`
	Count  int           `json:"count"`
}

func (h *handlers) listRecentAlerts(ctx context.Context, _ *mcpsdk.CallToolRequest, in listAlertsInput) (*mcpsdk.CallToolResult, listAlertsOutput, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	alerts, _, err := h.store.ListAlerts(ctx, store.AlertFilter{Severity: in.Severity, Limit: limit})
	if err != nil {
		return nil, listAlertsOutput{}, err
	}
	out := listAlertsOutput{Alerts: alerts, Count: len(alerts)}
	return text(summariseAlerts(alerts)), out, nil
}

type queryEventsInput struct {
	IP     string `json:"ip,omitempty" jsonschema:"filter by exact source IP"`
	Status int    `json:"status,omitempty" jsonschema:"filter by HTTP status code"`
	Path   string `json:"path,omitempty" jsonschema:"filter by path substring"`
	From   string `json:"from,omitempty" jsonschema:"lower time bound, RFC3339"`
	To     string `json:"to,omitempty" jsonschema:"upper time bound, RFC3339"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum events to return (default 50, max 500)"`
}

type queryEventsOutput struct {
	Events []store.Event `json:"events"`
	Total  int           `json:"total"`
}

func (h *handlers) queryEvents(ctx context.Context, _ *mcpsdk.CallToolRequest, in queryEventsInput) (*mcpsdk.CallToolResult, queryEventsOutput, error) {
	f := store.EventFilter{IP: in.IP, Status: in.Status, Path: in.Path, Limit: in.Limit}
	if in.From != "" {
		t, err := time.Parse(time.RFC3339, in.From)
		if err != nil {
			return nil, queryEventsOutput{}, fmt.Errorf("invalid 'from' time: %w", err)
		}
		f.From = t
	}
	if in.To != "" {
		t, err := time.Parse(time.RFC3339, in.To)
		if err != nil {
			return nil, queryEventsOutput{}, fmt.Errorf("invalid 'to' time: %w", err)
		}
		f.To = t
	}
	events, total, err := h.store.ListEvents(ctx, f)
	if err != nil {
		return nil, queryEventsOutput{}, err
	}
	out := queryEventsOutput{Events: events, Total: total}
	return text(fmt.Sprintf("Returned %d of %d matching events.", len(events), total)), out, nil
}

type ipSummaryInput struct {
	IP string `json:"ip" jsonschema:"the IP address to summarise"`
}

func (h *handlers) getIPSummary(ctx context.Context, _ *mcpsdk.CallToolRequest, in ipSummaryInput) (*mcpsdk.CallToolResult, store.IPSummary, error) {
	if strings.TrimSpace(in.IP) == "" {
		return nil, store.IPSummary{}, fmt.Errorf("ip is required")
	}
	sum, err := h.store.IPSummary(ctx, in.IP)
	if err != nil {
		return nil, store.IPSummary{}, err
	}
	return text(summariseIP(sum)), sum, nil
}

type statsInput struct {
	WindowSeconds int `json:"window_seconds,omitempty" jsonschema:"lookback window in seconds (default 21600 = 6h)"`
	BucketSeconds int `json:"bucket_seconds,omitempty" jsonschema:"bucket size in seconds (default derived from the window)"`
}

func (h *handlers) getStats(ctx context.Context, _ *mcpsdk.CallToolRequest, in statsInput) (*mcpsdk.CallToolResult, store.Stats, error) {
	window := in.WindowSeconds
	if window <= 0 {
		window = 6 * 3600
	}
	bucket := in.BucketSeconds
	if bucket <= 0 {
		bucket = window / 72
	}
	if bucket <= 0 {
		bucket = 60
	}
	to := time.Now().UTC()
	from := to.Add(-time.Duration(window) * time.Second)
	st, err := h.store.Stats(ctx, from, to, bucket)
	if err != nil {
		return nil, store.Stats{}, err
	}
	return text(summariseStats(st)), st, nil
}

func text(s string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: s}},
	}
}

func summariseAlerts(alerts []store.Alert) string {
	if len(alerts) == 0 {
		return "No alerts."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d alert(s):\n", len(alerts))
	for _, a := range alerts {
		fmt.Fprintf(&b, "- [%s] %s for %s (%dx, last %s)\n",
			a.Severity, a.Title, a.IP, a.Count, a.LastSeen.Format(time.RFC3339))
	}
	return b.String()
}

func summariseIP(s store.IPSummary) string {
	if s.TotalEvents == 0 {
		return fmt.Sprintf("No events recorded for %s.", s.IP)
	}
	return fmt.Sprintf("%s: %d requests between %s and %s, %d alert(s).",
		s.IP, s.TotalEvents, s.FirstSeen.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339), len(s.Alerts))
}

func summariseStats(s store.Stats) string {
	return fmt.Sprintf("%d events from %d unique IPs and %d alerts between %s and %s.",
		s.TotalEvents, s.UniqueIPs, s.TotalAlerts,
		s.From.Format(time.RFC3339), s.To.Format(time.RFC3339))
}
