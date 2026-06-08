package store

import (
	"context"
	"time"
)

type TimeBucket struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

type StatusCount struct {
	Status int   `json:"status"`
	Count  int64 `json:"count"`
}

type PathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// Stats is the summary used by the overview page and the get_stats MCP tool.
type Stats struct {
	From          time.Time     `json:"from"`
	To            time.Time     `json:"to"`
	BucketSeconds int           `json:"bucket_seconds"`
	TotalEvents   int64         `json:"total_events"`
	TotalAlerts   int64         `json:"total_alerts"`
	UniqueIPs     int64         `json:"unique_ips"`
	Series        []TimeBucket  `json:"series"`
	TopIPs        []IPCount     `json:"top_ips"`
	Statuses      []StatusCount `json:"statuses"`
}

func (s *Store) Stats(ctx context.Context, from, to time.Time, bucketSeconds int) (Stats, error) {
	if bucketSeconds <= 0 {
		bucketSeconds = 300
	}
	fromU, toU := from.Unix(), to.Unix()
	out := Stats{From: from.UTC(), To: to.UTC(), BucketSeconds: bucketSeconds}

	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*), COUNT(DISTINCT ip) FROM events WHERE ts BETWEEN ? AND ?",
		fromU, toU).Scan(&out.TotalEvents, &out.UniqueIPs); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM alerts WHERE created_at BETWEEN ? AND ?",
		fromU, toU).Scan(&out.TotalAlerts); err != nil {
		return out, err
	}

	buckets := map[int64]int64{}
	rows, err := s.db.QueryContext(ctx,
		"SELECT (ts/?)*? AS b, COUNT(*) FROM events WHERE ts BETWEEN ? AND ? GROUP BY b",
		bucketSeconds, bucketSeconds, fromU, toU)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var b, c int64
		if err := rows.Scan(&b, &c); err != nil {
			rows.Close()
			return out, err
		}
		buckets[b] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	step := int64(bucketSeconds)
	start := (fromU / step) * step
	out.Series = []TimeBucket{}
	for b := start; b <= toU; b += step {
		out.Series = append(out.Series, TimeBucket{Time: time.Unix(b, 0).UTC(), Count: buckets[b]})
	}

	out.TopIPs, err = s.topIPs(ctx, fromU, toU, 10)
	if err != nil {
		return out, err
	}
	out.Statuses, err = s.statusBreakdown(ctx, fromU, toU)
	if err != nil {
		return out, err
	}
	return out, nil
}

func (s *Store) topIPs(ctx context.Context, fromU, toU int64, limit int) ([]IPCount, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT ip, COUNT(*) c FROM events WHERE ts BETWEEN ? AND ? GROUP BY ip ORDER BY c DESC, ip LIMIT ?",
		fromU, toU, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPCount{}
	for rows.Next() {
		var ic IPCount
		if err := rows.Scan(&ic.IP, &ic.Count); err != nil {
			return nil, err
		}
		out = append(out, ic)
	}
	return out, rows.Err()
}

func (s *Store) statusBreakdown(ctx context.Context, fromU, toU int64) ([]StatusCount, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT status, COUNT(*) c FROM events WHERE ts BETWEEN ? AND ? GROUP BY status ORDER BY status",
		fromU, toU)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StatusCount{}
	for rows.Next() {
		var sc StatusCount
		if err := rows.Scan(&sc.Status, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// IPSummary is the per-IP detail used by the dashboard and the get_ip_summary
// MCP tool.
type IPSummary struct {
	IP          string        `json:"ip"`
	TotalEvents int64         `json:"total_events"`
	FirstSeen   time.Time     `json:"first_seen"`
	LastSeen    time.Time     `json:"last_seen"`
	Statuses    []StatusCount `json:"statuses"`
	TopPaths    []PathCount   `json:"top_paths"`
	Alerts      []Alert       `json:"alerts"`
}

func (s *Store) IPSummary(ctx context.Context, ip string) (IPSummary, error) {
	out := IPSummary{IP: ip, Statuses: []StatusCount{}, TopPaths: []PathCount{}, Alerts: []Alert{}}

	var first, last int64
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0) FROM events WHERE ip = ?",
		ip).Scan(&out.TotalEvents, &first, &last); err != nil {
		return out, err
	}
	if out.TotalEvents > 0 {
		out.FirstSeen = time.Unix(first, 0).UTC()
		out.LastSeen = time.Unix(last, 0).UTC()
	}

	statusRows, err := s.db.QueryContext(ctx,
		"SELECT status, COUNT(*) c FROM events WHERE ip = ? GROUP BY status ORDER BY status", ip)
	if err != nil {
		return out, err
	}
	for statusRows.Next() {
		var sc StatusCount
		if err := statusRows.Scan(&sc.Status, &sc.Count); err != nil {
			statusRows.Close()
			return out, err
		}
		out.Statuses = append(out.Statuses, sc)
	}
	statusRows.Close()
	if err := statusRows.Err(); err != nil {
		return out, err
	}

	pathRows, err := s.db.QueryContext(ctx,
		"SELECT path, COUNT(*) c FROM events WHERE ip = ? GROUP BY path ORDER BY c DESC, path LIMIT 10", ip)
	if err != nil {
		return out, err
	}
	for pathRows.Next() {
		var pc PathCount
		if err := pathRows.Scan(&pc.Path, &pc.Count); err != nil {
			pathRows.Close()
			return out, err
		}
		out.TopPaths = append(out.TopPaths, pc)
	}
	pathRows.Close()
	if err := pathRows.Err(); err != nil {
		return out, err
	}

	alerts, _, err := s.ListAlerts(ctx, AlertFilter{IP: ip, Limit: 50})
	if err != nil {
		return out, err
	}
	out.Alerts = alerts
	return out, nil
}
