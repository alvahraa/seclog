// Package store is the SQLite access layer. Times are kept as Unix seconds in
// the database and exposed as time.Time on the Go types.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the database at path. WAL mode lets the read-only
// MCP server share the file with the API server that writes to it.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(normal)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Event is a single access-log record.
type Event struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Time      time.Time `json:"time"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	Bytes     int64     `json:"bytes"`
	Referer   string    `json:"referer"`
	UserAgent string    `json:"user_agent"`
	Parsed    bool      `json:"parsed"`
	Raw       string    `json:"raw,omitempty"`
}

// Alert is a triggered detection.
type Alert struct {
	ID        int64     `json:"id"`
	Rule      string    `json:"rule"`
	Severity  string    `json:"severity"`
	IP        string    `json:"ip"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) InsertEvents(ctx context.Context, events []Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO events (ip, ts, method, path, status, bytes, referer, user_agent, parsed, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, e := range events {
		parsed := 1
		if !e.Parsed {
			parsed = 0
		}
		if _, err := stmt.ExecContext(ctx, e.IP, e.Time.Unix(), e.Method, e.Path,
			e.Status, e.Bytes, e.Referer, e.UserAgent, parsed, e.Raw); err != nil {
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// EventFilter selects and paginates events. Zero-valued fields are ignored.
type EventFilter struct {
	IP     string
	Status int
	Path   string
	From   time.Time
	To     time.Time
	Limit  int
	Offset int
}

const eventColumns = `id, ip, ts, method, path, status, bytes, referer, user_agent, parsed, raw`

func scanEvent(rows *sql.Rows) (Event, error) {
	var e Event
	var ts int64
	var parsed int
	if err := rows.Scan(&e.ID, &e.IP, &ts, &e.Method, &e.Path, &e.Status,
		&e.Bytes, &e.Referer, &e.UserAgent, &parsed, &e.Raw); err != nil {
		return Event{}, err
	}
	e.Time = time.Unix(ts, 0).UTC()
	e.Parsed = parsed != 0
	return e, nil
}

// ListEvents returns a page of events plus the total count matching the filter.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, int, error) {
	var where []string
	var args []any
	if f.IP != "" {
		where = append(where, "ip = ?")
		args = append(args, f.IP)
	}
	if f.Status != 0 {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.Path != "" {
		where = append(where, "path LIKE ?")
		args = append(args, "%"+f.Path+"%")
	}
	if !f.From.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.From.Unix())
	}
	if !f.To.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, f.To.Unix())
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	q := "SELECT " + eventColumns + " FROM events" + clause + " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	events := []Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// EventsSince returns events with id greater than sinceID, oldest first. The
// detection engine uses it as a watermark cursor over new arrivals.
func (s *Store) EventsSince(ctx context.Context, sinceID int64, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+eventColumns+" FROM events WHERE id > ? ORDER BY id ASC LIMIT ?", sinceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectEvents(rows)
}

// EventsInWindow returns events at or after since, oldest first. Detection rules
// run over this slice so rate and auth-failure counts have context.
func (s *Store) EventsInWindow(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+eventColumns+" FROM events WHERE ts >= ? ORDER BY ts ASC LIMIT ?", since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectEvents(rows)
}

func collectEvents(rows *sql.Rows) ([]Event, error) {
	events := []Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) InsertAlert(ctx context.Context, a Alert) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (rule, severity, ip, title, detail, count, first_seen, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Rule, a.Severity, a.IP, a.Title, a.Detail, a.Count,
		a.FirstSeen.Unix(), a.LastSeen.Unix(), time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RecentAlertExists reports whether an alert for the same rule and IP was
// created within the given window. It keeps the engine from re-raising the same
// alert on every tick.
func (s *Store) RecentAlertExists(ctx context.Context, rule, ip string, within time.Duration) (bool, error) {
	cutoff := time.Now().Add(-within).Unix()
	var x int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM alerts WHERE rule = ? AND ip = ? AND created_at >= ? LIMIT 1",
		rule, ip, cutoff).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

type AlertFilter struct {
	Severity string
	Rule     string
	IP       string
	Limit    int
	Offset   int
}

func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]Alert, int, error) {
	var where []string
	var args []any
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.Rule != "" {
		where = append(where, "rule = ?")
		args = append(args, f.Rule)
	}
	if f.IP != "" {
		where = append(where, "ip = ?")
		args = append(args, f.IP)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	q := `SELECT id, rule, severity, ip, title, detail, count, first_seen, last_seen, created_at
		FROM alerts` + clause + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	alerts := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		alerts = append(alerts, a)
	}
	return alerts, total, rows.Err()
}

func scanAlert(rows *sql.Rows) (Alert, error) {
	var a Alert
	var first, last, created int64
	if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.IP, &a.Title, &a.Detail,
		&a.Count, &first, &last, &created); err != nil {
		return Alert{}, err
	}
	a.FirstSeen = time.Unix(first, 0).UTC()
	a.LastSeen = time.Unix(last, 0).UTC()
	a.CreatedAt = time.Unix(created, 0).UTC()
	return a, nil
}
