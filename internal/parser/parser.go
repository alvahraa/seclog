// Package parser reads access-log lines in the NCSA combined format used by
// both Nginx (combined) and Apache (combined). It returns the structured
// fields the rest of the system stores and analyses.
package parser

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Entry is a single parsed access-log line.
type Entry struct {
	IP        string
	Time      time.Time
	Method    string
	Path      string
	Protocol  string
	Status    int
	Bytes     int64
	Referer   string
	UserAgent string
}

// ErrUnrecognized is returned when a line does not match the combined format.
var ErrUnrecognized = errors.New("parser: line does not match combined log format")

// remote_addr - remote_user [time_local] "request" status body_bytes_sent "referer" "user_agent"
var combined = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`)

const timeLayout = "02/Jan/2006:15:04:05 -0700"

func Parse(line string) (Entry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Entry{}, ErrUnrecognized
	}
	m := combined.FindStringSubmatch(line)
	if m == nil {
		return Entry{}, ErrUnrecognized
	}
	ts, err := time.Parse(timeLayout, m[3])
	if err != nil {
		return Entry{}, ErrUnrecognized
	}
	status, err := strconv.Atoi(m[5])
	if err != nil {
		return Entry{}, ErrUnrecognized
	}
	var bytes int64
	if m[6] != "-" {
		bytes, _ = strconv.ParseInt(m[6], 10, 64)
	}
	method, path, proto := splitRequest(m[4])
	return Entry{
		IP:        m[1],
		Time:      ts.UTC(),
		Method:    method,
		Path:      path,
		Protocol:  proto,
		Status:    status,
		Bytes:     bytes,
		Referer:   cleanDash(m[7]),
		UserAgent: cleanDash(m[8]),
	}, nil
}

// splitRequest breaks the request line ("GET /path HTTP/1.1") into its parts,
// tolerating malformed requests that scanners often send.
func splitRequest(req string) (method, path, proto string) {
	parts := strings.Fields(req)
	switch len(parts) {
	case 0:
		return "", "", ""
	case 1:
		return "", parts[0], ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], parts[2]
	}
}

func cleanDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
