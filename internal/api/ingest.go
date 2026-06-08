package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"seclog/internal/parser"
	"seclog/internal/store"
)

type ingestResponse struct {
	Received int `json:"received"`
	Stored   int `json:"stored"`
	Parsed   int `json:"parsed"`
	Failed   int `json:"failed"`
}

// ingest accepts a batch of raw log lines, either as JSON {"lines": [...]} or as
// a text/plain body with one line per row. Unparseable lines are stored with
// parsed=false so nothing is silently dropped.
func (a *API) ingest(w http.ResponseWriter, r *http.Request) {
	lines, err := readLines(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now().UTC()
	events := make([]store.Event, 0, len(lines))
	var parsed, failed int
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		entry, perr := parser.Parse(ln)
		if perr != nil {
			failed++
			events = append(events, store.Event{Time: now, Parsed: false, Raw: ln})
			continue
		}
		parsed++
		events = append(events, store.Event{
			IP:        entry.IP,
			Time:      entry.Time,
			Method:    entry.Method,
			Path:      entry.Path,
			Status:    entry.Status,
			Bytes:     entry.Bytes,
			Referer:   entry.Referer,
			UserAgent: entry.UserAgent,
			Parsed:    true,
		})
	}

	stored, err := a.store.InsertEvents(r.Context(), events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store events: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ingestResponse{
		Received: len(lines), Stored: stored, Parsed: parsed, Failed: failed,
	})
}

func readLines(r *http.Request) ([]string, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Lines []string `json:"lines"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		return body.Lines, nil
	}

	var lines []string
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
