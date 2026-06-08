package api

import (
	"net/http"

	"seclog/internal/store"
)

type eventsResponse struct {
	Events []store.Event `json:"events"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	f := store.EventFilter{
		IP:     r.URL.Query().Get("ip"),
		Status: queryInt(r, "status", 0),
		Path:   r.URL.Query().Get("path"),
		Limit:  limit,
		Offset: offset,
	}
	if t, ok := parseTime(r.URL.Query().Get("from")); ok {
		f.From = t
	}
	if t, ok := parseTime(r.URL.Query().Get("to")); ok {
		f.To = t
	}

	events, total, err := a.store.ListEvents(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, eventsResponse{Events: events, Total: total, Limit: limit, Offset: offset})
}
