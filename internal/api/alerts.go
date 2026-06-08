package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"seclog/internal/store"
)

type alertsResponse struct {
	Alerts []store.Alert `json:"alerts"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) {
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

	f := store.AlertFilter{
		Severity: r.URL.Query().Get("severity"),
		Rule:     r.URL.Query().Get("rule"),
		IP:       r.URL.Query().Get("ip"),
		Limit:    limit,
		Offset:   offset,
	}
	alerts, total, err := a.store.ListAlerts(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alertsResponse{Alerts: alerts, Total: total, Limit: limit, Offset: offset})
}

func (a *API) ipSummary(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	sum, err := a.store.IPSummary(r.Context(), ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}
