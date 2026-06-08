package api

import (
	"net/http"
	"time"
)

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	window := queryInt(r, "window", 6*3600)
	if window <= 0 {
		window = 6 * 3600
	}
	bucket := queryInt(r, "bucket", 0)
	if bucket <= 0 {
		bucket = chooseBucket(window)
	}

	to := time.Now().UTC()
	from := to.Add(-time.Duration(window) * time.Second)

	st, err := a.store.Stats(r.Context(), from, to, bucket)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// chooseBucket keeps the number of points on the overview chart reasonable for
// the requested window.
func chooseBucket(window int) int {
	switch {
	case window <= 3600:
		return 60
	case window <= 6*3600:
		return 300
	case window <= 24*3600:
		return 900
	default:
		return 3600
	}
}
