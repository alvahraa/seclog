package detect

import (
	"context"
	"log/slog"
	"time"

	"seclog/internal/store"
)

// Engine periodically evaluates rules over newly ingested events and persists
// the resulting alerts. It tracks a watermark (the highest event id it has
// processed) so each event is only considered once.
type Engine struct {
	store     *store.Store
	cfg       Config
	interval  time.Duration
	lookback  time.Duration
	dedupe    time.Duration
	watermark int64
	log       *slog.Logger
}

func NewEngine(s *store.Store, cfg Config, interval time.Duration, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Engine{
		store:    s,
		cfg:      cfg,
		interval: interval,
		lookback: 15 * time.Minute,
		dedupe:   10 * time.Minute,
		log:      log,
	}
}

// Run blocks until ctx is cancelled, evaluating rules on each tick.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	e.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runOnce(ctx)
		}
	}
}

func (e *Engine) runOnce(ctx context.Context) {
	newEvents, err := e.store.EventsSince(ctx, e.watermark, 20000)
	if err != nil {
		e.log.Error("detect: load new events", "err", err)
		return
	}
	if len(newEvents) == 0 {
		return
	}

	maxID := e.watermark
	since := time.Now().Add(-e.lookback)
	for _, ev := range newEvents {
		if ev.ID > maxID {
			maxID = ev.ID
		}
		// Ingested logs can carry past timestamps (backfill or seeding), so widen
		// the evaluation window to cover them.
		if ev.Time.Before(since) {
			since = ev.Time
		}
	}

	window, err := e.store.EventsInWindow(ctx, since, 50000)
	if err != nil {
		e.log.Error("detect: load window", "err", err)
		return
	}

	created := 0
	for _, c := range Evaluate(window, e.cfg) {
		exists, err := e.store.RecentAlertExists(ctx, c.Rule, c.IP, e.dedupe)
		if err != nil {
			e.log.Error("detect: dedup check", "err", err)
			continue
		}
		if exists {
			continue
		}
		if _, err := e.store.InsertAlert(ctx, store.Alert{
			Rule: c.Rule, Severity: c.Severity, IP: c.IP, Title: c.Title,
			Detail: c.Detail, Count: c.Count, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
		}); err != nil {
			e.log.Error("detect: insert alert", "err", err)
			continue
		}
		created++
	}

	e.watermark = maxID
	if created > 0 {
		e.log.Info("detect: raised alerts", "count", created)
	}
}
