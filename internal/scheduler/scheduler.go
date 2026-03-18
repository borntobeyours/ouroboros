// Package scheduler provides cron-based recurring scan scheduling.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScheduleConfig describes a recurring scan job.
type ScheduleConfig struct {
	ID       int64  `json:"id"`
	Target   string `json:"target"`
	Profile  string `json:"profile"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Cron     string `json:"cron"`
	Webhook  string `json:"webhook,omitempty"`
	// Internal: computed from Cron at load time.
	schedule cronSchedule
}

// Runner executes scheduled scans.
// It delegates the actual scan to a callback so the scheduler package stays
// independent of the engine package (avoiding import cycles).
type Runner struct {
	db      *sql.DB
	scanFn  ScanFunc
	mu      sync.Mutex
	jobs    map[int64]*jobState
	stopCh  chan struct{}
	stopped bool
}

// ScanFunc is called by the scheduler to execute a scan.
// It receives the ScheduleConfig and returns the new session ID (or "" on error).
type ScanFunc func(cfg ScheduleConfig) (sessionID string, err error)

type jobState struct {
	cfg    ScheduleConfig
	cancel context.CancelFunc
}

// NewRunner creates a scheduler that uses db for persistent job storage and
// calls scanFn whenever a job fires.
func NewRunner(db *sql.DB, scanFn ScanFunc) *Runner {
	return &Runner{
		db:     db,
		scanFn: scanFn,
		jobs:   make(map[int64]*jobState),
		stopCh: make(chan struct{}),
	}
}

// Start launches all persisted schedules in the background and blocks until
// ctx is cancelled or Stop() is called.
func (r *Runner) Start(ctx context.Context) error {
	schedules, err := r.ListSchedules()
	if err != nil {
		return fmt.Errorf("load schedules: %w", err)
	}
	for _, s := range schedules {
		r.startJob(ctx, s)
	}
	<-ctx.Done()
	return nil
}

// Stop cancels all running jobs.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.stopped = true
	for _, js := range r.jobs {
		js.cancel()
	}
	close(r.stopCh)
}

func (r *Runner) startJob(ctx context.Context, cfg ScheduleConfig) {
	jctx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.jobs[cfg.ID] = &jobState{cfg: cfg, cancel: cancel}
	r.mu.Unlock()

	go func() {
		for {
			next := cfg.schedule.Next(time.Now())
			wait := time.Until(next)
			if wait < 0 {
				wait = 0
			}
			select {
			case <-jctx.Done():
				return
			case <-time.After(wait):
				_, _ = r.scanFn(cfg)
			}
		}
	}()
}

// ──────────────────────────────────────────────────────
// CRUD — delegates to the shared SQLite db passed in
// ──────────────────────────────────────────────────────

// AddSchedule persists a new schedule and starts it if the runner is live.
func (r *Runner) AddSchedule(ctx context.Context, cfg ScheduleConfig) (int64, error) {
	sched, err := parseCron(cfg.Cron)
	if err != nil {
		return 0, fmt.Errorf("invalid cron expression %q: %w", cfg.Cron, err)
	}
	cfg.schedule = sched

	res, err := r.db.ExecContext(ctx,
		`INSERT INTO schedules (target, profile, provider, model, cron, webhook) VALUES (?,?,?,?,?,?)`,
		cfg.Target, cfg.Profile, cfg.Provider, cfg.Model, cfg.Cron, cfg.Webhook,
	)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	cfg.ID = id

	r.mu.Lock()
	alive := !r.stopped
	r.mu.Unlock()
	if alive {
		r.startJob(ctx, cfg)
	}
	return id, nil
}

// RemoveSchedule stops and deletes a schedule by ID.
func (r *Runner) RemoveSchedule(id int64) error {
	r.mu.Lock()
	if js, ok := r.jobs[id]; ok {
		js.cancel()
		delete(r.jobs, id)
	}
	r.mu.Unlock()

	_, err := r.db.Exec(`DELETE FROM schedules WHERE id = ?`, id)
	return err
}

// ListSchedules returns all persisted schedules.
func (r *Runner) ListSchedules() ([]ScheduleConfig, error) {
	rows, err := r.db.Query(
		`SELECT id, target, profile, provider, model, cron, COALESCE(webhook,'') FROM schedules ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScheduleConfig
	for rows.Next() {
		var c ScheduleConfig
		if err := rows.Scan(&c.ID, &c.Target, &c.Profile, &c.Provider, &c.Model, &c.Cron, &c.Webhook); err != nil {
			return nil, err
		}
		sched, err := parseCron(c.Cron)
		if err == nil {
			c.schedule = sched
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ──────────────────────────────────────────────────────
// Cron expression parser (pure Go, no external deps)
// ──────────────────────────────────────────────────────
// Supports:
//   @hourly, @daily, @weekly, @monthly, @yearly/@annually
//   Standard 5-field cron: minute hour day-of-month month day-of-week
//   Each field: * | number | number-number | */step | number/step

type cronSchedule struct {
	minutes  []int // 0-59
	hours    []int // 0-23
	days     []int // 1-31
	months   []int // 1-12
	weekdays []int // 0-6 (0=Sunday)
}

func parseCron(expr string) (cronSchedule, error) {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "@yearly", "@annually":
		return parseCron("0 0 1 1 *")
	case "@monthly":
		return parseCron("0 0 1 * *")
	case "@weekly":
		return parseCron("0 0 * * 0")
	case "@daily", "@midnight":
		return parseCron("0 0 * * *")
	case "@hourly":
		return parseCron("0 * * * *")
	}

	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return cronSchedule{}, fmt.Errorf("expected 5 fields, got %d", len(fields))
	}

	minutes, err := expandField(fields[0], 0, 59)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("minute field: %w", err)
	}
	hours, err := expandField(fields[1], 0, 23)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("hour field: %w", err)
	}
	days, err := expandField(fields[2], 1, 31)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("day-of-month field: %w", err)
	}
	months, err := expandField(fields[3], 1, 12)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("month field: %w", err)
	}
	weekdays, err := expandField(fields[4], 0, 6)
	if err != nil {
		return cronSchedule{}, fmt.Errorf("day-of-week field: %w", err)
	}

	return cronSchedule{
		minutes:  minutes,
		hours:    hours,
		days:     days,
		months:   months,
		weekdays: weekdays,
	}, nil
}

// expandField expands a cron field into a sorted list of integers.
func expandField(field string, min, max int) ([]int, error) {
	if field == "*" {
		vals := make([]int, max-min+1)
		for i := range vals {
			vals[i] = min + i
		}
		return vals, nil
	}

	set := map[int]struct{}{}

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "/") {
			// step: */N or start/N
			ps := strings.SplitN(part, "/", 2)
			step, err := strconv.Atoi(ps[1])
			if err != nil || step < 1 {
				return nil, fmt.Errorf("invalid step in %q", part)
			}
			start := min
			end := max
			if ps[0] != "*" {
				start, err = strconv.Atoi(ps[0])
				if err != nil {
					return nil, fmt.Errorf("invalid range start in %q", part)
				}
			}
			for v := start; v <= end; v += step {
				set[v] = struct{}{}
			}
		} else if strings.Contains(part, "-") {
			// range: low-high
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for v := lo; v <= hi; v++ {
				set[v] = struct{}{}
			}
		} else {
			v, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", part)
			}
			set[v] = struct{}{}
		}
	}

	// Validate and sort
	vals := make([]int, 0, len(set))
	for v := range set {
		if v < min || v > max {
			return nil, fmt.Errorf("value %d out of range [%d,%d]", v, min, max)
		}
		vals = append(vals, v)
	}
	sortInts(vals)
	return vals, nil
}

// Next returns the next time after t that matches the schedule.
func (s cronSchedule) Next(t time.Time) time.Time {
	// Round up to the next minute boundary.
	t = t.Add(time.Minute - time.Duration(t.Second())*time.Second - time.Duration(t.Nanosecond())*time.Nanosecond)

	for i := 0; i < 366*24*60; i++ { // guard: max 1 year of minutes
		if !inList(int(t.Month()), s.months) {
			t = t.Add(time.Minute)
			continue
		}
		if !inList(t.Day(), s.days) && !inList(int(t.Weekday()), s.weekdays) {
			t = t.Add(time.Minute)
			continue
		}
		// If day-of-month or day-of-week is "*", both lists will contain all values.
		if !inList(t.Hour(), s.hours) {
			t = t.Add(time.Minute)
			continue
		}
		if !inList(t.Minute(), s.minutes) {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	// Fallback: should never happen with valid cron expressions.
	return t.Add(24 * time.Hour)
}

func inList(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortInts(a []int) {
	// Simple insertion sort — list is always small (<= 60 elements).
	for i := 1; i < len(a); i++ {
		key := a[i]
		j := i - 1
		for j >= 0 && a[j] > key {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = key
	}
}
