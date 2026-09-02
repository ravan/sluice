package validtime

import "time"

// Guard bounds a document's claimed timestamp before it may become valid time
// (§2.4): earlier than Floor, or later than now+Skew, is rejected.
type Guard struct {
	Floor time.Time     // inclusive lower bound (default 2000-01-01T00:00:00Z)
	Skew  time.Duration // future tolerance above now (default 5m)
}

// Default is the guard the CLI and pipeline use when unconfigured.
func Default() Guard {
	return Guard{Floor: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), Skew: 5 * time.Minute}
}

// Resolve maps an optional native assertion timestamp to a valid_from under the
// guard. It returns the resolved UTC time and whether it fell back to now. A nil
// t, a t before Floor, or a t after now+Skew all fall back to now (fallback=true).
// now is assumed UTC (the shell passes time.Now().UTC()).
//
// verbatim exception — the exact boundary logic IS the design decision.
func (g Guard) Resolve(t *time.Time, now time.Time) (time.Time, bool) {
	if t == nil {
		return now, true
	}
	ut := t.UTC()
	if ut.Before(g.Floor) {
		return now, true
	}
	if ut.After(now.Add(g.Skew)) {
		return now, true
	}
	return ut, false
}
