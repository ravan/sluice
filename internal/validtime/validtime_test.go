package validtime

import (
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

	ptr := func(tm time.Time) *time.Time { return &tm }

	tests := []struct {
		name         string
		guard        Guard
		t            *time.Time
		wantTime     time.Time
		wantFallback bool
	}{
		{
			name:         "nil falls back to now",
			guard:        Default(),
			t:            nil,
			wantTime:     now,
			wantFallback: true,
		},
		{
			name:         "default guard valid",
			guard:        Default(),
			t:            ptr(time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC)),
			wantTime:     time.Date(2021, 12, 10, 10, 15, 0, 0, time.UTC),
			wantFallback: false,
		},
		{
			name:         "before floor falls back",
			guard:        Default(),
			t:            ptr(time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC)),
			wantTime:     now,
			wantFallback: true,
		},
		{
			name:         "exactly floor is inclusive",
			guard:        Default(),
			t:            ptr(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)),
			wantTime:     time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
			wantFallback: false,
		},
		{
			name:         "beyond skew falls back",
			guard:        Default(),
			t:            ptr(now.Add(10 * time.Minute)),
			wantTime:     now,
			wantFallback: true,
		},
		{
			name:         "within skew valid",
			guard:        Default(),
			t:            ptr(now.Add(2 * time.Minute)),
			wantTime:     now.Add(2 * time.Minute),
			wantFallback: false,
		},
		{
			name:         "custom floor rejects otherwise-valid date",
			guard:        Guard{Floor: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), Skew: 5 * time.Minute},
			t:            ptr(time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC)),
			wantTime:     now,
			wantFallback: true,
		},
		{
			name:         "non-UTC normalized to UTC",
			guard:        Default(),
			t:            ptr(time.Date(2021, 12, 10, 10, 15, 0, 0, time.FixedZone("x", 3600))),
			wantTime:     time.Date(2021, 12, 10, 9, 15, 0, 0, time.UTC),
			wantFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTime, gotFallback := tt.guard.Resolve(tt.t, now)
			if !gotTime.Equal(tt.wantTime) {
				t.Errorf("time = %v, want %v", gotTime, tt.wantTime)
			}
			if gotFallback != tt.wantFallback {
				t.Errorf("fallback = %v, want %v", gotFallback, tt.wantFallback)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	d := Default()
	if !d.Floor.Equal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Floor = %v, want 2000-01-01T00:00:00Z", d.Floor)
	}
	if d.Skew != 5*time.Minute {
		t.Errorf("Skew = %v, want 5m", d.Skew)
	}
}
