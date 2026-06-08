package parser

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	utc := time.FixedZone("", 0)
	tests := []struct {
		name    string
		line    string
		want    Entry
		wantErr bool
	}{
		{
			name: "nginx combined",
			line: `192.168.1.10 - - [08/Jun/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"`,
			want: Entry{
				IP:        "192.168.1.10",
				Time:      time.Date(2026, time.June, 8, 13, 55, 36, 0, utc),
				Method:    "GET",
				Path:      "/index.html",
				Protocol:  "HTTP/1.1",
				Status:    200,
				Bytes:     2326,
				Referer:   "https://example.com/",
				UserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
			},
		},
		{
			name: "apache combined with user and offset",
			line: `10.0.0.5 - frank [10/Oct/2025:13:55:36 -0700] "POST /api/login HTTP/2.0" 403 512 "-" "curl/8.4.0"`,
			want: Entry{
				IP:        "10.0.0.5",
				Time:      time.Date(2025, time.October, 10, 13, 55, 36, 0, time.FixedZone("", -7*3600)),
				Method:    "POST",
				Path:      "/api/login",
				Protocol:  "HTTP/2.0",
				Status:    403,
				Bytes:     512,
				Referer:   "",
				UserAgent: "curl/8.4.0",
			},
		},
		{
			name: "dash body bytes and empty fields",
			line: `203.0.113.9 - - [08/Jun/2026:00:00:01 +0000] "HEAD / HTTP/1.1" 301 - "-" "-"`,
			want: Entry{
				IP:       "203.0.113.9",
				Time:     time.Date(2026, time.June, 8, 0, 0, 1, 0, utc),
				Method:   "HEAD",
				Path:     "/",
				Protocol: "HTTP/1.1",
				Status:   301,
				Bytes:    0,
			},
		},
		{
			name: "malformed request line",
			line: `198.51.100.7 - - [08/Jun/2026:09:10:11 +0000] "GET" 400 0 "-" "sqlmap/1.7"`,
			want: Entry{
				IP:        "198.51.100.7",
				Time:      time.Date(2026, time.June, 8, 9, 10, 11, 0, utc),
				Method:    "",
				Path:      "GET",
				Protocol:  "",
				Status:    400,
				Bytes:     0,
				UserAgent: "sqlmap/1.7",
			},
		},
		{
			name:    "garbage",
			line:    "this is not a log line",
			wantErr: true,
		},
		{
			name:    "blank",
			line:    "   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Time.Equal(tt.want.Time) {
				t.Errorf("time = %v, want %v", got.Time, tt.want.Time)
			}
			got.Time, tt.want.Time = time.Time{}, time.Time{}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
