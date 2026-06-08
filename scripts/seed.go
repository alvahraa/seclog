// Command seed generates realistic access-log lines and posts them to the
// seclog ingest endpoint so the dashboard has data on first run. It includes a
// handful of lines that intentionally trip the detection rules.
//
// Usage:
//
//	go run scripts/seed.go -url http://localhost:8080 -n 1500
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

var normalIPs = []string{
	"192.168.10.14", "192.168.10.27", "10.4.1.8", "10.4.1.33",
	"172.16.5.5", "172.16.5.91", "85.214.132.117", "91.198.174.192",
	"66.249.66.1", "157.240.22.35", "13.107.21.200", "104.18.32.47",
}

var normalPaths = []string{
	"/", "/index.html", "/about", "/contact", "/pricing",
	"/products", "/products/42", "/products/108", "/blog",
	"/blog/securing-nginx", "/static/app.js", "/static/styles.css",
	"/images/logo.png", "/favicon.ico", "/api/health", "/api/products",
	"/search?q=router", "/login", "/account",
}

var browsers = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
}

func main() {
	url := flag.String("url", "http://localhost:8080", "base URL of the seclog API")
	n := flag.Int("n", 1500, "number of normal log lines to generate")
	batch := flag.Int("batch", 250, "lines per ingest request")
	flag.Parse()

	now := time.Now().UTC()
	lines := make([]string, 0, *n+200)

	for i := 0; i < *n; i++ {
		ip := normalIPs[rand.Intn(len(normalIPs))]
		t := now.Add(-time.Duration(rand.Intn(6*3600)) * time.Second)
		path := normalPaths[rand.Intn(len(normalPaths))]
		lines = append(lines, line(ip, t, "GET", path, weightedStatus(), 200+rand.Intn(8000), "-", browsers[rand.Intn(len(browsers))]))
	}
	lines = append(lines, attackLines(now)...)

	sent := 0
	for start := 0; start < len(lines); start += *batch {
		end := start + *batch
		if end > len(lines) {
			end = len(lines)
		}
		if err := ingest(*url, lines[start:end]); err != nil {
			log.Fatalf("ingest: %v", err)
		}
		sent += end - start
		fmt.Printf("sent %d/%d\n", sent, len(lines))
	}
	fmt.Printf("done: ingested %d lines to %s\n", len(lines), *url)
}

func line(ip string, t time.Time, method, path string, status, bytes int, referer, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"`,
		ip, t.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, bytes, referer, ua)
}

func weightedStatus() int {
	switch r := rand.Intn(100); {
	case r < 82:
		return 200
	case r < 88:
		return 304
	case r < 94:
		return 404
	case r < 97:
		return 301
	case r < 99:
		return 302
	default:
		return 500
	}
}

// attackLines returns log lines that deliberately trigger each detection rule.
func attackLines(now time.Time) []string {
	var out []string

	// Brute force: repeated 401s against a login path from one IP.
	bf := now.Add(-8 * time.Minute)
	for i := 0; i < 14; i++ {
		out = append(out, line("203.0.113.66", bf.Add(time.Duration(i*3)*time.Second),
			"POST", "/wp-login.php", 401, 0, "-", "python-requests/2.31.0"))
	}

	// Scanner sweeping sensitive paths with a tooling user agent.
	scan := now.Add(-15 * time.Minute)
	scanPaths := []string{
		"/.env", "/.git/config", "/phpmyadmin/index.php", "/wp-login.php",
		"/vendor/phpunit/eval-stdin.php", "/config.php", "/.aws/credentials", "/actuator/health",
	}
	for i, p := range scanPaths {
		status := 404
		if i%3 == 0 {
			status = 403
		}
		out = append(out, line("198.51.100.23", scan.Add(time.Duration(i*2)*time.Second),
			"GET", p, status, 0, "-", "sqlmap/1.7.2#stable (http://sqlmap.org)"))
	}

	// Request rate spike: many requests from one IP inside a minute.
	flood := now.Add(-5 * time.Minute)
	for i := 0; i < 130; i++ {
		out = append(out, line("192.0.2.155", flood.Add(time.Duration(i*350)*time.Millisecond),
			"GET", "/", 200, 1500, "-", browsers[0]))
	}

	// Scattered forbidden responses against an admin path.
	for i := 0; i < 6; i++ {
		out = append(out, line("203.0.113.99", now.Add(-time.Duration(20+i)*time.Minute),
			"GET", "/admin", 403, 0, "-", browsers[1]))
	}

	return out
}

func ingest(base string, lines []string) error {
	body, err := json.Marshal(map[string][]string{"lines": lines})
	if err != nil {
		return err
	}
	resp, err := http.Post(base+"/api/ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ingest returned status %d", resp.StatusCode)
	}
	return nil
}
