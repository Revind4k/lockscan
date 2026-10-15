// Package osv queries the OSV.dev vulnerability database for a set of package versions.
//
// Lookup is two steps, because /v1/querybatch returns only vulnerability IDs:
//  1. POST /v1/querybatch with every package (chunked to the API's 1000-query limit)
//  2. GET /v1/vulns/{id} for each distinct ID, through a bounded worker pool and an
//     on-disk cache keyed by ID and modified time, so repeat scans make no detail calls.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Revind4k/lockscan/internal/parse"
)

const (
	DefaultBaseURL = "https://api.osv.dev"
	batchLimit     = 1000
)

// Vuln is the subset of the OSV schema lockscan reports on.
type Vuln struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Aliases          []string        `json:"aliases"`
	Modified         string          `json:"modified"`
	Severity         []SeverityEntry `json:"severity"`
	Affected         []Affected      `json:"affected"`
	DatabaseSpecific map[string]any  `json:"database_specific"`
	References       []Reference     `json:"references"`
	// SeverityFrom is set when the rating was borrowed from an alias's record.
	SeverityFrom string `json:"severity_from,omitempty"`
}

type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Finding is one vulnerability affecting one installed package.
type Finding struct {
	Package parse.Package
	Vuln    *Vuln
}

// Client talks to the OSV API. The zero value is not usable; use New.
type Client struct {
	BaseURL  string
	HTTP     *http.Client
	CacheDir string // empty disables the detail cache
	Workers  int
	Retries  int
	// sleep is replaceable so tests don't wait on real backoff.
	sleep func(time.Duration)
}

func New() *Client {
	cache := ""
	if d, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(d, "lockscan")
	}
	return &Client{
		BaseURL:  DefaultBaseURL,
		HTTP:     &http.Client{Timeout: 20 * time.Second},
		CacheDir: cache,
		Workers:  8,
		Retries:  3,
		sleep:    time.Sleep,
	}
}

// Scan returns every known vulnerability for pkgs. Order follows pkgs.
func (c *Client) Scan(ctx context.Context, pkgs []parse.Package) ([]Finding, error) {
	ids, err := c.queryBatch(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	unique := map[string]string{} // id -> modified
	for _, list := range ids {
		for _, v := range list {
			unique[v.ID] = v.Modified
		}
	}
	vulns, err := c.fetchAll(ctx, unique, false)
	if err != nil {
		return nil, err
	}
	if err := c.enrich(ctx, vulns); err != nil {
		return nil, err
	}
	var out []Finding
	for i, list := range ids {
		for _, v := range list {
			out = append(out, Finding{Package: pkgs[i], Vuln: vulns[v.ID]})
		}
	}
	return out, nil
}

type idRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// queryBatch returns, for each package, the IDs of vulnerabilities affecting it.
func (c *Client) queryBatch(ctx context.Context, pkgs []parse.Package) ([][]idRef, error) {
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version   string `json:"version"`
		PageToken string `json:"page_token,omitempty"`
	}
	type result struct {
		Vulns         []idRef `json:"vulns"`
		NextPageToken string  `json:"next_page_token"`
	}

	out := make([][]idRef, len(pkgs))
	for start := 0; start < len(pkgs); start += batchLimit {
		end := min(start+batchLimit, len(pkgs))
		// pending holds indexes (into pkgs) still to query and their page tokens;
		// a package with many vulns comes back paginated and is re-queried alone.
		pending := map[int]string{}
		for i := start; i < end; i++ {
			pending[i] = ""
		}
		for len(pending) > 0 {
			order := make([]int, 0, len(pending))
			qs := make([]query, 0, len(pending))
			for i := start; i < end; i++ {
				tok, ok := pending[i]
				if !ok {
					continue
				}
				var q query
				q.Package.Name, q.Package.Ecosystem = pkgs[i].Name, pkgs[i].Ecosystem
				q.Version, q.PageToken = pkgs[i].Version, tok
				order, qs = append(order, i), append(qs, q)
			}
			var resp struct {
				Results []result `json:"results"`
			}
			if err := c.do(ctx, http.MethodPost, "/v1/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
				return nil, fmt.Errorf("querybatch: %w", err)
			}
			if len(resp.Results) != len(qs) {
				return nil, fmt.Errorf("querybatch: sent %d queries, got %d results", len(qs), len(resp.Results))
			}
			pending = map[int]string{}
			for j, r := range resp.Results {
				i := order[j]
				out[i] = append(out[i], r.Vulns...)
				if r.NextPageToken != "" {
					pending[i] = r.NextPageToken
				}
			}
		}
	}
	return out, nil
}

// fetchAll downloads full records for ids with a bounded pool of workers. With
// missingOK, an ID OSV doesn't have (404) is left out instead of failing the scan.
func (c *Client) fetchAll(ctx context.Context, ids map[string]string, missingOK bool) (map[string]*Vuln, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string)
	var (
		mu       sync.Mutex
		out      = make(map[string]*Vuln, len(ids))
		firstErr error
		wg       sync.WaitGroup
	)
	for range max(c.Workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				v, err := c.fetch(ctx, id, ids[id])
				if missingOK && errors.Is(err, errNotFound) {
					v, err = nil, nil
				}
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = fmt.Errorf("vuln %s: %w", id, err)
					cancel()
				}
				if v != nil {
					out[id] = v
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func (c *Client) fetch(ctx context.Context, id, modified string) (*Vuln, error) {
	cachePath := ""
	if c.CacheDir != "" && modified != "" {
		// modified is part of the key, so an updated advisory is refetched.
		safe := strings.NewReplacer(":", "_", "/", "_").Replace(id + "@" + modified)
		cachePath = filepath.Join(c.CacheDir, safe+".json")
		if b, err := os.ReadFile(cachePath); err == nil {
			var v Vuln
			if json.Unmarshal(b, &v) == nil {
				return &v, nil
			}
		}
	}
	var v Vuln
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+id, nil, &v); err != nil {
		return nil, err
	}
	if cachePath != "" {
		if b, err := json.Marshal(v); err == nil && os.MkdirAll(c.CacheDir, 0o755) == nil {
			_ = os.WriteFile(cachePath, b, 0o644) // cache is best-effort
		}
	}
	return &v, nil
}

// enrich fills in severity for records that carry none, which is common: the Go
// vulnerability database publishes no severity by policy, and some records ship only a
// CVSS v4 vector. For each such record, its aliases are looked up (GHSA first, then CVE,
// the NVD import) and the first usable rating is copied in, with SeverityFrom recording
// where it came from. Aliases OSV doesn't have (404) are skipped.
func (c *Client) enrich(ctx context.Context, vulns map[string]*Vuln) error {
	need := map[string]string{} // alias -> "" (modified unknown, so these bypass the cache key)
	for _, v := range vulns {
		if lvl, _ := Severity(v); lvl == Unknown {
			for _, a := range rankAliases(v.Aliases) {
				if _, have := vulns[a]; !have {
					need[a] = ""
				}
			}
		}
	}
	if len(need) == 0 {
		return nil
	}
	found, err := c.fetchAll(ctx, need, true)
	if err != nil {
		return err
	}
	for _, v := range vulns {
		if lvl, _ := Severity(v); lvl != Unknown {
			continue
		}
		for _, a := range rankAliases(v.Aliases) {
			src := vulns[a]
			if src == nil {
				src = found[a]
			}
			if src == nil {
				continue
			}
			if lvl, _ := Severity(src); lvl != Unknown {
				v.Severity, v.SeverityFrom = src.Severity, src.ID
				if s, ok := src.DatabaseSpecific["severity"]; ok {
					if v.DatabaseSpecific == nil {
						v.DatabaseSpecific = map[string]any{}
					}
					v.DatabaseSpecific["severity"] = s
				}
				break
			}
		}
	}
	return nil
}

// rankAliases orders aliases GHSA first, then CVE; other databases are not consulted.
func rankAliases(aliases []string) []string {
	var ghsa, cve []string
	for _, a := range aliases {
		switch {
		case strings.HasPrefix(a, "GHSA-"):
			ghsa = append(ghsa, a)
		case strings.HasPrefix(a, "CVE-"):
			cve = append(cve, a)
		}
	}
	return append(ghsa, cve...)
}

// errPermanent marks responses that retrying will not fix (4xx other than 429);
// errNotFound is the 404 case of it.
var (
	errPermanent = errors.New("permanent")
	errNotFound  = fmt.Errorf("not found: %w", errPermanent)
)

// do sends one JSON request, retrying timeouts, 429 and 5xx with jittered exponential backoff.
func (c *Client) do(ctx context.Context, method, path string, body, into any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * 500 * time.Millisecond
			c.sleep(backoff + time.Duration(rand.Int64N(int64(backoff/2)+1)))
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = c.once(ctx, method, path, payload, into)
		if lastErr == nil || errors.Is(lastErr, errPermanent) || ctx.Err() != nil {
			return lastErr
		}
	}
	return fmt.Errorf("after %d attempts: %w", c.Retries+1, lastErr)
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, into any) error {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "lockscan (+https://github.com/Revind4k/lockscan)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("HTTP 404: %w", errNotFound)
	case resp.StatusCode >= 400:
		return fmt.Errorf("HTTP %d: %s: %w", resp.StatusCode, strings.TrimSpace(string(b[:min(len(b), 200)])), errPermanent)
	}
	return json.Unmarshal(b, into)
}
