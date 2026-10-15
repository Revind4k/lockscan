package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Revind4k/lockscan/internal/parse"
)

// fakeOSV serves querybatch and vulns/{id} from in-memory data. vulnsFor maps
// "name@version" to advisory IDs; pageSize > 0 paginates querybatch results.
type fakeOSV struct {
	vulnsFor     map[string][]string
	pageSize     int
	failFirst    int32 // respond 503 to this many requests first
	batchCalls   atomic.Int32
	detailCalls  atomic.Int32
	maxBatchSize atomic.Int32
	requests     atomic.Int32
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.requests.Add(1) <= f.failFirst {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		f.batchCalls.Add(1)
		var req struct {
			Queries []struct {
				Package   struct{ Name string } `json:"package"`
				Version   string                `json:"version"`
				PageToken string                `json:"page_token"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if n := int32(len(req.Queries)); n > f.maxBatchSize.Load() {
			f.maxBatchSize.Store(n)
		}
		type res struct {
			Vulns []idRef `json:"vulns,omitempty"`
			Next  string  `json:"next_page_token,omitempty"`
		}
		out := struct {
			Results []res `json:"results"`
		}{}
		for _, q := range req.Queries {
			ids := f.vulnsFor[q.Package.Name+"@"+q.Version]
			start := 0
			fmt.Sscan(q.PageToken, &start)
			end := len(ids)
			if f.pageSize > 0 && start+f.pageSize < end {
				end = start + f.pageSize
			}
			var r res
			for _, id := range ids[start:end] {
				r.Vulns = append(r.Vulns, idRef{ID: id, Modified: "2026-01-01T00:00:00Z"})
			}
			if end < len(ids) {
				r.Next = fmt.Sprint(end)
			}
			out.Results = append(out.Results, r)
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		f.detailCalls.Add(1)
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "MISSING" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(Vuln{ID: id, Summary: "summary of " + id, Modified: "2026-01-01T00:00:00Z"})
	default:
		http.NotFound(w, r)
	}
}

func newClient(t *testing.T, f *fakeOSV) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := New()
	c.BaseURL = srv.URL
	c.CacheDir = t.TempDir()
	c.sleep = func(time.Duration) {}
	return c
}

func pkg(name, version string) parse.Package {
	return parse.Package{Name: name, Version: version, Ecosystem: "npm"}
}

func TestScanMapsFindingsToPackages(t *testing.T) {
	f := &fakeOSV{vulnsFor: map[string][]string{
		"lodash@4.17.20": {"GHSA-1", "GHSA-2"},
		"minimist@1.2.0": {"GHSA-2"}, // shared advisory: fetched once
		"left-pad@1.3.0": nil,
	}}
	c := newClient(t, f)
	got, err := c.Scan(context.Background(), []parse.Package{pkg("lodash", "4.17.20"), pkg("left-pad", "1.3.0"), pkg("minimist", "1.2.0")})
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for _, fd := range got {
		pairs = append(pairs, fd.Package.Name+":"+fd.Vuln.ID)
	}
	if strings.Join(pairs, ",") != "lodash:GHSA-1,lodash:GHSA-2,minimist:GHSA-2" {
		t.Errorf("findings = %v", pairs)
	}
	if n := f.detailCalls.Load(); n != 2 {
		t.Errorf("detail calls = %d, want 2 (one per distinct advisory)", n)
	}
}

func TestScanChunksLargeBatches(t *testing.T) {
	f := &fakeOSV{vulnsFor: map[string][]string{"p1500@1.0.0": {"GHSA-X"}}}
	c := newClient(t, f)
	var pkgs []parse.Package
	for i := range 2500 {
		pkgs = append(pkgs, pkg(fmt.Sprintf("p%d", i), "1.0.0"))
	}
	got, err := c.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Package.Name != "p1500" {
		t.Errorf("findings = %+v", got)
	}
	if b, m := f.batchCalls.Load(), f.maxBatchSize.Load(); b != 3 || m != batchLimit {
		t.Errorf("batch calls = %d (max size %d), want 3 calls of at most %d", b, m, batchLimit)
	}
}

func TestScanFollowsPagination(t *testing.T) {
	f := &fakeOSV{pageSize: 2, vulnsFor: map[string][]string{"big@1.0.0": {"A", "B", "C", "D", "E"}}}
	c := newClient(t, f)
	got, err := c.Scan(context.Background(), []parse.Package{pkg("big", "1.0.0"), pkg("small", "1.0.0")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("got %d findings, want 5 across 3 pages", len(got))
	}
}

func TestRetriesTransientErrors(t *testing.T) {
	f := &fakeOSV{failFirst: 2, vulnsFor: map[string][]string{"a@1.0.0": {"GHSA-1"}}}
	c := newClient(t, f)
	if _, err := c.Scan(context.Background(), []parse.Package{pkg("a", "1.0.0")}); err != nil {
		t.Fatalf("expected recovery after 2 transient failures, got %v", err)
	}
}

func TestGivesUpAfterRetries(t *testing.T) {
	f := &fakeOSV{failFirst: 100}
	c := newClient(t, f)
	c.Retries = 2
	_, err := c.Scan(context.Background(), []parse.Package{pkg("a", "1.0.0")})
	if err == nil || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("err = %v", err)
	}
	if n := f.requests.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	f := &fakeOSV{vulnsFor: map[string][]string{"a@1.0.0": {"MISSING"}}}
	c := newClient(t, f)
	_, err := c.Scan(context.Background(), []parse.Package{pkg("a", "1.0.0")})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
	if n := f.detailCalls.Load(); n != 1 {
		t.Errorf("detail calls = %d, want 1 (404 is not retried)", n)
	}
}

func TestCacheSkipsRepeatDetailCalls(t *testing.T) {
	f := &fakeOSV{vulnsFor: map[string][]string{"a@1.0.0": {"GHSA-1", "GHSA-2"}}}
	c := newClient(t, f)
	for range 2 {
		if _, err := c.Scan(context.Background(), []parse.Package{pkg("a", "1.0.0")}); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.detailCalls.Load(); n != 2 {
		t.Errorf("detail calls over two scans = %d, want 2 (second scan served from cache)", n)
	}
}

func TestRespectsContextTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })
	c := New()
	c.BaseURL, c.CacheDir = srv.URL, ""
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Scan(ctx, []parse.Package{pkg("a", "1.0.0")}); err == nil {
		t.Fatal("expected a timeout error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v; context deadline was not honored", d)
	}
}

func TestEnrichBorrowsSeverityFromAliases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Write([]byte(`{"results":[{"vulns":[{"id":"GO-1","modified":"m"},{"id":"GO-2","modified":"m"}]}]}`))
		case "/v1/vulns/GO-1": // only a GHSA alias has a rating
			w.Write([]byte(`{"id":"GO-1","aliases":["CVE-1","GHSA-1"]}`))
		case "/v1/vulns/GO-2": // its only alias is unknown to OSV
			w.Write([]byte(`{"id":"GO-2","aliases":["CVE-404"]}`))
		case "/v1/vulns/GHSA-1":
			w.Write([]byte(`{"id":"GHSA-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}`))
		case "/v1/vulns/CVE-1":
			w.Write([]byte(`{"id":"CVE-1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.BaseURL, c.CacheDir = srv.URL, ""
	got, err := c.Scan(context.Background(), []parse.Package{{Name: "x", Version: "1", Ecosystem: "Go"}})
	if err != nil {
		t.Fatalf("a 404 on an alias must not fail the scan: %v", err)
	}
	byID := map[string]*Vuln{}
	for _, f := range got {
		byID[f.Vuln.ID] = f.Vuln
	}
	if l, s := Severity(byID["GO-1"]); l != High || s != 7.5 || byID["GO-1"].SeverityFrom != "GHSA-1" {
		t.Errorf("GO-1 = %v %v from %q, want HIGH 7.5 from GHSA-1", l, s, byID["GO-1"].SeverityFrom)
	}
	if l, _ := Severity(byID["GO-2"]); l != Unknown || byID["GO-2"].SeverityFrom != "" {
		t.Errorf("GO-2 should stay UNKNOWN, got %v", l)
	}
}
