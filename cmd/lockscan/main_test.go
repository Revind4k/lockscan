package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Revind4k/lockscan/internal/osv"
)

// fakeAPI reports one critical lodash advisory and one medium minimist advisory.
func fakeAPI(t *testing.T) *osv.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			res := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				res[i] = map[string]any{}
				switch q.Package.Name {
				case "lodash":
					res[i]["vulns"] = []map[string]string{{"id": "GHSA-crit", "modified": "x"}}
				case "minimist":
					res[i]["vulns"] = []map[string]string{{"id": "GHSA-med", "modified": "x"}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.URL.Path == "/v1/vulns/GHSA-crit":
			w.Write([]byte(`{"id":"GHSA-crit","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash",
			  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			  "affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
		case r.URL.Path == "/v1/vulns/GHSA-med":
			w.Write([]byte(`{"id":"GHSA-med","summary":"Prototype pollution in minimist","database_specific":{"severity":"MODERATE"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := osv.New()
	c.BaseURL, c.CacheDir = srv.URL, ""
	return c
}

func project(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	lock := `{"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/minimist":{"version":"1.2.0"},"node_modules/ok":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func lockscan(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut, fakeAPI(t))
	return code, out.String(), errOut.String()
}

func TestTableAndExitCodes(t *testing.T) {
	dir := project(t)
	code, out, _ := lockscan(t, dir)
	if code != 1 {
		t.Errorf("default --fail-on high with a critical finding: exit %d, want 1", code)
	}
	for _, want := range []string{"2 vulnerabilities in 3 packages (1 critical, 1 medium)", "CRITICAL 9.8", "4.17.21", "MEDIUM"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "GHSA-crit") > strings.Index(out, "GHSA-med") {
		t.Error("table is not sorted most severe first")
	}
	if code, _, _ := lockscan(t, "--fail-on", "critical", dir); code != 1 {
		t.Errorf("--fail-on critical: exit %d, want 1", code)
	}
	if code, _, _ := lockscan(t, "--fail-on", "none", dir); code != 0 {
		t.Errorf("--fail-on none: exit %d, want 0", code)
	}
	if code, _, _ := lockscan(t, "--ignore", "cve-2021-23337", dir); code != 0 {
		t.Errorf("ignoring the critical by CVE alias should leave only a medium: exit %d, want 0", code)
	}
}

func TestJSON(t *testing.T) {
	_, out, _ := lockscan(t, "--format", "json", "--fail-on", "none", project(t))
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(rows) != 2 || rows[0]["id"] != "GHSA-crit" || rows[0]["cvss"] != 9.8 {
		t.Errorf("rows = %+v", rows)
	}
}

func TestSARIF(t *testing.T) {
	dir := project(t)
	outFile := filepath.Join(t.TempDir(), "out.sarif")
	if code, _, stderr := lockscan(t, "--format", "sarif", "--output", outFile, "--fail-on", "none", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	b, _ := os.ReadFile(outFile)
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 {
		t.Fatalf("unexpected SARIF shape: %s", b)
	}
	r := doc.Runs[0]
	if r.Results[0].Level != "error" || r.Results[1].Level != "warning" {
		t.Errorf("levels = %s, %s", r.Results[0].Level, r.Results[1].Level)
	}
	if !strings.HasSuffix(r.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI, "package-lock.json") {
		t.Errorf("location = %+v", r.Results[0].Locations)
	}
	if r.Tool.Driver.Rules[0].Properties["security-severity"] != "9.8" {
		t.Errorf("security-severity = %v", r.Tool.Driver.Rules[0].Properties)
	}
}

func TestUsageErrors(t *testing.T) {
	dir := project(t)
	for _, args := range [][]string{
		{"--fail-on", "severe", dir},
		{"--format", "xml", dir},
		{filepath.Join(dir, "missing")},
		{t.TempDir()}, // no lockfiles
	} {
		if code, _, _ := lockscan(t, args...); code != 2 {
			t.Errorf("lockscan %v: exit %d, want 2", args, code)
		}
	}
}

func TestClean(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"packages":{"node_modules/ok":{"version":"1.0.0"}}}`), 0o644)
	code, out, _ := lockscan(t, dir)
	if code != 0 || !strings.Contains(out, "No known vulnerabilities in 1 packages") {
		t.Errorf("exit %d, out %q", code, out)
	}
}
