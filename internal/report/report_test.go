package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Revind4k/lockscan/internal/osv"
	"github.com/Revind4k/lockscan/internal/parse"
)

func TestRowsMergesAliasedAdvisories(t *testing.T) {
	net := parse.Package{Name: "golang.org/x/net", Version: "0.17.0", Ecosystem: "Go", Source: "go.mod"}
	other := parse.Package{Name: "golang.org/x/text", Version: "0.13.0", Ecosystem: "Go", Source: "go.mod"}
	goVuln := &osv.Vuln{ID: "GO-2025-3503", Aliases: []string{"CVE-2025-22870", "GHSA-qxp5-gwg8-xv66"}}
	ghsa := &osv.Vuln{ID: "GHSA-qxp5-gwg8-xv66", Aliases: []string{"CVE-2025-22870"},
		Severity: []osv.SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L"}}}
	// Linked only through a shared CVE, not directly.
	viaCVE := &osv.Vuln{ID: "PYSEC-X", Aliases: []string{"CVE-2025-22870"}}
	unrelated := &osv.Vuln{ID: "GO-2026-0001"}

	rows := Rows([]osv.Finding{
		{Package: net, Vuln: goVuln},
		{Package: net, Vuln: ghsa},
		{Package: net, Vuln: viaCVE},
		{Package: net, Vuln: unrelated},
		{Package: other, Vuln: ghsa}, // same advisory on a different package stays separate
	})
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}
	top := rows[0]
	if top.ID != "GHSA-qxp5-gwg8-xv66" || top.Severity != "MEDIUM" || top.Score != 4.8 {
		t.Errorf("representative = %s %s %v, want the scored GHSA record", top.ID, top.Severity, top.Score)
	}
	want := map[string]bool{"CVE-2025-22870": true, "GO-2025-3503": true, "PYSEC-X": true}
	if len(top.Aliases) != len(want) {
		t.Errorf("aliases = %v", top.Aliases)
	}
	for _, a := range top.Aliases {
		if !want[a] {
			t.Errorf("unexpected alias %s", a)
		}
	}
	if ghsa.Aliases[0] != "CVE-2025-22870" || len(ghsa.Aliases) != 1 {
		t.Error("merge mutated the shared advisory record")
	}
}

func TestWorst(t *testing.T) {
	if Worst(nil) != osv.Unknown {
		t.Error("empty rows should be Unknown")
	}
	rows := Rows([]osv.Finding{
		{Package: parse.Package{Name: "a"}, Vuln: &osv.Vuln{ID: "1", DatabaseSpecific: map[string]any{"severity": "LOW"}}},
		{Package: parse.Package{Name: "b"}, Vuln: &osv.Vuln{ID: "2", DatabaseSpecific: map[string]any{"severity": "HIGH"}}},
	})
	if Worst(rows) != osv.High {
		t.Errorf("Worst = %v", Worst(rows))
	}
}

func TestSARIFCleanScanIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, nil, "test"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	// GitHub's upload rejects null here ("rules is not of a type(s) array").
	if r := string(doc.Runs[0].Tool.Driver.Rules); r != "[]" {
		t.Errorf("rules = %s, want []", r)
	}
	if r := string(doc.Runs[0].Results); r != "[]" {
		t.Errorf("results = %s, want []", r)
	}
}
