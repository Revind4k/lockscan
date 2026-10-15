package osv

import "testing"

func TestCVSS3(t *testing.T) {
	// Expected scores from the NVD CVSS v3.1 calculator.
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
	}
	for _, c := range cases {
		got, ok := CVSS3(c.vector)
		if !ok || got != c.want {
			t.Errorf("CVSS3(%s) = %v, %v; want %v", c.vector, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := CVSS3(bad); ok {
			t.Errorf("CVSS3(%q) accepted an invalid vector", bad)
		}
	}
}

func TestSeverityPrefersVectorThenLabel(t *testing.T) {
	v := &Vuln{
		Severity:         []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		DatabaseSpecific: map[string]any{"severity": "LOW"},
	}
	if l, s := Severity(v); l != Critical || s != 9.8 {
		t.Errorf("got %v %v, want CRITICAL 9.8", l, s)
	}
	v.Severity = nil
	if l, _ := Severity(v); l != Low {
		t.Errorf("label fallback: got %v, want LOW", l)
	}
	v.DatabaseSpecific = map[string]any{"severity": "MODERATE"}
	if l, _ := Severity(v); l != Medium {
		t.Errorf("MODERATE: got %v, want MEDIUM", l)
	}
	if l, _ := Severity(&Vuln{}); l != Unknown {
		t.Errorf("empty: got %v, want UNKNOWN", l)
	}
}

func TestFixedIn(t *testing.T) {
	var v Vuln
	a := Affected{}
	a.Package.Name, a.Package.Ecosystem = "lodash", "npm"
	a.Ranges = append(a.Ranges, struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{"SEMVER", []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}})
	other := Affected{}
	other.Package.Name, other.Package.Ecosystem = "lodash-es", "npm"
	other.Ranges = a.Ranges
	v.Affected = []Affected{a, other}
	got := FixedIn(&v, "lodash", "npm")
	if len(got) != 1 || got[0] != "4.17.21" {
		t.Errorf("FixedIn = %v", got)
	}
}
