package osv

import (
	"math"
	"strings"
)

// Level is a coarse severity, ordered so levels compare with <.
type Level int

const (
	Unknown Level = iota
	Low
	Medium
	High
	Critical
)

func (l Level) String() string {
	return [...]string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[l]
}

// ParseLevel accepts LOW/MEDIUM/MODERATE/HIGH/CRITICAL (any case).
func ParseLevel(s string) (Level, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return Low, true
	case "MEDIUM", "MODERATE":
		return Medium, true
	case "HIGH":
		return High, true
	case "CRITICAL":
		return Critical, true
	}
	return Unknown, false
}

// Severity picks the best available rating for v: a CVSS v3 vector if present (computed
// here, since OSV ships the vector rather than the score), else the advisory database's
// own label (GitHub's "MODERATE", etc.). Score is 0 when no vector was usable.
func Severity(v *Vuln) (Level, float64) {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if score, ok := CVSS3(s.Score); ok {
				return levelFor(score), score
			}
		}
	}
	for _, m := range []map[string]any{v.DatabaseSpecific, firstAffectedDB(v)} {
		if s, ok := m["severity"].(string); ok {
			if l, ok := ParseLevel(s); ok {
				return l, 0
			}
		}
	}
	return Unknown, 0
}

func firstAffectedDB(v *Vuln) map[string]any {
	for _, a := range v.Affected {
		if a.DatabaseSpecific != nil {
			return a.DatabaseSpecific
		}
	}
	return nil
}

func levelFor(score float64) Level {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	}
	return Unknown // CVSS 0.0 is "None"
}

// CVSS3 computes the CVSS v3.0/v3.1 base score from a vector string, per the FIRST spec.
func CVSS3(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		m[k] = val
	}
	weight := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	get := func(k string) (float64, bool) {
		w, ok := weight[k][m[k]]
		return w, ok
	}
	av, ok1 := get("AV")
	ac, ok2 := get("AC")
	ui, ok3 := get("UI")
	c, ok4 := get("C")
	i, ok5 := get("I")
	a, ok6 := get("A")
	scope := m["S"]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || (scope != "U" && scope != "C") {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = map[string]float64{"U": 0.62, "C": 0.68}[scope]
	case "H":
		pr = map[string]float64{"U": 0.27, "C": 0.5}[scope]
	default:
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploit := 8.22 * av * ac * pr * ui
	if scope == "U" {
		return roundUp(math.Min(impact+exploit, 10)), true
	}
	return roundUp(math.Min(1.08*(impact+exploit), 10)), true
}

// roundUp is the spec's Roundup: smallest one-decimal number >= x, computed on
// integers to avoid float artifacts (e.g. 4.000000001 must not become 4.1).
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// FixedIn lists the versions that fix v for pkg (from "fixed" range events), in OSV order.
func FixedIn(v *Vuln, name, ecosystem string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range v.Affected {
		if a.Package.Name != name || !strings.EqualFold(a.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" { // commit hashes, not versions
				continue
			}
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" && !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
		}
	}
	return out
}
