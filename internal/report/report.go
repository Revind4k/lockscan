// Package report renders scan findings as a terminal table, JSON, or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/Revind4k/lockscan/internal/osv"
)

// Row is one finding, flattened and scored, as every format sees it.
type Row struct {
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases,omitempty"`
	Severity  string    `json:"severity"`
	Score     float64   `json:"cvss,omitempty"`
	RatedBy   string    `json:"severity_from,omitempty"` // alias the rating was borrowed from
	FixedIn   []string  `json:"fixed_in,omitempty"`
	Summary   string    `json:"summary"`
	Source    string    `json:"source"`
	URL       string    `json:"url"`
	level     osv.Level `json:"-"`
}

// Rows scores findings, merges advisories that alias each other, and sorts most severe first.
func Rows(findings []osv.Finding) []Row {
	rows := make([]Row, 0, len(findings))
	for _, f := range mergeAliases(findings) {
		lvl, score := osv.Severity(f.Vuln)
		summary := f.Vuln.Summary
		if summary == "" {
			summary = firstLine(f.Vuln.Details)
		}
		rows = append(rows, Row{
			Ecosystem: f.Package.Ecosystem,
			Package:   f.Package.Name,
			Version:   f.Package.Version,
			ID:        f.Vuln.ID,
			Aliases:   f.Vuln.Aliases,
			Severity:  lvl.String(),
			Score:     score,
			RatedBy:   f.Vuln.SeverityFrom,
			FixedIn:   osv.FixedIn(f.Vuln, f.Package.Name, f.Package.Ecosystem),
			Summary:   summary,
			Source:    f.Package.Source,
			URL:       "https://osv.dev/vulnerability/" + f.Vuln.ID,
			level:     lvl,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].level != rows[j].level {
			return rows[i].level > rows[j].level
		}
		if rows[i].Package != rows[j].Package {
			return rows[i].Package < rows[j].Package
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

// mergeAliases collapses findings for the same installed package whose advisories are
// the same issue under different databases (GHSA-…, PYSEC-…, GO-…, CVE-…), linked through
// their IDs and aliases. The record with the best severity data is kept as the
// representative; the others' IDs and fix versions are folded into it.
func mergeAliases(findings []osv.Finding) []osv.Finding {
	type key struct{ eco, name, version, source string }
	groups := map[key][]osv.Finding{}
	var order []key
	for _, f := range findings {
		k := key{f.Package.Ecosystem, f.Package.Name, f.Package.Version, f.Package.Source}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}

	var out []osv.Finding
	for _, k := range order {
		fs := groups[k]
		// Union-find over the findings of one package: two findings join when they share any ID.
		parent := make([]int, len(fs))
		for i := range parent {
			parent[i] = i
		}
		var find func(int) int
		find = func(i int) int {
			if parent[i] != i {
				parent[i] = find(parent[i])
			}
			return parent[i]
		}
		owner := map[string]int{}
		for i, f := range fs {
			for _, id := range append([]string{f.Vuln.ID}, f.Vuln.Aliases...) {
				if j, ok := owner[id]; ok {
					parent[find(i)] = find(j)
				} else {
					owner[id] = i
				}
			}
		}
		clusters := map[int][]osv.Finding{}
		var roots []int
		for i, f := range fs {
			r := find(i)
			if _, ok := clusters[r]; !ok {
				roots = append(roots, r)
			}
			clusters[r] = append(clusters[r], f)
		}
		for _, r := range roots {
			out = append(out, merged(clusters[r]))
		}
	}
	return out
}

func merged(cluster []osv.Finding) osv.Finding {
	if len(cluster) == 1 {
		return cluster[0]
	}
	best := 0
	for i, f := range cluster {
		if better(f.Vuln, cluster[best].Vuln) {
			best = i
		}
	}
	rep := *cluster[best].Vuln // copy: the original is shared with other packages
	ids := map[string]bool{rep.ID: true}
	var aliases []string
	for _, f := range cluster {
		for _, id := range append([]string{f.Vuln.ID}, f.Vuln.Aliases...) {
			if !ids[id] {
				ids[id] = true
				aliases = append(aliases, id)
			}
		}
		if f.Vuln != cluster[best].Vuln {
			rep.Affected = append(append([]osv.Affected(nil), rep.Affected...), f.Vuln.Affected...)
		}
	}
	sort.Strings(aliases)
	rep.Aliases = aliases
	return osv.Finding{Package: cluster[best].Package, Vuln: &rep}
}

// better prefers a computed CVSS score, then any severity label, then GHSA IDs
// (the most widely linked), then the lexically smaller ID for stable output.
func better(a, b *osv.Vuln) bool {
	la, sa := osv.Severity(a)
	lb, sb := osv.Severity(b)
	if (sa > 0) != (sb > 0) {
		return sa > 0
	}
	if (la != osv.Unknown) != (lb != osv.Unknown) {
		return la != osv.Unknown
	}
	if ga, gb := strings.HasPrefix(a.ID, "GHSA-"), strings.HasPrefix(b.ID, "GHSA-"); ga != gb {
		return ga
	}
	return a.ID < b.ID
}

// Worst returns the highest severity among rows (Unknown when empty).
func Worst(rows []Row) osv.Level {
	w := osv.Unknown
	for _, r := range rows {
		w = max(w, r.level)
	}
	return w
}

// Table writes a human-readable table, with a one-line summary on top.
func Table(w io.Writer, rows []Row, scanned int) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintf(w, "No known vulnerabilities in %d packages.\n", scanned)
		return err
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Severity]++
	}
	var parts []string
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], strings.ToLower(s)))
		}
	}
	fmt.Fprintf(w, "%d vulnerabilities in %d packages (%s)\n\n", len(rows), scanned, strings.Join(parts, ", "))
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	borrowed := false
	fmt.Fprintln(tw, "SEVERITY\tPACKAGE\tVERSION\tFIXED IN\tID\tSUMMARY")
	for _, r := range rows {
		fixed := strings.Join(r.FixedIn, ", ")
		if fixed == "" {
			fixed = "-"
		}
		sev := r.Severity
		if r.Score > 0 {
			sev = fmt.Sprintf("%s %.1f", r.Severity, r.Score)
		}
		if r.RatedBy != "" {
			sev += "*"
			borrowed = true
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", sev, r.Package, r.Version, fixed, r.ID, truncate(r.Summary, 70))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if borrowed {
		_, err := fmt.Fprintln(w, "\n* rating taken from an alias (GHSA or CVE record); the advisory itself has none.")
		return err
	}
	return nil
}

// JSON writes rows as an indented JSON array.
func JSON(w io.Writer, rows []Row) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if rows == nil {
		rows = []Row{}
	}
	return enc.Encode(rows)
}

// SARIF writes a SARIF 2.1.0 log that GitHub code scanning accepts. Each advisory is a
// rule; each affected package is a result located on the lockfile that pins it.
func SARIF(w io.Writer, rows []Row, toolVersion string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		ShortDescription msg            `json:"shortDescription"`
		HelpURI          string         `json:"helpUri"`
		Properties       map[string]any `json:"properties"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
	}

	rules := []rule{} // SARIF requires an array, so a clean scan must encode [] not null
	seen := map[string]bool{}
	results := make([]result, 0, len(rows))
	for _, r := range rows {
		if !seen[r.ID] {
			seen[r.ID] = true
			props := map[string]any{"tags": []string{"security", "dependency", r.Ecosystem}}
			if r.Score > 0 {
				// GitHub reads this to show Critical/High/Medium/Low on the alert.
				props["security-severity"] = fmt.Sprintf("%.1f", r.Score)
			}
			rules = append(rules, rule{ID: r.ID, ShortDescription: msg{truncate(r.Summary, 200)}, HelpURI: r.URL, Properties: props})
		}
		text := fmt.Sprintf("%s %s is affected by %s (%s).", r.Package, r.Version, r.ID, r.Severity)
		if len(r.FixedIn) > 0 {
			text += " Fixed in " + strings.Join(r.FixedIn, ", ") + "."
		}
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = strings.TrimPrefix(r.Source, "./")
		results = append(results, result{RuleID: r.ID, Level: sarifLevel(r.level), Message: msg{text}, Locations: []location{loc}})
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "lockscan",
				"version":        toolVersion,
				"informationUri": "https://github.com/Revind4k/lockscan",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(l osv.Level) string {
	switch l {
	case osv.Critical, osv.High:
		return "error"
	case osv.Medium:
		return "warning"
	}
	return "note"
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
