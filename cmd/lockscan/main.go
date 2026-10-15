// Command lockscan finds known vulnerabilities in the dependencies pinned by a project's lockfiles.
//
// Exit codes: 0 no finding at or above --fail-on, 1 at least one such finding, 2 usage or runtime error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Revind4k/lockscan/internal/osv"
	"github.com/Revind4k/lockscan/internal/parse"
	"github.com/Revind4k/lockscan/internal/report"
)

var version = "dev" // set by -ldflags "-X main.version=..."

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, osv.New()))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, client *osv.Client) int {
	fs := flag.NewFlagSet("lockscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "table", "output format: table, json, sarif")
	failOn := fs.String("fail-on", "high", "exit 1 if any finding is at or above: low, medium, high, critical, none")
	outPath := fs.String("output", "", "write the report to this file instead of stdout")
	ignore := fs.String("ignore", "", "comma-separated advisory IDs or aliases to ignore (e.g. GHSA-xxxx,CVE-2024-1234)")
	noCache := fs.Bool("no-cache", false, "don't read or write the advisory cache")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall time limit for the scan")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: lockscan [flags] [path ...]\n\nScans each path (default \".\") for lockfiles: %s.\n\n", supported())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "lockscan", version)
		return 0
	}

	threshold := osv.Level(-1) // "none": never fail
	if *failOn != "none" {
		l, ok := osv.ParseLevel(*failOn)
		if !ok {
			fmt.Fprintf(stderr, "lockscan: --fail-on must be low, medium, high, critical or none, not %q\n", *failOn)
			return 2
		}
		threshold = l
	}
	if *format != "table" && *format != "json" && *format != "sarif" {
		fmt.Fprintf(stderr, "lockscan: unknown --format %q\n", *format)
		return 2
	}
	if *noCache {
		client.CacheDir = ""
	}

	roots := fs.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var files []string
	for _, r := range roots {
		info, err := os.Stat(r)
		if err != nil {
			fmt.Fprintln(stderr, "lockscan:", err)
			return 2
		}
		if !info.IsDir() {
			files = append(files, r)
			continue
		}
		found, err := parse.Discover(r)
		if err != nil {
			fmt.Fprintln(stderr, "lockscan:", err)
			return 2
		}
		files = append(files, found...)
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "lockscan: no lockfiles found (looked for %s)\n", supported())
		return 2
	}

	var pkgs []parse.Package
	for _, f := range files {
		p, err := parse.File(f)
		if err != nil {
			fmt.Fprintln(stderr, "lockscan:", err)
			return 2
		}
		pkgs = append(pkgs, p...)
	}
	fmt.Fprintf(stderr, "lockscan: %d packages from %d lockfiles\n", len(pkgs), len(files))

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	findings, err := client.Scan(ctx, pkgs)
	if err != nil {
		fmt.Fprintln(stderr, "lockscan: OSV lookup failed:", err)
		return 2
	}
	rows := filterIgnored(report.Rows(findings), *ignore)

	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(stderr, "lockscan:", err)
			return 2
		}
		defer f.Close()
		out = f
	}
	switch *format {
	case "json":
		err = report.JSON(out, rows)
	case "sarif":
		err = report.SARIF(out, rows, version)
	default:
		err = report.Table(out, rows, len(pkgs))
	}
	if err != nil {
		fmt.Fprintln(stderr, "lockscan:", err)
		return 2
	}

	if threshold >= 0 && len(rows) > 0 && report.Worst(rows) >= threshold {
		return 1
	}
	return 0
}

func filterIgnored(rows []report.Row, list string) []report.Row {
	ignored := map[string]bool{}
	for _, id := range strings.Split(list, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ignored[strings.ToUpper(id)] = true
		}
	}
	if len(ignored) == 0 {
		return rows
	}
	out := rows[:0]
next:
	for _, r := range rows {
		for _, id := range append([]string{r.ID}, r.Aliases...) {
			if ignored[strings.ToUpper(id)] {
				continue next
			}
		}
		out = append(out, r)
	}
	return out
}

func supported() string {
	names := []string{"package-lock.json", "uv.lock", "requirements.txt", "pubspec.lock", "go.mod", "gradle.lockfile", "Package.resolved"}
	return strings.Join(names, ", ")
}
