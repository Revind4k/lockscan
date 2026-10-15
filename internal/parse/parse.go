// Package parse reads dependency lockfiles into a flat list of exact package versions.
package parse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Package is one resolved dependency. Ecosystem uses OSV's names (npm, PyPI, Pub, Go, Maven, SwiftURL).
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Source    string `json:"source"` // lockfile path, for reporting
}

type parser func(path string) ([]Package, error)

// Parsers maps a lockfile's base name to its parser.
var Parsers = map[string]parser{
	"package-lock.json": npmLock,
	"uv.lock":           uvLock,
	"requirements.txt":  requirementsTxt,
	"pubspec.lock":      pubspecLock,
	"go.mod":            goMod,
	"gradle.lockfile":   gradleLock,
	"Package.resolved":  swiftResolved,
}

// skipDirs are never descended into: vendored or generated trees whose lockfiles are not the project's own.
var skipDirs = map[string]bool{"node_modules": true, ".git": true, ".venv": true, "build": true, ".build": true, "vendor": true, ".dart_tool": true}

// Discover walks root and returns every supported lockfile, sorted.
func Discover(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && skipDirs[d.Name()] && p != root {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			if _, ok := Parsers[d.Name()]; ok {
				found = append(found, p)
			}
		}
		return nil
	})
	sort.Strings(found)
	return found, err
}

// File parses one lockfile, choosing the parser by base name.
func File(path string) ([]Package, error) {
	p, ok := Parsers[filepath.Base(path)]
	if !ok {
		return nil, fmt.Errorf("unsupported lockfile: %s", path)
	}
	pkgs, err := p(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range pkgs {
		pkgs[i].Source = path
	}
	return dedupe(pkgs), nil
}

func dedupe(in []Package) []Package {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		k := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if p.Name == "" || p.Version == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

// npm lockfile v2/v3: "packages" keyed by "node_modules/<name>" (nested paths for duplicates).
func npmLock(path string) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
	}
	if err := readJSON(path, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for key, v := range lock.Packages {
		i := strings.LastIndex(key, "node_modules/")
		if i < 0 || v.Link {
			continue // "" is the root project itself; links point at workspace packages
		}
		out = append(out, Package{Name: key[i+len("node_modules/"):], Version: v.Version, Ecosystem: "npm"})
	}
	return out, nil
}

func uvLock(path string) ([]Package, error) {
	var lock struct {
		Package []struct {
			Name    string            `toml:"name"`
			Version string            `toml:"version"`
			Source  map[string]string `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.DecodeFile(path, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for _, p := range lock.Package {
		if _, local := p.Source["editable"]; local {
			continue // the project itself, not a published dependency
		}
		if _, local := p.Source["virtual"]; local {
			continue
		}
		out = append(out, Package{Name: p.Name, Version: p.Version, Ecosystem: "PyPI"})
	}
	return out, nil
}

// requirements.txt: only exact "name==version" pins can be checked; ranges are skipped.
func requirementsTxt(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		line = strings.SplitN(line, ";", 2)[0] // drop environment markers
		name, ver, ok := strings.Cut(line, "==")
		if !ok || strings.HasPrefix(line, "-") {
			continue
		}
		name = strings.TrimSpace(strings.SplitN(name, "[", 2)[0]) // drop extras
		out = append(out, Package{Name: name, Version: strings.TrimSpace(ver), Ecosystem: "PyPI"})
	}
	return out, sc.Err()
}

func pubspecLock(path string) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `yaml:"version"`
			Source  string `yaml:"source"`
		} `yaml:"packages"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for name, p := range lock.Packages {
		if p.Source == "hosted" { // sdk and path/git packages are not on pub.dev
			out = append(out, Package{Name: name, Version: p.Version, Ecosystem: "Pub"})
		}
	}
	return out, nil
}

// go.mod require lines (single and block form); go.mod lists the selected module versions.
func goMod(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Package
	inBlock := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.SplitN(sc.Text(), "//", 2)[0])
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inBlock:
			continue
		}
		if fields := strings.Fields(line); len(fields) >= 2 {
			// OSV's Go ranges are bare semver ("1.2.3"), so drop go.mod's "v" prefix.
			out = append(out, Package{Name: fields[0], Version: strings.TrimPrefix(fields[1], "v"), Ecosystem: "Go"})
		}
	}
	return out, sc.Err()
}

// Gradle dependency locking: "group:artifact:version=configurations".
func gradleLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coord := strings.SplitN(line, "=", 2)[0]
		parts := strings.Split(coord, ":")
		if len(parts) == 3 {
			out = append(out, Package{Name: parts[0] + ":" + parts[1], Version: parts[2], Ecosystem: "Maven"})
		}
	}
	return out, sc.Err()
}

// SwiftPM Package.resolved (v2/v3): OSV keys Swift packages by repository URL.
func swiftResolved(path string) ([]Package, error) {
	var lock struct {
		Pins []struct {
			Location string `json:"location"`
			State    struct {
				Version string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	}
	if err := readJSON(path, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for _, p := range lock.Pins {
		name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p.Location, "https://"), "http://"), ".git")
		out = append(out, Package{Name: name, Version: p.State.Version, Ecosystem: "SwiftURL"})
	}
	return out, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
