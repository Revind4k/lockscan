package parse

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixtures = "../../testdata/project"

func TestDiscoverSkipsVendoredTrees(t *testing.T) {
	got, err := Discover(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var rel []string
	for _, p := range got {
		r, _ := filepath.Rel(fixtures, p)
		rel = append(rel, r)
	}
	want := "android/gradle.lockfile api/requirements.txt api/uv.lock app/pubspec.lock ios/Package.resolved svc/go.mod web/package-lock.json"
	if strings.Join(rel, " ") != want {
		t.Errorf("Discover =\n  %s\nwant\n  %s", strings.Join(rel, " "), want)
	}
}

func TestParsers(t *testing.T) {
	cases := []struct {
		file string
		want []string // "ecosystem name version", sorted
	}{
		{"web/package-lock.json", []string{
			"npm @babel/core 7.24.0",
			"npm lodash 4.17.20",
			"npm lodash 4.17.21", // nested duplicate at a different version is kept
		}},
		{"api/uv.lock", []string{"PyPI fastapi 0.110.0", "PyPI jinja2 3.1.2"}},
		{"api/requirements.txt", []string{"PyPI requests 2.31.0", "PyPI uvicorn 0.29.0"}},
		{"app/pubspec.lock", []string{"Pub http 1.2.0"}},
		{"svc/go.mod", []string{"Go github.com/gin-gonic/gin 1.9.0", "Go golang.org/x/net 0.17.0", "Go golang.org/x/text 0.13.0"}},
		{"android/gradle.lockfile", []string{"Maven com.fasterxml.jackson.core:jackson-databind 2.15.0", "Maven org.yaml:snakeyaml 1.33"}},
		{"ios/Package.resolved", []string{"SwiftURL github.com/Alamofire/Alamofire 5.8.0"}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join(fixtures, c.file)
			pkgs, err := File(path)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, p := range pkgs {
				got = append(got, p.Ecosystem+" "+p.Name+" "+p.Version)
				if p.Source != path {
					t.Errorf("%s: Source = %q, want %q", p.Name, p.Source, path)
				}
			}
			sort.Strings(got)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(c.want, "\n  "))
			}
		})
	}
}

func TestUnsupportedFile(t *testing.T) {
	if _, err := File("Cargo.lock"); err == nil {
		t.Error("expected an error for an unsupported lockfile")
	}
}

func TestDedupe(t *testing.T) {
	in := []Package{
		{Name: "a", Version: "1", Ecosystem: "npm"},
		{Name: "a", Version: "1", Ecosystem: "npm"},
		{Name: "a", Version: "2", Ecosystem: "npm"},
		{Name: "", Version: "1", Ecosystem: "npm"},
		{Name: "b", Version: "", Ecosystem: "npm"},
	}
	if got := dedupe(in); len(got) != 2 {
		t.Errorf("dedupe kept %d, want 2: %+v", len(got), got)
	}
}
