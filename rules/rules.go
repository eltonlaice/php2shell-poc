// Package rules embeds the detection rules shipped with php2shell-poc.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed suricata/*.rules sigma/*.yaml modsecurity/*.conf
var assets embed.FS

// Kinds lists the supported rule formats.
func Kinds() []string {
	return []string{"suricata", "sigma", "modsecurity"}
}

// Files lists every embedded rule file, sorted.
func Files() ([]string, error) {
	var out []string
	err := fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, path)
		return nil
	})
	sort.Strings(out)
	return out, err
}

// Get returns the rule file for kind (suricata, sigma or modsecurity).
func Get(kind string) ([]byte, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	var path string
	switch kind {
	case "suricata":
		path = "suricata/php2shell.rules"
	case "sigma":
		path = "sigma/php2shell.yaml"
	case "modsecurity":
		path = "modsecurity/php2shell.conf"
	default:
		return nil, fmt.Errorf("rules: unknown kind %q (want one of %s)", kind, strings.Join(Kinds(), ", "))
	}
	return assets.ReadFile(path)
}
