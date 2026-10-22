package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	uuidRE   = regexp.MustCompile(`(?m)^id:\s*([0-9a-fA-F-]{36})\s*$`)
	sidRE    = regexp.MustCompile(`sid:(\d+);`)
	modSecID = regexp.MustCompile(`id:(\d+),`)
)

// Validate performs structural checks on the embedded rules.
func Validate() error {
	for _, kind := range Kinds() {
		data, err := Get(kind)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return fmt.Errorf("rules: %s is empty", kind)
		}
		switch kind {
		case "sigma":
			if err := validateSigma(data); err != nil {
				return err
			}
		case "suricata":
			if err := validateIDs(data, sidRE, "suricata"); err != nil {
				return err
			}
		case "modsecurity":
			if err := validateIDs(data, modSecID, "modsecurity"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSigma(data []byte) error {
	matches := uuidRE.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return fmt.Errorf("sigma: no rule ids found")
	}
	seen := map[string]bool{}
	for _, m := range matches {
		id := strings.ToLower(string(m[1]))
		if !validUUID(id) {
			return fmt.Errorf("sigma: invalid rule id %q (must be a UUID)", id)
		}
		if seen[id] {
			return fmt.Errorf("sigma: duplicate rule id %q", id)
		}
		seen[id] = true
	}
	return nil
}

func validUUID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	want := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != want[i] {
			return false
		}
		for _, r := range p {
			if !strings.ContainsRune("0123456789abcdef", r) {
				return false
			}
		}
	}
	// Version 4 and RFC 4122 variant.
	return parts[2][0] == '4' && strings.ContainsRune("89ab", rune(parts[3][0]))
}

func validateIDs(data []byte, re *regexp.Regexp, kind string) error {
	matches := re.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return fmt.Errorf("%s: no rule ids found", kind)
	}
	seen := map[string]bool{}
	for _, m := range matches {
		id := string(m[1])
		if _, err := strconv.Atoi(id); err != nil {
			return fmt.Errorf("%s: invalid rule id %q", kind, id)
		}
		if seen[id] {
			return fmt.Errorf("%s: duplicate rule id %s", kind, id)
		}
		seen[id] = true
	}
	return nil
}

// Count returns the number of rules in the embedded set (all formats).
func Count() map[string]int {
	out := map[string]int{}
	for _, kind := range Kinds() {
		data, err := Get(kind)
		if err != nil {
			continue
		}
		switch kind {
		case "sigma":
			out[kind] = len(uuidRE.FindAll(data, -1))
		case "suricata":
			out[kind] = len(sidRE.FindAll(data, -1))
		case "modsecurity":
			out[kind] = len(modSecID.FindAll(data, -1))
		}
	}
	return out
}
