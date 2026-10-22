package rules

import "testing"

func TestValidate(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCounts(t *testing.T) {
	got := Count()
	want := map[string]int{"suricata": 10, "sigma": 4, "modsecurity": 6}
	for kind, n := range want {
		if got[kind] != n {
			t.Errorf("%s: got %d rules, want %d", kind, got[kind], n)
		}
	}
}

func TestGetUnknown(t *testing.T) {
	if _, err := Get("snort"); err == nil {
		t.Fatal("expected error for unknown rule kind")
	}
}
