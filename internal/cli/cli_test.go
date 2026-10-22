package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	code, out, errOut := run(t, "version")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	if !strings.Contains(out, Version) {
		t.Fatalf("version output = %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errOut := run(t, "explode")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestRulesCheck(t *testing.T) {
	code, out, errOut := run(t, "rules", "check")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	if !strings.Contains(out, "rules: ok") {
		t.Fatalf("stdout = %q", out)
	}
}

func TestRulesShow(t *testing.T) {
	code, out, errOut := run(t, "rules", "show", "sigma")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	if !strings.Contains(out, "title: php2shell") {
		t.Fatalf("unexpected rule output: %.80q", out)
	}
}

func TestVerifyRefusesPublicTarget(t *testing.T) {
	code, _, errOut := run(t, "verify", "chain-a", "--target", "http://8.8.8.8")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "non-local target") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestVerifyAllSkipsExperimental(t *testing.T) {
	code, out, _ := run(t,
		"verify", "all",
		"--fpm-target", "http://127.0.0.1:1",
		"--apache-target", "http://127.0.0.1:1",
		"--attempts", "1",
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (targets are closed)", code)
	}
	if !strings.Contains(out, "[SKIP] chain E") {
		t.Fatalf("expected chain E skip notice, got:\n%s", out)
	}
	if strings.Contains(out, "chain E: producer") {
		t.Fatalf("chain E should not run without --experimental:\n%s", out)
	}
}

func TestHelp(t *testing.T) {
	code, out, _ := run(t, "help")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "php2shell verify") {
		t.Fatalf("help output = %q", out)
	}
}
