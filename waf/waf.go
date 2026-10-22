// Package waf implements an HTTP middleware that blocks the request shapes
// used by the php2shell chains: a session id supplied in the multipart body,
// an upload-progress trigger, PHP code or serialized objects in a filename,
// and chunked multipart bodies that bypass post_max_size accounting.
//
// It is intentionally conservative: it only inspects multipart requests and
// never rewrites them. When a body is buffered for inspection it is restored
// byte for byte before the next handler runs.
package waf

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

// Violation is one matched detection rule.
type Violation struct {
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// Config controls the middleware.
type Config struct {
	// Block rejects matching requests with 403. When false the middleware
	// only logs (same as LogOnly).
	Block bool
	// LogOnly forces observe-only mode even when Block is true.
	LogOnly bool
	// MaxBody is the maximum number of bytes buffered for inspection.
	MaxBody int64
	// Logger receives one line per violation. Defaults to slog.Default().
	Logger *slog.Logger
	// SessionName is the PHP session name to look for in the body.
	SessionName string
	// BlockChunked rejects chunked multipart uploads. Off by default because
	// some legitimate clients stream uploads.
	BlockChunked bool
}

// DefaultConfig returns the recommended configuration.
func DefaultConfig() Config {
	return Config{
		Block:       true,
		MaxBody:     8 << 20,
		Logger:      slog.Default(),
		SessionName: "PHPSESSID",
	}
}

func (c Config) sessionName() string {
	if c.SessionName == "" {
		return "PHPSESSID"
	}
	return c.SessionName
}

func (c Config) logger() *slog.Logger {
	if c.Logger == nil {
		return slog.Default()
	}
	return c.Logger
}

// Handler wraps next with the php2shell checks.
func (c Config) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		violations := c.InspectRequest(r)

		for _, v := range violations {
			c.logger().Warn("php2shell waf",
				"rule", v.Rule,
				"detail", v.Detail,
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"action", c.action(),
			)
		}

		if len(violations) > 0 && c.Block && !c.LogOnly {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":      "blocked by php2shell waf",
				"violations": violations,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c Config) action() string {
	if c.Block && !c.LogOnly {
		return "blocked"
	}
	return "logged"
}

// InspectRequest checks r and restores r.Body so downstream handlers can read
// it. It never consumes more than MaxBody bytes before handing the request on.
func (c Config) InspectRequest(r *http.Request) []Violation {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(ct), "multipart/form-data") {
		return nil
	}

	var out []Violation
	seen := map[string]bool{}
	add := func(v Violation) {
		if seen[v.Rule] {
			return
		}
		seen[v.Rule] = true
		out = append(out, v)
	}

	if c.BlockChunked {
		for _, te := range r.TransferEncoding {
			if strings.EqualFold(te, "chunked") {
				add(Violation{Rule: "chunked-multipart", Detail: "chunked multipart body can bypass post_max_size"})
			}
		}
	}

	limit := c.MaxBody
	if limit <= 0 {
		limit = 8 << 20
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return out
	}
	if int64(len(body)) > limit {
		// Too large to inspect fully. Keep the prefix and stream the rest.
		body = body[:limit]
		r.Body = readCloser{
			Reader: io.MultiReader(bytes.NewReader(body), r.Body),
			Closer: r.Body,
		}
		return out
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	_, params, err := mime.ParseMediaType(ct)
	if err != nil || params["boundary"] == "" {
		return out
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		name := part.FormName()
		filename := part.FileName()

		if name != "" && name == c.sessionName() {
			add(Violation{Rule: "session-in-body", Detail: "session id supplied as a form field: " + name})
		}
		if name == "PHP_SESSION_UPLOAD_PROGRESS" {
			add(Violation{Rule: "upload-progress", Detail: "upload progress trigger in multipart body"})
		}
		if filename != "" {
			if strings.Contains(filename, "<?") {
				add(Violation{Rule: "filename-php", Detail: "PHP open tag in upload filename"})
			}
			for _, marker := range []string{"|O:", "|a:", "|C:", "|s:"} {
				if strings.Contains(filename, marker) {
					add(Violation{Rule: "filename-serialized", Detail: "serialized object marker in upload filename: " + marker})
					break
				}
			}
		}
		_, _ = io.Copy(io.Discard, part)
	}

	// The multipart parser rejects unescaped quotes in a filename, which is
	// exactly how a hand-crafted exploit may be sent. Scan the raw body for
	// the filename prefix as a fallback so malformed parts are still caught.
	for _, v := range rawFilenameViolations(body) {
		add(v)
	}
	return out
}

func rawFilenameViolations(body []byte) []Violation {
	var out []Violation
	idx := 0
	for {
		i := bytes.Index(body[idx:], []byte(`filename="`))
		if i < 0 {
			break
		}
		start := idx + i + len(`filename="`)
		end := start + 512
		if end > len(body) {
			end = len(body)
		}
		// Stay on the header line: binary file content after the CRLF must not
		// be mistaken for a filename payload.
		if nl := bytes.IndexByte(body[start:], '\n'); nl >= 0 && start+nl < end {
			end = start + nl
		}
		seg := body[start:end]
		if bytes.Contains(seg, []byte("<?php")) || bytes.Contains(seg, []byte("<?")) {
			out = append(out, Violation{Rule: "filename-php", Detail: "PHP open tag after filename= in raw body"})
		}
		for _, marker := range [][]byte{[]byte("|O:"), []byte("|a:"), []byte("|C:"), []byte("|s:")} {
			if bytes.Contains(seg, marker) {
				out = append(out, Violation{Rule: "filename-serialized", Detail: "serialized marker after filename= in raw body"})
				break
			}
		}
		idx = start
	}
	return out
}

type readCloser struct {
	io.Reader
	io.Closer
}
