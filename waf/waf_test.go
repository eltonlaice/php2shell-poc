package waf

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eltonlaice/php2shell-poc/internal/mp"
)

func body(t *testing.T, parts ...mp.Part) ([]byte, string) {
	t.Helper()
	b := mp.NewWithBoundary("WAFTEST")
	body, err := b.Bytes(parts...)
	if err != nil {
		t.Fatal(err)
	}
	return body, b.ContentType()
}

func invoke(t *testing.T, cfg Config, body []byte, ct string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(200)
	})
	req := httptest.NewRequest(http.MethodPost, "http://lab/index.php", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	cfg.Handler(next).ServeHTTP(rec, req)
	return rec, seen
}

func TestBlocksUploadProgress(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "PHP_SESSION_UPLOAD_PROGRESS", Value: []byte("x")})
	rec, _ := invoke(t, DefaultConfig(), b, ct)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestBlocksSessionInBody(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "PHPSESSID", Value: []byte("abc")})
	rec, _ := invoke(t, DefaultConfig(), b, ct)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestBlocksPHPInFilename(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "f", Filename: `<?php system($_GET['c']); ?>`, Value: []byte("Z")})
	rec, _ := invoke(t, DefaultConfig(), b, ct)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestBlocksSerializedFilename(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "f", Filename: `x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}`, Value: []byte("Z")})
	rec, _ := invoke(t, DefaultConfig(), b, ct)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAllowsBenignUploadAndRestoresBody(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "file", Filename: "holiday.jpg", Value: []byte("jpegbytes")})
	rec, seen := invoke(t, DefaultConfig(), b, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !bytes.Equal([]byte(seen), b) {
		t.Fatalf("downstream body mismatch: %d vs %d bytes", len(seen), len(b))
	}
}

func TestLogOnlyPasses(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "PHP_SESSION_UPLOAD_PROGRESS", Value: []byte("x")})
	cfg := DefaultConfig()
	cfg.LogOnly = true
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	rec, _ := invoke(t, cfg, b, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestIgnoresNonMultipart(t *testing.T) {
	cfg := DefaultConfig()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	req := httptest.NewRequest(http.MethodPost, "http://lab/index.php", strings.NewReader("PHP_SESSION_UPLOAD_PROGRESS=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	cfg.Handler(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestBlockChunked(t *testing.T) {
	b, ct := body(t, mp.Part{Name: "f", Filename: "a", Value: []byte("z")})
	cfg := DefaultConfig()
	cfg.BlockChunked = true
	req := httptest.NewRequest(http.MethodPost, "http://lab/index.php", bytes.NewReader(b))
	req.Header.Set("Content-Type", ct)
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
