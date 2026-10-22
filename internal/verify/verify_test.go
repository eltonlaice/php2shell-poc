package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestChainA(t *testing.T) {
	var injected atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.php":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "P2S_A_START") {
				injected.Store(true)
			}
			w.WriteHeader(200)
		case "/vuln.php":
			if injected.Load() {
				_, _ = io.WriteString(w, "P2S_A_STARTuid=0(root)P2S_A_END")
				return
			}
			_, _ = io.WriteString(w, "not found")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	opt := DefaultOptions(srv.URL)
	opt.Stall = false
	res, err := ChainA(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain A not confirmed: %+v", res)
	}
	if !strings.Contains(res.Summary, "uid=0") {
		t.Fatalf("summary = %q", res.Summary)
	}
}

func TestChainC(t *testing.T) {
	var uploaded atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/upload.php":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "Evil") && strings.Contains(string(b), "O:4:") {
				uploaded.Store(true)
			}
			w.WriteHeader(200)
		case "/api/endpoint.php":
			if uploaded.Load() && strings.Contains(r.Header.Get("Cookie"), "PHPSESSID=") {
				_, _ = io.WriteString(w, "P2S_C_MARK:uid=0(root):P2S_C_END")
				return
			}
			_, _ = io.WriteString(w, "plain")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	opt := DefaultOptions(srv.URL)
	opt.Attempts = 1
	res, err := ChainC(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain C not confirmed: %+v", res)
	}
}

func TestChainD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "Fatal error: Allowed memory size of 33554432 bytes exhausted (tried to allocate 20480 bytes)")
	}))
	defer srv.Close()

	opt := DefaultOptions(srv.URL)
	opt.Headers = 10
	opt.HeaderSize = 8
	res, err := ChainD(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain D not confirmed: %+v", res)
	}
	if !strings.Contains(res.Summary, "crash primitive") {
		t.Fatalf("summary should be explicit about crash-only: %q", res.Summary)
	}
}

func TestChainE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seed_session.php":
			_, _ = io.WriteString(w, "seeded")
		case "/session_oom.php":
			_, _ = io.WriteString(w, "Fatal error: Allowed memory size of 33554432 bytes exhausted")
		case "/nosession.php":
			_, _ = io.WriteString(w, "Warning: Session object destruction failed")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	opt := DefaultOptions(srv.URL)
	opt.Attempts = 1
	opt.Size = 1024
	res, err := ChainE(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain E not confirmed: %+v", res)
	}
}

func TestRefusesPublicTarget(t *testing.T) {
	opt := DefaultOptions("http://8.8.8.8:80")
	if _, err := ChainA(context.Background(), opt); err == nil {
		t.Fatal("expected guard error for public target")
	}
}
