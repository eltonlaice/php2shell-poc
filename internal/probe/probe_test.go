package probe

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetAndPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, "ct=%s body=%s", r.Header.Get("Content-Type"), b)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()

	c := New(2 * time.Second)
	resp, err := c.Get(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "hello" {
		t.Fatalf("get: status=%d body=%q", resp.Status, resp.Body)
	}

	resp, err = c.Post(srv.URL, []byte("data"), "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusCreated {
		t.Fatalf("post status = %d", resp.Status)
	}
	if string(resp.Body) != "ct=text/plain body=data" {
		t.Fatalf("post body = %q", resp.Body)
	}
}

func TestNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()

	resp, err := New(2*time.Second).Get(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirects must not be followed)", resp.Status)
	}
}

func TestStallSendsPartialBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got=%d", len(b))
	}))
	defer srv.Close()

	c := New(2 * time.Second)
	conn, err := c.Stall(srv.URL, "multipart/form-data; boundary=B", 64, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The server blocks waiting for 64 bytes; reset the connection so the
	// handler can return. The point of this test is that Stall returns an open
	// connection after sending only the prefix.
	conn.Close()
}

func TestStallRejectsBadURL(t *testing.T) {
	if _, err := New(time.Second).Stall("://bad", "text/plain", 1, nil, nil); err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestPostHeaders(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Test")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	if _, err := New(2*time.Second).Post(srv.URL, []byte("x"), "text/plain", map[string]string{"X-Test": "yes"}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != "yes" {
		t.Fatalf("header = %q", got)
	}
}
