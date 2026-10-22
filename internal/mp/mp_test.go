package mp

import (
	"bytes"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
)

func TestWriteRoundTrip(t *testing.T) {
	b := NewWithBoundary("TESTBOUNDARY")
	body, err := b.Bytes(
		Part{Name: "sid", Value: []byte("abc123")},
		Part{Name: "f", Filename: "hello.txt", Value: []byte("data")},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, params, err := mime.ParseMediaType(b.ContentType())
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])

	p1, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if p1.FormName() != "sid" {
		t.Fatalf("form name = %q", p1.FormName())
	}
	got := new(bytes.Buffer)
	_, _ = got.ReadFrom(p1)
	if got.String() != "abc123" {
		t.Fatalf("value = %q", got.String())
	}

	p2, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if p2.FileName() != "hello.txt" {
		t.Fatalf("filename = %q", p2.FileName())
	}
}

func TestFilenameQuotesAreRaw(t *testing.T) {
	b := NewWithBoundary("B")
	body, err := b.Bytes(Part{
		Name:     "f",
		Filename: `x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}`,
		Value:    []byte("Z"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `filename="x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}"`
	if !bytes.Contains(body, []byte(want)) {
		t.Fatalf("raw filename not preserved:\n%s", body)
	}
}

func TestRejectsCRLF(t *testing.T) {
	b := NewWithBoundary("B")
	if _, err := b.Bytes(Part{Name: "f", Filename: "a\r\nX: y", Value: []byte("z")}); err == nil {
		t.Fatal("expected error for CRLF filename")
	}
}

func TestBytesHeadOmitsClosingBoundary(t *testing.T) {
	b := NewWithBoundary("B")
	head, err := b.BytesHead(Part{Name: "f", Filename: "a", Value: []byte("z")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(head), "--B--") {
		t.Fatal("head contains closing boundary")
	}
}
