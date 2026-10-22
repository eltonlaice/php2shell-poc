// Package mp builds multipart/form-data bodies byte for byte.
//
// It deliberately does not use mime/multipart.Writer: this toolkit needs to
// emit filenames verbatim, including quotes and pipe characters, because the
// php2shell chains rely on the PHP multipart parser storing those bytes
// unmodified in the session file.
package mp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Part is a single multipart body part.
type Part struct {
	// Name is the form field name. It is written inside a quoted string and
	// therefore must not contain CR, LF or a double quote.
	Name string
	// Filename is written verbatim between filename=" and ". Quotes are not
	// escaped on purpose; CR and LF are rejected to keep the request valid.
	Filename string
	// Value is the part body.
	Value []byte
	// Headers are extra part headers, written in order after Content-Disposition.
	Headers [][2]string
	// NoContentType suppresses the default Content-Type for file parts.
	NoContentType bool
}

// Builder writes multipart bodies with a fixed boundary.
type Builder struct {
	Boundary string
}

// New returns a Builder with a random boundary.
func New() *Builder {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failures are unrecoverable in practice; a static
		// boundary keeps the toolkit usable in constrained environments.
		return &Builder{Boundary: "----php2shellstaticboundary"}
	}
	return &Builder{Boundary: "----php2shell" + hex.EncodeToString(b[:])}
}

// NewWithBoundary returns a Builder using boundary.
func NewWithBoundary(boundary string) *Builder {
	return &Builder{Boundary: boundary}
}

// ContentType returns the matching Content-Type header value.
func (b *Builder) ContentType() string {
	return "multipart/form-data; boundary=" + b.Boundary
}

// Write encodes parts and the closing boundary to w.
func (b *Builder) Write(w io.Writer, parts ...Part) (int64, error) {
	n, err := b.writeParts(w, parts...)
	if err != nil {
		return n, err
	}
	written, err := fmt.Fprintf(w, "--%s--\r\n", b.Boundary)
	return n + int64(written), err
}

// Bytes returns the encoded body.
func (b *Builder) Bytes(parts ...Part) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := b.Write(&buf, parts...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BytesHead returns the encoded parts without the closing boundary. It is used
// to keep an upload request open (Content-Length declares more bytes than are
// sent) while the PHP upload-progress entry still exists.
func (b *Builder) BytesHead(parts ...Part) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := b.writeParts(&buf, parts...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Builder) writeParts(w io.Writer, parts ...Part) (int64, error) {
	if b.Boundary == "" {
		return 0, errors.New("mp: empty boundary")
	}
	var total int64
	for _, p := range parts {
		if p.Name == "" {
			return total, errors.New("mp: empty part name")
		}
		if strings.ContainsAny(p.Name, "\r\n\"") {
			return total, fmt.Errorf("mp: invalid part name %q", p.Name)
		}
		if strings.ContainsAny(p.Filename, "\r\n") {
			return total, errors.New("mp: filename must not contain CR or LF")
		}

		var head bytes.Buffer
		fmt.Fprintf(&head, "--%s\r\n", b.Boundary)
		fmt.Fprintf(&head, "Content-Disposition: form-data; name=\"%s\"", p.Name)
		if p.Filename != "" {
			// Raw on purpose: no escaping, no quoting.
			head.WriteString("; filename=\"")
			head.WriteString(p.Filename)
			head.WriteString("\"\r\n")
			if !p.NoContentType {
				head.WriteString("Content-Type: application/octet-stream\r\n")
			}
		} else {
			head.WriteString("\r\n")
		}
		for _, h := range p.Headers {
			if strings.ContainsAny(h[0], ":\r\n") || strings.ContainsAny(h[1], "\r\n") {
				return total, fmt.Errorf("mp: invalid header %q", h[0])
			}
			fmt.Fprintf(&head, "%s: %s\r\n", h[0], h[1])
		}
		head.WriteString("\r\n")

		n, err := w.Write(head.Bytes())
		total += int64(n)
		if err != nil {
			return total, err
		}
		n, err = w.Write(p.Value)
		total += int64(n)
		if err != nil {
			return total, err
		}
		n, err = w.Write([]byte("\r\n"))
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
