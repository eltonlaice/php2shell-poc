// Package cli implements the php2shell command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/eltonlaice/php2shell-poc/internal/verify"
	"github.com/eltonlaice/php2shell-poc/rules"
	"github.com/eltonlaice/php2shell-poc/waf"
)

// Version is the toolkit version.
const Version = "0.1.1"

// Run executes the command line and returns a process exit code.
func Run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		usage(out)
		return 2
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], out, errOut)
	case "lab":
		return runLab(args[1:], out, errOut)
	case "waf":
		return runWAF(args[1:], out, errOut)
	case "rules":
		return runRules(args[1:], out, errOut)
	case "version", "-v", "--version":
		fmt.Fprintln(out, "php2shell-poc", Version)
		return 0
	case "help", "-h", "--help":
		usage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command %q\n\n", args[0])
		usage(errOut)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `php2shell-poc — lab verification and WAF toolkit for php2shell

Usage:
  php2shell verify <chain-a|chain-c|chain-d|chain-e|all> [flags]
  php2shell lab <up|down|status|logs> [flags]
  php2shell waf serve [flags]
  php2shell rules <list|show|check>
  php2shell version

Verification is lab-only by default: non-local targets are refused unless
--allow-public is passed. See README.md and docs/THREAT_MODEL.md.
`)
}

func addCommon(fs *flag.FlagSet, def string) *verify.Options {
	o := verify.DefaultOptions(def)
	fs.StringVar(&o.Target, "target", def, "target base URL")
	fs.BoolVar(&o.AllowPublic, "allow-public", false, "allow non-local targets (only for systems you own)")
	fs.BoolVar(&o.Insecure, "insecure", false, "skip TLS certificate verification")
	fs.DurationVar(&o.Timeout, "timeout", 15*time.Second, "per-request timeout")
	fs.StringVar(&o.Command, "command", "id", "command to execute on a successful chain")
	fs.StringVar(&o.SessionDir, "session-dir", "/tmp/sessions", "session.save_path on the target")
	fs.IntVar(&o.Attempts, "attempts", 3, "attempts for race-dependent steps")
	return &o
}

func runVerify(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: php2shell verify <chain-a|chain-c|chain-d|chain-e|all> [flags]")
		return 2
	}
	ctx := context.Background()
	switch args[0] {
	case "chain-a":
		fs := flag.NewFlagSet("chain-a", flag.ContinueOnError)
		fs.SetOutput(errOut)
		o := addCommon(fs, "http://127.0.0.1:18080")
		fs.StringVar(&o.InjectPath, "inject-path", o.InjectPath, "endpoint that calls session_start()")
		fs.StringVar(&o.LFIPath, "lfi-path", o.LFIPath, "application LFI endpoint")
		fs.BoolVar(&o.Stall, "stall", true, "hold the upload open while triggering the LFI")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		res, err := verify.ChainA(ctx, *o)
		return report(out, errOut, res, err)

	case "chain-c":
		fs := flag.NewFlagSet("chain-c", flag.ContinueOnError)
		fs.SetOutput(errOut)
		o := addCommon(fs, "http://127.0.0.1:18080")
		fs.StringVar(&o.PollutePath, "pollute-path", o.PollutePath, "directory using php_serialize")
		fs.StringVar(&o.UploadPath, "upload-path", o.UploadPath, "upload endpoint in the php_serialize directory")
		fs.StringVar(&o.TriggerPath, "trigger-path", o.TriggerPath, "endpoint in the php-handler directory")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		res, err := verify.ChainC(ctx, *o)
		return report(out, errOut, res, err)

	case "chain-d":
		fs := flag.NewFlagSet("chain-d", flag.ContinueOnError)
		fs.SetOutput(errOut)
		o := addCommon(fs, "http://127.0.0.1:18081")
		fs.IntVar(&o.Headers, "headers", 30000, "number of part headers")
		fs.IntVar(&o.HeaderSize, "header-size", 512, "bytes per part header")
		fs.StringVar(&o.OOMath, "path", "/index.php", "endpoint to POST to")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		res, err := verify.ChainD(ctx, *o)
		return report(out, errOut, res, err)

	case "chain-e":
		fs := flag.NewFlagSet("chain-e", flag.ContinueOnError)
		fs.SetOutput(errOut)
		o := addCommon(fs, "http://127.0.0.1:18080")
		fs.Int64Var(&o.Size, "size", 24<<20, "seeded session size in bytes")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		res, err := verify.ChainE(ctx, *o)
		return report(out, errOut, res, err)

	case "all":
		fs := flag.NewFlagSet("all", flag.ContinueOnError)
		fs.SetOutput(errOut)
		fpm := fs.String("fpm-target", "http://127.0.0.1:18080", "FPM target (chains A and C)")
		apache := fs.String("apache-target", "http://127.0.0.1:18081", "mod_php target (chain D)")
		allow := fs.Bool("allow-public", false, "allow non-local targets")
		cmd := fs.String("command", "id", "command to execute")
		attempts := fs.Int("attempts", 3, "attempts for race-dependent steps")
		experimental := fs.Bool("experimental", false, "also run chain E (not reproduced in the lab)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		base := verify.DefaultOptions(*fpm)
		base.AllowPublic = *allow
		base.Command = *cmd
		base.Attempts = *attempts

		var results []verify.Result
		var errs []error

		a, errA := verify.ChainA(ctx, base)
		c, errC := verify.ChainC(ctx, base)
		dOpt := base
		dOpt.Target = *apache
		d, errD := verify.ChainD(ctx, dOpt)
		results = append(results, a, c, d)
		errs = append(errs, errA, errC, errD)

		if *experimental {
			e, errE := verify.ChainE(ctx, base)
			results = append(results, e)
			errs = append(errs, errE)
		} else {
			fmt.Fprintln(out, "[SKIP] chain E: experimental (use --experimental to include it)")
		}

		failed := 0
		for _, err := range errs {
			if err != nil {
				fmt.Fprintln(errOut, "error:", err)
				failed++
			}
		}
		for _, r := range results {
			fmt.Fprintln(out, r.String())
			if !r.OK {
				failed++
			}
		}
		if failed > 0 {
			return 1
		}
		return 0

	default:
		fmt.Fprintf(errOut, "unknown verification %q\n", args[0])
		return 2
	}
}

func report(out, errOut io.Writer, res verify.Result, err error) int {
	if err != nil {
		fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	fmt.Fprintln(out, res.String())
	if !res.OK {
		return 1
	}
	return 0
}

func runLab(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: php2shell lab <up|down|status|logs> [--dir lab]")
		return 2
	}
	fs := flag.NewFlagSet("lab", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("dir", "lab", "directory containing docker-compose.yml")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	compose := filepath.Join(*dir, "docker-compose.yml")
	if _, err := os.Stat(compose); err != nil {
		fmt.Fprintf(errOut, "lab: %s not found; run from the repository root or pass --dir\n", compose)
		return 1
	}
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(errOut, "lab: docker not found in PATH")
		return 1
	}

	var cmd *exec.Cmd
	switch args[0] {
	case "up":
		cmd = exec.Command("docker", "compose", "-f", compose, "up", "-d")
	case "down":
		cmd = exec.Command("docker", "compose", "-f", compose, "down", "--remove-orphans")
	case "status":
		cmd = exec.Command("docker", "compose", "-f", compose, "ps")
	case "logs":
		cmd = exec.Command("docker", "compose", "-f", compose, "logs", "--tail=100")
	default:
		fmt.Fprintf(errOut, "unknown lab command %q\n", args[0])
		return 2
	}
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(errOut, "lab:", err)
		return 1
	}
	return 0
}

func runWAF(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintln(errOut, "usage: php2shell waf serve [flags]")
		return 2
	}
	fs := flag.NewFlagSet("waf", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", "127.0.0.1:8080", "listen address")
	upstream := fs.String("upstream", "http://127.0.0.1:18080", "upstream PHP application")
	logOnly := fs.Bool("log-only", false, "log violations without blocking")
	maxBody := fs.Int64("max-body", 8<<20, "bytes buffered for inspection")
	sessionName := fs.String("session-name", "PHPSESSID", "PHP session name")
	blockChunked := fs.Bool("block-chunked", false, "reject chunked multipart uploads")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	u, err := url.Parse(*upstream)
	if err != nil {
		fmt.Fprintln(errOut, "waf: invalid upstream:", err)
		return 1
	}
	logger := slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := waf.Config{
		Block:        true,
		LogOnly:      *logOnly,
		MaxBody:      *maxBody,
		Logger:       logger,
		SessionName:  *sessionName,
		BlockChunked: *blockChunked,
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           cfg.Handler(proxy),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("waf listening", "listen", *listen, "upstream", u.String(), "log_only", *logOnly)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(errOut, "waf:", err)
		return 1
	}
	return 0
}

func runRules(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: php2shell rules <list|show|check>")
		return 2
	}
	switch args[0] {
	case "list":
		files, err := rules.Files()
		if err != nil {
			fmt.Fprintln(errOut, "rules:", err)
			return 1
		}
		for _, f := range files {
			fmt.Fprintln(out, f)
		}
		return 0
	case "show":
		if len(args) < 2 {
			fmt.Fprintln(errOut, "usage: php2shell rules show <suricata|sigma|modsecurity>")
			return 2
		}
		b, err := rules.Get(args[1])
		if err != nil {
			fmt.Fprintln(errOut, "rules:", err)
			return 1
		}
		_, _ = out.Write(b)
		return 0
	case "check":
		if err := rules.Validate(); err != nil {
			fmt.Fprintln(errOut, "rules:", err)
			return 1
		}
		fmt.Fprintln(out, "rules: ok")
		return 0
	default:
		fmt.Fprintf(errOut, "unknown rules command %q\n", args[0])
		return 2
	}
}
