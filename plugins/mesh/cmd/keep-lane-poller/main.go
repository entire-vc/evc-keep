// Command keep-lane-poller asks keep-server for pending lane restarts and runs
// the narrow restart wrapper for each. Config comes from the environment:
//
//	KEEP_URL                  server base URL
//	KEEP_POLLER_TOKEN_FILE    mode-600 env file with a KEEP_POLLER_TOKEN=<token> line (or the bare token)
//	KEEP_LANE_RESTART_SCRIPT  absolute path of keep-lane-restart.sh
//	KEEP_POLL_INTERVAL        optional, default 30s
//	KEEP_POLL_LANES           comma list of lanes the poller may restart (required)
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/entire-vc/evc-keep/plugins/mesh/lanepoller"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("keep-lane-poller", "err", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	file := os.Getenv("KEEP_POLLER_TOKEN_FILE")
	if file == "" {
		return fmt.Errorf("KEEP_POLLER_TOKEN_FILE is not set")
	}
	if err := checkTokenFile(file); err != nil {
		return err
	}
	raw, err := os.ReadFile(file) //nolint:gosec // operator-set path to the token file
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	token, err := tokenOf(string(raw))
	if err != nil {
		return err
	}
	interval := 30 * time.Second
	if s := os.Getenv("KEEP_POLL_INTERVAL"); s != "" {
		if interval, err = time.ParseDuration(s); err != nil || interval < time.Second {
			return fmt.Errorf("KEEP_POLL_INTERVAL must be a duration >= 1s")
		}
	}
	var lanes []string
	for _, l := range strings.Split(os.Getenv("KEEP_POLL_LANES"), ",") {
		if l = strings.TrimSpace(l); l != "" {
			lanes = append(lanes, l)
		}
	}
	p, err := lanepoller.New(lanepoller.Config{
		BaseURL: os.Getenv("KEEP_URL"),
		Token:   token,
		Script:  os.Getenv("KEEP_LANE_RESTART_SCRIPT"),
		Allow:   lanes,
		Log:     log,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("started", "lanes", strings.Join(lanes, ","), "interval", interval.String())
	p.Run(ctx, interval)
	return nil
}

// tokenOf takes the value of the KEEP_POLLER_TOKEN= line, or the whole content
// when the file is one line without "=" (the bare token). Anything else is
// refused so an unrelated line is never sent as a bearer.
func tokenOf(content string) (string, error) {
	c := strings.TrimSpace(content)
	if v, ok := strings.CutPrefix(c, "KEEP_POLLER_TOKEN="); ok && !strings.Contains(c, "\n") {
		return strings.Trim(v, `"'`), nil
	}
	if c != "" && !strings.ContainsAny(c, "=\n ") {
		return c, nil
	}
	return "", fmt.Errorf("token file must be a single KEEP_POLLER_TOKEN=<token> line or the bare token")
}

// checkTokenFile refuses a token file that anyone but its owner can read or
// that carries bits beyond owner read/write (0600 or 0400 pass).
func checkTokenFile(file string) error {
	fi, err := os.Stat(file) //nolint:gosec // operator-set path to the token file
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if fi.Mode().Perm()&^0o600 != 0 {
		return fmt.Errorf("token file must be mode 600")
	}
	return nil
}
