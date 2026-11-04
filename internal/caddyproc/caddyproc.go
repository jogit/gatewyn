// Package caddyproc lance Caddy comme processus fils de Gatewyn et le relance
// s'il s'arrête, pour que l'image n'ait qu'un seul service (comme NPM).
package caddyproc

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// restartDelay est l'attente avant de relancer Caddy ; variable pour les tests.
var restartDelay = 2 * time.Second

// Run exécute « bin run » jusqu'à l'annulation de ctx. Les journaux de Caddy vont à out
// (os.Stderr si nil). À chaque démarrage,
// onStart est appelé dans sa propre goroutine (pour republier les hôtes une
// fois que Caddy répond). Caddy reçoit SIGTERM à l'annulation de ctx ; Run ne
// rend la main qu'une fois Caddy arrêté.
func Run(ctx context.Context, bin string, onStart func(ctx context.Context), log *slog.Logger, out io.Writer) {
	if out == nil {
		out = os.Stderr
	}
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, bin, "run")
		cmd.Stdout, cmd.Stderr = out, out
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 10 * time.Second

		if err := cmd.Start(); err != nil {
			log.Error("Caddy failed to start", "binary", bin, "error", err)
		} else {
			log.Info("Caddy started", "pid", cmd.Process.Pid)
			go onStart(ctx)
			err = cmd.Wait()
			if ctx.Err() != nil {
				return
			}
			log.Warn("Caddy stopped, restarting", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(restartDelay):
		}
	}
}
