package caddyproc

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeCaddy écrit un script qui note chaque lancement dans un fichier puis exécute cmd.
func fakeCaddy(t *testing.T, cmd string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "starts")
	bin = filepath.Join(dir, "caddy")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n" + cmd + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func starts(log string) int {
	b, _ := os.ReadFile(log)
	return strings.Count(string(b), "run\n")
}

func TestRestartsCaddyWhenItExitsAndRepublishesEachTime(t *testing.T) {
	restartDelay = 20 * time.Millisecond
	bin, log := fakeCaddy(t, "exit 1")
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	done := make(chan struct{})
	go func() { Run(ctx, bin, func(context.Context) { started.Add(1) }, quiet, nil); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for starts(log) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if starts(log) < 3 {
		t.Errorf("%d démarrages seulement", starts(log))
	}
	if started.Load() < 3 {
		t.Errorf("onStart appelé %d fois, attendu au moins 3 (une fois par démarrage)", started.Load())
	}
}

func TestStopsCaddyWhenContextIsCancelled(t *testing.T) {
	bin, log := fakeCaddy(t, "exec sleep 60")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, bin, func(context.Context) {}, quiet, nil); close(done) }()
	for i := 0; i < 200 && starts(log) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ne rend pas la main après l'annulation : Caddy n'a pas reçu SIGTERM")
	}
	if starts(log) != 1 {
		t.Errorf("%d démarrages, attendu 1 (pas de relance après l'annulation)", starts(log))
	}
}

func TestMissingBinaryDoesNotSpinAndStopsOnCancel(t *testing.T) {
	restartDelay = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		Run(ctx, "/nonexistent/caddy", func(context.Context) { t.Error("onStart appelé sans Caddy") }, quiet, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run ne s'arrête pas")
	}
}
