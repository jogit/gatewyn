package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jogit/gatewyn/internal/auth"
	"github.com/jogit/gatewyn/internal/store"
)

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("chemin interrogé : %s", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	if got := healthcheck(addr); got != 0 {
		t.Errorf("serveur sain : code %d", got)
	}
	// L'adresse d'écoute de l'image (« :8080 ») sans hôte : la sonde interroge le local.
	if got := healthcheck(":" + port); got != 0 {
		t.Errorf("adresse sans hôte : code %d", got)
	}
	status = http.StatusServiceUnavailable
	if got := healthcheck(addr); got != 1 {
		t.Errorf("serveur malade : code %d", got)
	}
	srv.Close()
	if got := healthcheck(addr); got != 1 {
		t.Errorf("serveur arrêté : code %d", got)
	}
	if got := healthcheck("pas-une-adresse"); got != 1 {
		t.Errorf("adresse invalide : code %d", got)
	}
}

func TestResetPassword(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := resetPassword(ctx, st); err == nil {
		t.Fatal("sans compte, la réinitialisation doit échouer")
	}
	if ok, _ := st.AdminExists(ctx); ok {
		t.Fatal("la réinitialisation ne doit pas créer de compte")
	}

	old, _ := auth.HashPassword("ancien-mot-de-passe")
	if err := st.CreateAdmin(ctx, "admin", old); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, "session", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	pw, err := resetPassword(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidatePassword(pw); err != nil {
		t.Errorf("mot de passe généré refusé par l'interface : %v", err)
	}
	_, hash, _ := st.AdminCredentials(ctx)
	if !auth.VerifyPassword(pw, hash) || auth.VerifyPassword("ancien-mot-de-passe", hash) {
		t.Error("le mot de passe n'a pas été remplacé")
	}
	if ok, _ := st.SessionValid(ctx, "session"); ok {
		t.Error("les sessions doivent être fermées")
	}
	if pw2, _ := resetPassword(ctx, st); pw2 == pw {
		t.Error("le mot de passe généré doit être aléatoire")
	}
}
