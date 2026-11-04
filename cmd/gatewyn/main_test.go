package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
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
