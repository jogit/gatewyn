// Commande gatewyn : interface web pour publier des services en HTTPS avec Caddy.
//
// Configuration par variables d'environnement :
//
//	GATEWYN_LISTEN          adresse d'écoute (défaut 127.0.0.1:8080 : local seulement)
//	GATEWYN_DB              fichier SQLite (défaut gatewyn.db)
//	GATEWYN_CADDY_BIN       chemin du binaire Caddy : Gatewyn le lance et le relance (image Docker).
//	                        Vide : Gatewyn pilote un Caddy déjà lancé, ailleurs.
//	GATEWYN_CADDY_URL       API d'administration de Caddy (défaut http://127.0.0.1:2019)
//	GATEWYN_PUBLIC_IP       adresses publiques de cette machine, séparées par des virgules
//	GATEWYN_SECURE_COOKIES  "1" derrière HTTPS
//	GATEWYN_KEY_FILE        clé de chiffrement des identifiants DNS (défaut : secret.key à côté de la base)
//	GATEWYN_CERT_DIR        dossier des certificats de Caddy (page Certificats) ; vide : page indisponible
//	GATEWYN_NO_LOGIN        "1" supprime le mot de passe (essais en local seulement)
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jogit/gatewyn/internal/acmelog"
	"github.com/jogit/gatewyn/internal/auth"
	"github.com/jogit/gatewyn/internal/caddyadmin"
	"github.com/jogit/gatewyn/internal/caddyproc"
	"github.com/jogit/gatewyn/internal/secrets"
	"github.com/jogit/gatewyn/internal/store"
	"github.com/jogit/gatewyn/internal/web"
)

// version est la version de Gatewyn ; l'image Docker la remplace à la construction (-ldflags -X).
var version = "0.1.0"

// healthcheck interroge le serveur local (sonde de santé de l'image, qui n'a ni shell ni curl).
// Renvoie 0 si /healthz répond 200.
func healthcheck(listen string) int {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(env("GATEWYN_LISTEN", "127.0.0.1:8080")))
	}
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		os.Exit(runResetPassword())
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("shutdown", "error", err)
		os.Exit(1)
	}
}

// resetPassword remplace le mot de passe administrateur par un mot de passe aléatoire, ferme toutes
// les sessions et le renvoie. Il sert quand le mot de passe est perdu :
// docker exec <conteneur> /gatewyn reset-password
func resetPassword(ctx context.Context, st *store.Store) (string, error) {
	if exists, err := st.AdminExists(ctx); err != nil {
		return "", err
	} else if !exists {
		return "", errors.New("aucun compte administrateur : créez-le depuis l'interface")
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	pw := base64.RawURLEncoding.EncodeToString(b)
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return "", err
	}
	if err := st.ChangePassword(ctx, hash, ""); err != nil {
		return "", err
	}
	_ = st.Audit(ctx, "password.reset", "mot de passe réinitialisé en ligne de commande")
	return pw, nil
}

func runResetPassword() int {
	st, err := store.Open(env("GATEWYN_DB", "gatewyn.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer st.Close()
	pw, err := resetPassword(context.Background(), st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Println("New administrator password (all sessions are closed, change it in Settings):")
	fmt.Println(pw)
	return 0
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger) error {
	listen := env("GATEWYN_LISTEN", "127.0.0.1:8080")
	dbPath := env("GATEWYN_DB", "gatewyn.db")
	caddyURL := env("GATEWYN_CADDY_URL", "http://127.0.0.1:2019")
	var publicIPs []string
	for _, ip := range strings.Split(os.Getenv("GATEWYN_PUBLIC_IP"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			publicIPs = append(publicIPs, ip)
		}
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	box, err := secrets.Open(env("GATEWYN_KEY_FILE", filepath.Join(filepath.Dir(dbPath), "secret.key")))
	if err != nil {
		return err
	}

	caddy := caddyadmin.New(caddyURL)
	certs := acmelog.New() // échecs de certificat lus dans les journaux de Caddy
	srv, err := web.New(web.Config{
		Store: st, Caddy: caddy, PublicIPs: publicIPs,
		SecureCookies:   env("GATEWYN_SECURE_COOKIES", "") == "1",
		NoLogin:         env("GATEWYN_NO_LOGIN", "") == "1",
		CertDir:         env("GATEWYN_CERT_DIR", ""),
		CertFailures:    certs,
		AccessLogFile:   env("GATEWYN_ACCESS_LOG", filepath.Join(filepath.Dir(dbPath), "logs", "access.log")),
		GoAccessURL:     env("GATEWYN_GOACCESS_URL", ""),
		CrowdSecKeyFile: env("GATEWYN_CROWDSEC_KEY_FILE", ""),
		Secrets:         box,
		Logger:          log,
	})
	if err != nil {
		return err
	}
	if env("GATEWYN_NO_LOGIN", "") == "1" {
		log.Warn("GATEWYN_NO_LOGIN=1: no password required, for local testing only")
	}
	if len(publicIPs) == 0 {
		log.Info("GATEWYN_PUBLIC_IP is not set: domain DNS will be checked without comparing to your public address")
	}

	// Remet Caddy dans l'état enregistré : une fois au démarrage, et après chaque
	// relance de Caddy s'il est supervisé. Caddy peut mettre quelques secondes à répondre.
	publish := func(ctx context.Context) {
		var err error
		for i := 0; i < 20 && ctx.Err() == nil; i++ {
			// Caddy relance son serveur d'administration à chaque changement de configuration :
			// une requête reçue à ce moment-là échoue (EOF), on réessaie.
			if err = caddy.Ping(ctx); err == nil {
				if err = srv.Sync(ctx); err == nil {
					return
				}
			}
			time.Sleep(time.Second)
		}
		if ctx.Err() == nil {
			log.Warn("Caddy could not be configured; try again by editing a host", "error", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	caddyDone := make(chan struct{})
	if bin := env("GATEWYN_CADDY_BIN", ""); bin != "" {
		go func() { caddyproc.Run(ctx, bin, publish, log, certs.Wrap(os.Stderr)); close(caddyDone) }()
	} else {
		close(caddyDone)
		go publish(ctx)
	}

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()

	log.Info("Gatewyn starting", "version", version, "address", listen, "caddy", caddyURL)
	err = httpSrv.ListenAndServe()
	stop()
	<-caddyDone // Caddy reçoit SIGTERM et s'arrête proprement avant la fin du processus
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
