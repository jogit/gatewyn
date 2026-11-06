// Package web sert l'interface de Gatewyn : gabarits HTML côté serveur et htmx,
// sans étape de compilation JavaScript.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jogit/gatewyn/internal/acmelog"
	"github.com/jogit/gatewyn/internal/auth"
	"github.com/jogit/gatewyn/internal/caddyadmin"
	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/checks"
	"github.com/jogit/gatewyn/internal/dnsprov"
	"github.com/jogit/gatewyn/internal/secrets"
	"github.com/jogit/gatewyn/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	cookieName      = "gatewyn_session"
	sessionLifetime = 12 * time.Hour
	maxFormBytes    = 64 << 10
)

// Publisher publie les hôtes dans Caddy. *caddyadmin.Client le satisfait.
type Publisher interface {
	// ApplyAll publie les hôtes et les réglages globaux (CrowdSec, proxies de confiance).
	ApplyAll(ctx context.Context, hosts []caddyconf.Host, g caddyconf.Global) error
	CrowdSecStatus(ctx context.Context) (caddyadmin.CrowdSecStatus, error)
	Ping(ctx context.Context) error
}

// Config rassemble les dépendances du serveur web.
type Config struct {
	Store     *store.Store
	Caddy     Publisher
	Resolver  checks.Resolver
	PublicIPs []string
	// SecureCookies marque le cookie de session « Secure » (à activer derrière HTTPS).
	SecureCookies bool
	// NoLogin supprime l'authentification : réservé aux essais en local.
	NoLogin bool
	// CertDir est le dossier des certificats de Caddy ; vide si Gatewyn ne peut pas le lire.
	CertDir string
	// CertFailures donne les échecs d'obtention de certificat lus dans les journaux de Caddy (nil : aucun).
	CertFailures *acmelog.Tracker
	// AccessLogFile : fichier du journal d'accès de Caddy (réglage « Statistiques de trafic ») ; vide : indisponible.
	AccessLogFile string
	// GoAccessURL : adresse du service GoAccess (http://goaccess:8080 par défaut), pour la page Statistiques.
	GoAccessURL string
	// Secrets chiffre les identifiants des comptes DNS ; nil : comptes DNS indisponibles.
	Secrets *secrets.Box
	// CrowdSecClient interroge l'API locale de CrowdSec (http.DefaultClient si nil).
	CrowdSecClient *http.Client
	// CrowdSecKeyFile : fichier où CrowdSec dépose la clé du bouncer Gatewyn (compose Gatewyn) ; vide ou absent : la clé se saisit à la main.
	CrowdSecKeyFile string
	// CrowdSecMetricsURL remplace l'adresse des métriques de CrowdSec (déduite de son API locale si vide).
	CrowdSecMetricsURL string
	Logger             *slog.Logger
	// Remplaçables dans les tests.
	CheckDNS    func(ctx context.Context, domain string) checks.Result
	CheckTarget func(ctx context.Context, target string) checks.Result
	Now         func() time.Time
}

// Server est le serveur web de Gatewyn.
type Server struct {
	cfg     Config
	pages   map[string]*template.Template
	limiter *auth.Limiter

	// syncMu sérialise les publications vers Caddy : deux envois entrelacés (démarrage et
	// enregistrement d'un hôte, par exemple) pourraient laisser Caddy sur l'état le plus ancien.
	syncMu sync.Mutex
}

// New construit le serveur.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.CheckDNS == nil {
		cfg.CheckDNS = func(ctx context.Context, d string) checks.Result {
			return checks.DNS(ctx, cfg.Resolver, d, cfg.PublicIPs)
		}
	}
	if cfg.GoAccessURL == "" {
		cfg.GoAccessURL = defaultGoAccessURL
	}
	if cfg.CheckTarget == nil {
		cfg.CheckTarget = checks.Target
	}
	s := &Server{cfg: cfg, pages: map[string]*template.Template{}, limiter: auth.NewLimiter(5, 15*time.Minute)}
	s.limiter.Now = cfg.Now
	for _, name := range []string{"login", "setup", "hosts", "new", "dashboard", "security", "access", "proxies", "listform", "certificates", "dnsform", "dnsaccounts", "stats", "statsinstall", "crowdsecform", "crowdsecinstall", "settings"} {
		t, err := template.ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		s.pages[name] = t
	}
	return s, nil
}

// Handler renvoie le gestionnaire HTTP complet.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /setup", s.setupForm)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)

	mux.HandleFunc("GET /{$}", s.auth(s.dashboard))
	mux.HandleFunc("GET /dashboard/online", s.auth(s.dashboardOnline))
	mux.HandleFunc("GET /hosts", s.auth(s.listPage(caddyconf.KindProxy)))
	mux.HandleFunc("GET /stats", s.auth(s.statsGet))
	mux.HandleFunc("GET /stats/install", s.auth(s.statsInstall))
	mux.HandleFunc("POST /stats/journal", s.auth(s.statsJournal))
	mux.HandleFunc("GET /settings", s.auth(s.settingsPage))
	mux.HandleFunc("POST /settings", s.auth(s.saveSettings))
	mux.HandleFunc("POST /settings/password", s.auth(s.changePassword))
	mux.HandleFunc("GET /certificates", s.auth(s.certificatesPage))
	mux.HandleFunc("GET /certificates/root.crt", s.auth(s.downloadRootCert))
	mux.HandleFunc("GET /certificates/dns", s.auth(s.dnsAccountsPage))
	mux.HandleFunc("GET /certificates/dns/new", s.auth(s.newDNSForm))
	mux.HandleFunc("GET /certificates/dns/fields", s.auth(s.dnsFields))
	mux.HandleFunc("POST /certificates/dns", s.auth(s.createDNS))
	mux.HandleFunc("GET /certificates/dns/{id}/edit", s.auth(s.editDNSForm))
	mux.HandleFunc("POST /certificates/dns/{id}", s.auth(s.updateDNS))
	mux.HandleFunc("POST /certificates/dns/{id}/delete", s.auth(s.deleteDNS))
	mux.HandleFunc("GET /security", s.auth(s.securityPage))
	mux.HandleFunc("GET /security/protection", s.auth(s.crowdSecPage))
	mux.HandleFunc("GET /security/access", s.auth(s.accessPage))
	mux.HandleFunc("GET /security/proxies", s.auth(s.proxiesPage))
	mux.HandleFunc("POST /security/proxies", s.auth(s.saveProxies))
	mux.HandleFunc("GET /security/crowdsec/install", s.auth(s.crowdSecInstallPage))
	mux.HandleFunc("GET /security/crowdsec", s.auth(s.crowdSecFormPage))
	mux.HandleFunc("POST /security/crowdsec", s.auth(s.saveCrowdSecForm))
	mux.HandleFunc("GET /security/crowdsec/status", s.auth(s.crowdSecStatus))
	mux.HandleFunc("POST /security/crowdsec/disable", s.auth(s.setCrowdSecEnabled(false)))
	mux.HandleFunc("POST /security/crowdsec/enable", s.auth(s.setCrowdSecEnabled(true)))
	mux.HandleFunc("POST /security/crowdsec/remove", s.auth(s.removeCrowdSec))
	mux.HandleFunc("GET /security/lists/new", s.auth(s.newListForm))
	mux.HandleFunc("POST /security/lists", s.auth(s.createList))
	mux.HandleFunc("GET /security/lists/{id}/edit", s.auth(s.editListForm))
	mux.HandleFunc("POST /security/lists/{id}", s.auth(s.updateList))
	mux.HandleFunc("POST /security/lists/{id}/delete", s.auth(s.deleteList))
	mux.HandleFunc("GET /redirections", s.auth(s.listPage(caddyconf.KindRedirect)))
	mux.HandleFunc("GET /erreurs-404", s.auth(s.listPage(caddyconf.KindNotFound)))
	mux.HandleFunc("GET /hosts/new", s.auth(s.newForm))
	mux.HandleFunc("GET /hosts/locations/row", s.auth(s.locationRow))
	mux.HandleFunc("GET /hosts/domains/row", s.auth(s.domainRow))
	mux.HandleFunc("POST /hosts/check/dns", s.auth(s.checkDNS))
	mux.HandleFunc("POST /hosts/check/target", s.auth(s.checkTarget))
	mux.HandleFunc("POST /hosts/check/preview", s.auth(s.checkPreview))
	mux.HandleFunc("POST /hosts", s.auth(s.createHost))
	mux.HandleFunc("GET /hosts/{id}/edit", s.auth(s.editForm))
	mux.HandleFunc("POST /hosts/{id}", s.auth(s.updateHost))
	mux.HandleFunc("GET /hosts/{id}/status", s.auth(s.hostStatus))
	mux.HandleFunc("POST /hosts/{id}/toggle", s.auth(s.toggleHost))
	mux.HandleFunc("POST /hosts/{id}/delete", s.auth(s.deleteHost))

	// Refuse les requêtes inter-sites qui modifient l'état (en-têtes Sec-Fetch-Site et Origin).
	protected := http.NewCrossOriginProtection().Handler(mux)
	return securityHeaders(s.translated(protected))
}

// healthz répond 200 si la base et l'API d'administration de Caddy répondent : c'est ce que lit
// la sonde de santé de l'image (« gatewyn healthcheck »). Sans authentification, et sans rien révéler.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := s.cfg.Store.AdminExists(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.cfg.Caddy.Ping(ctx); err != nil {
		http.Error(w, "caddy unavailable", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprint(w, "ok")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// --- authentification ---

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.NoLogin {
			next(w, r)
			return
		}
		exists, err := s.cfg.Store.AdminExists(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !exists {
			s.redirect(w, r, "/setup")
			return
		}
		if c, err := r.Cookie(cookieName); err == nil {
			if ok, _ := s.cfg.Store.SessionValid(r.Context(), auth.HashToken(c.Value)); ok {
				next(w, r)
				return
			}
		}
		s.redirect(w, r, "/login")
	}
}

// redirect redirige, y compris pour une requête htmx (qui ignore les redirections 3xx).
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) error {
	token, hash, err := auth.NewToken()
	if err != nil {
		return err
	}
	exp := s.cfg.Now().Add(sessionLifetime)
	if err := s.cfg.Store.CreateSession(r.Context(), hash, exp); err != nil {
		return err
	}
	_ = s.cfg.Store.PurgeSessions(r.Context())
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", Expires: exp,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.cfg.SecureCookies || r.TLS != nil,
	})
	return nil
}

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	if exists, _ := s.cfg.Store.AdminExists(r.Context()); exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "setup", page{Title: "Installation"})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	again := func(msg string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "setup", page{Title: "Installation", Error: msg})
	}
	username := auth.NormalizeUsername(r.PostFormValue("username"))
	if err := auth.ValidateUsername(username); err != nil {
		again(capitalize(err.Error()) + ".")
		return
	}
	pw := r.PostFormValue("password")
	if err := auth.ValidatePassword(pw); err != nil {
		again(capitalize(err.Error()) + ".")
		return
	}
	if pw != r.PostFormValue("confirm") {
		again("Les deux mots de passe ne sont pas identiques.")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.cfg.Store.CreateAdmin(r.Context(), username, hash); err != nil {
		if errors.Is(err, store.ErrExists) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.fail(w, r, err)
		return
	}
	_ = s.cfg.Store.Audit(r.Context(), "setup", "compte administrateur créé : "+username)
	if err := s.startSession(w, r); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if exists, _ := s.cfg.Store.AdminExists(r.Context()); !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, "login", page{Title: "Connexion"})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	ip := clientIP(r)
	if !s.limiter.Allowed(ip) {
		wait := s.limiter.RetryAfter(ip).Round(time.Minute)
		if wait < time.Minute {
			wait = time.Minute
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(s.limiter.RetryAfter(ip).Seconds())))
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, "login", page{Title: "Connexion", Error: fmt.Sprintf("Trop d'essais. Réessayez dans %d min.", int(wait.Minutes()))})
		return
	}
	username, hash, err := s.cfg.Store.AdminCredentials(r.Context())
	if err != nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	// Le mot de passe est toujours vérifié, même si l'identifiant est faux : même durée dans les deux cas.
	passwordOK := auth.VerifyPassword(r.PostFormValue("password"), hash)
	userOK := subtle.ConstantTimeCompare([]byte(auth.NormalizeUsername(r.PostFormValue("username"))), []byte(username)) == 1
	if !passwordOK || !userOK {
		s.limiter.Fail(ip)
		_ = s.cfg.Store.Audit(r.Context(), "login.failed", "origine "+ip)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login", page{Title: "Connexion", Error: "Identifiant ou mot de passe incorrect."})
		return
	}
	s.limiter.Reset(ip)
	if err := s.startSession(w, r); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.cfg.Store.Audit(r.Context(), "login", "origine "+ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.cfg.Store.DeleteSession(r.Context(), auth.HashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// clientIP renvoie l'adresse de l'appelant. Les en-têtes X-Forwarded-For ne
// sont volontairement pas crus : n'importe qui peut les écrire.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- hôtes ---

type hostView struct {
	ID          int64
	Domain      string
	Aliases     string // autres noms, séparés par des virgules
	Kind        string
	Target      string
	Disabled    bool
	Type        string // redirection : « Permanente » ou « Temporaire »
	Detail      string // redirection : précision affichée sous le type
	Dest        string // cible ou destination affichée
	CertProblem string // échec d'obtention du certificat, en clair (vide : aucun)
	IsProxy     bool
}

type resultView struct{ Class, Label, Message string }

func view(r checks.Result) resultView {
	v := resultView{Message: r.Message}
	switch r.Status {
	case checks.OK:
		v.Class, v.Label = "ok", "OK"
	case checks.Warn:
		v.Class, v.Label = "warn", "À voir"
	case checks.Error:
		v.Class, v.Label = "err", "Problème"
	default:
		v.Class, v.Label = "info", "Info"
	}
	return v
}

// listPath est l'adresse de la liste des hôtes d'un type.
func listPath(kind string) string {
	switch kind {
	case caddyconf.KindRedirect:
		return "/redirections"
	case caddyconf.KindNotFound:
		return "/erreurs-404"
	}
	return "/hosts"
}

var listTitles = map[string]string{caddyconf.KindProxy: "Hôtes", caddyconf.KindRedirect: "Redirections", caddyconf.KindNotFound: "Erreurs 404"}

func (s *Server) listPage(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.hostsList(w, r, kind) }
}

func (s *Server) hostsList(w http.ResponseWriter, r *http.Request, kind string) {
	hosts, err := s.cfg.Store.ListHosts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.authedPage(r, listTitles[kind], kind)
	p.Kind, p.ListPath = kind, listPath(kind)
	p.Query = strings.TrimSpace(r.URL.Query().Get("q"))
	for _, h := range hosts {
		if kindFromForm(h.Kind) == kind && matches(h, p.Query) {
			v := toView(h)
			v.CertProblem = s.certProblem(h)
			p.Hosts = append(p.Hosts, v)
		}
	}
	if r.Header.Get("HX-Request") == "true" { // recherche en direct : seulement la liste
		s.renderFragment(w, "hosts", "list", p)
		return
	}
	q := r.URL.Query()
	switch {
	case q.Get("added") != "":
		p.Flash = fmt.Sprintf("%s est publié. Le certificat HTTPS est demandé automatiquement à la première visite.", q.Get("added"))
	case q.Get("changed") != "":
		p.Flash = fmt.Sprintf("%s est mis à jour.", q.Get("changed"))
	case q.Get("disabled") != "":
		p.Flash = fmt.Sprintf("%s est désactivé : il n'est plus publié.", q.Get("disabled"))
	case q.Get("enabled") != "":
		p.Flash = fmt.Sprintf("%s est activé : il est de nouveau publié.", q.Get("enabled"))
	case q.Get("deleted") != "":
		p.Flash = fmt.Sprintf("%s est supprimé.", q.Get("deleted"))
	}
	s.render(w, "hosts", p)
}

// audit enregistre l'action dans le journal d'audit. Ne jamais y mettre de secret.
func (s *Server) audit(ctx context.Context, action, detail string) {
	if err := s.cfg.Store.Audit(ctx, action, detail); err != nil {
		s.cfg.Logger.Error("audit log", "error", err)
	}
}

func (s *Server) hostStatus(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostFromPath(w, r)
	if !ok {
		return
	}
	if h.Kind == caddyconf.KindRedirect || h.Kind == caddyconf.KindNotFound {
		s.renderFragment(w, "hosts", "status", struct{ Class, Label, Message string }{"ok", "Actif", ""})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	res := s.cfg.CheckTarget(ctx, h.Target)
	v := view(res)
	label := "En ligne"
	switch res.Status {
	case checks.Warn:
		label = "À voir"
	case checks.Error:
		label = "Cible injoignable"
	}
	s.renderFragment(w, "hosts", "status", struct{ Class, Label, Message string }{v.Class, label, res.Message})
}

func (s *Server) toggleHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := s.cfg.Store.SetHostDisabled(ctx, h.ID, !h.Disabled); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sync(ctx); err != nil {
		_ = s.cfg.Store.SetHostDisabled(ctx, h.ID, h.Disabled) // retour à l'état précédent
		_ = s.sync(ctx)
		s.htmxError(w, explainSyncError(err))
		return
	}
	action := "host.disable"
	if h.Disabled {
		action = "host.enable"
	}
	s.audit(ctx, action, h.Domain)
	result := "disabled"
	if h.Disabled {
		result = "enabled"
	}
	w.Header().Set("HX-Redirect", listPath(h.Kind)+"?"+result+"="+template.URLQueryEscaper(h.Domain))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := s.cfg.Store.DeleteHost(ctx, h.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sync(ctx); err != nil {
		if _, e := s.cfg.Store.AddHostFull(ctx, h); e == nil && h.Disabled { // restauration avec son type et ses options
			if again, e := s.hostByDomain(ctx, h.Domain); e == nil {
				_ = s.cfg.Store.SetHostDisabled(ctx, again.ID, true)
			}
		}
		_ = s.sync(ctx)
		s.htmxError(w, explainSyncError(err))
		return
	}
	s.audit(ctx, "host.delete", h.Domain)
	w.Header().Set("HX-Redirect", listPath(h.Kind)+"?deleted="+template.URLQueryEscaper(h.Domain))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) hostByDomain(ctx context.Context, domain string) (store.Host, error) {
	hosts, err := s.cfg.Store.ListHosts(ctx)
	if err != nil {
		return store.Host{}, err
	}
	for _, h := range hosts {
		if h.Domain == domain {
			return h, nil
		}
	}
	return store.Host{}, store.ErrNotFound
}

func (s *Server) hostFromPath(w http.ResponseWriter, r *http.Request) (store.Host, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.Host{}, false
	}
	h, err := s.cfg.Store.HostByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return store.Host{}, false
	}
	if err != nil {
		s.fail(w, r, err)
		return store.Host{}, false
	}
	return h, true
}

// htmxError affiche un message d'erreur dans la zone #flash de la page.
func (s *Server) htmxError(w http.ResponseWriter, msg string) {
	w.Header().Set("HX-Retarget", "#flash")
	w.Header().Set("HX-Reswap", "innerHTML")
	fmt.Fprintf(w, `<div class="note" role="alert"><span class="pill err">Erreur</span> %s</div>`, template.HTMLEscapeString(msg))
}

// --- publication dans Caddy ---

// Sync publie tous les hôtes enregistrés dans Caddy.
func (s *Server) Sync(ctx context.Context) error { return s.sync(ctx) }

func (s *Server) sync(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	hosts, err := s.cfg.Store.ListHosts(ctx)
	if err != nil {
		return err
	}
	lists, err := s.cfg.Store.AccessLists(ctx)
	if err != nil {
		return err
	}
	access := map[int64][]string{}
	for _, l := range lists {
		access[l.ID] = l.Addresses
	}
	dns, err := s.dnsChallenges(ctx)
	if err != nil {
		return err
	}
	cs, err := s.activeCrowdSec(ctx)
	if err != nil {
		return err
	}
	proxies, err := s.trustedProxies(ctx)
	if err != nil {
		return err
	}
	out := make([]caddyconf.Host, len(hosts))
	for i, h := range hosts {
		out[i] = caddyconf.Host{WAF: h.WAF && cs != nil && cs.AppSecURL != "", Compress: h.Compress, NoBuffering: h.NoBuffering, FrameOptions: h.FrameOptions, NoIndex: h.NoIndex, CrowdSec: cs != nil, DNS: dns[h.DNSAccountID], Domain: h.Domain, Kind: h.Kind, Target: h.Target, Disabled: h.Disabled, Code: h.Code, Aliases: h.Aliases, HSTS: h.HSTS, PreservePath: h.PreservePath, HTTPOnly: h.HTTPOnly, SelfSigned: h.SelfSigned, Locations: confLocations(h.Locations, access), Access: access[h.AccessListID]}
	}
	accessLog, err := s.accessLog(ctx)
	if err != nil {
		return err
	}
	return s.cfg.Caddy.ApplyAll(ctx, out, caddyconf.Global{CrowdSec: cs, TrustedProxies: proxies, AccessLog: accessLog})
}

// explainSettingError : comme explainSyncError, pour un réglage qui ne concerne aucun hôte en particulier.
func explainSettingError(err error) string {
	var apiErr *caddyadmin.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("Caddy a refusé la configuration, le réglage n'a pas été enregistré. Détail : %s", apiErr.Message)
	}
	return fmt.Sprintf("Gatewyn n'arrive pas à joindre Caddy, le réglage n'a pas été enregistré (%s).", err.Error())
}

func explainSyncError(err error) string {
	var apiErr *caddyadmin.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("Caddy a refusé la configuration, l'hôte n'a pas été publié. Détail : %s", apiErr.Message)
	}
	return fmt.Sprintf("Gatewyn n'arrive pas à joindre Caddy, l'hôte n'a pas été publié (%s).", err.Error())
}

// --- rendu ---

// DomainList sépare la saisie du champ Domaine en un nom par ligne (au moins une, vide si besoin).
func (p page) DomainList() []string {
	if p.Domain == "" {
		return []string{""}
	}
	return strings.Split(p.Domain, ", ")
}

type page struct {
	Title, Nav       string
	Authed, CaddyOK  bool
	Flash, Error     string
	PwError          string // erreur du formulaire de changement de mot de passe
	CanChangePw      bool
	Hosts            []hostView
	Domain, Target   string
	Checks           []resultView
	CanForce         bool
	Heading, Action  string
	Submit           string
	Editing          bool
	EditID           int64
	EditDisabled     bool
	Kind             string
	Code             int
	Preserve         bool
	Query            string
	ListPath         string // liste à laquelle « Annuler » ramène
	Events           []eventView
	Lists            []listView
	Certs            []certView
	DNS              []dnsView
	Providers        []dnsprov.Provider
	ProviderID       string
	DNSFields        []fieldView
	DNSID            int64        // formulaire d'hôte : compte DNS choisi (0 = automatique)
	HasLocations     bool         // le bloc Avancé s'ouvre : des chemins sont définis
	LocRows          []locRowView // formulaire d'hôte : chemins vers d'autres cibles
	HTTPOnly         bool         // formulaire d'hôte : HTTP seulement, sans HTTPS
	SelfSigned       bool         // formulaire d'hôte : certificat auto-signé
	HSTS             int          // formulaire d'hôte : 0 aucun, 1 HSTS, 2 avec les sous-domaines
	CertsReadable    bool
	CS               csView
	ProxiesText      string // proxies de confiance, un par ligne
	AppSecURL        string // formulaire CrowdSec : adresse du WAF
	AppSecFailOpen   bool   // formulaire CrowdSec : laisser passer si AppSec tombe
	CrowdSecUIURL    string // formulaire CrowdSec : lien vers son interface web
	UILanguage       string // réglages : « auto », « fr » ou « en »
	AccessLogAvail   bool   // réglages : le journal d'accès est possible (fichier configuré)
	AccessLogOn      bool
	AccessLogDays    int
	AccessLogChoices []int
	HasHosts         bool   // vue d'ensemble : au moins un hôte
	CertCount        int    // vue d'ensemble : certificats lus
	CertNext         string // vue d'ensemble : délai avant la prochaine échéance
	CertClass        string
	CSConfigured     bool       // vue d'ensemble : CrowdSec est connecté
	GoAccessUp       bool       // statistiques : GoAccess répond
	GoAccessTarget   string     // statistiques : cible à publier
	GoAccessReport   string     // adresse du rapport (réglage), vide : bouton masqué
	Recent           []reqView  // statistiques : dernières requêtes du journal
	StatsSum         reqSummary // statistiques : résumé des requêtes lues
	KeyAuto          bool       // la clé du bouncer a été trouvée par Gatewyn : rien à saisir
	Guided           bool       // connexion depuis l'assistant : seul le champ clé est prioritaire
	WAF              bool       // formulaire d'hôte : WAF activé
	WAFAvailable     bool       // formulaire d'hôte : AppSec est connecté
	Compress         bool
	NoBuffering      bool
	NoIndex          bool
	FrameOptions     string
	RootCert         bool // le certificat racine de Caddy existe et peut être téléchargé
	Name, Addresses  string
	AccessID         int64 // formulaire d'hôte : liste d'accès choisie (0 = public)
}

func (s *Server) authedPage(r *http.Request, title, nav string) page {
	ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
	defer cancel()
	return page{Title: title, Nav: nav, Authed: true, CaddyOK: s.cfg.Caddy.Ping(ctx) == nil}
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		s.cfg.Logger.Error("page rendering", "page", name, "error", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) renderFragment(w http.ResponseWriter, pageName, fragment string, data any) {
	var buf bytes.Buffer
	if err := s.pages[pageName].ExecuteTemplate(&buf, fragment, data); err != nil {
		s.cfg.Logger.Error("fragment rendering", "fragment", fragment, "error", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Requête invalide", http.StatusBadRequest)
		return false
	}
	return true
}

// fail journalise une erreur interne sans en montrer le détail à l'utilisateur.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.cfg.Logger.Error("internal error", "path", r.URL.Path, "error", err)
	http.Error(w, "Erreur interne. Le détail est dans les journaux de Gatewyn.", http.StatusInternalServerError)
}

func capitalize(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// matches indique si l'hôte correspond à la recherche (domaine ou cible, sans tenir compte de la casse).
func matches(h store.Host, q string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	return strings.Contains(strings.ToLower(h.Domain), q) || strings.Contains(strings.ToLower(h.Target), q) ||
		strings.Contains(strings.ToLower(strings.Join(h.Aliases, " ")), q)
}

// certProblem explique en clair pourquoi le certificat d'un hôte n'a pas été obtenu, ou renvoie "" :
// pas d'échec connu, ou hôte sans certificat à obtenir (désactivé, HTTP seulement, auto-signé).
func (s *Server) certProblem(h store.Host) string {
	if h.Disabled || h.HTTPOnly || h.SelfSigned {
		return ""
	}
	domains := append([]string{h.Domain}, h.Aliases...)
	for _, d := range domains {
		if f, ok := s.cfg.CertFailures.Failure(d); ok {
			return checks.ExplainACME(f.Raw).Message
		}
	}
	return ""
}
