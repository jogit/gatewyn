package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jogit/gatewyn/internal/secrets"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jogit/gatewyn/internal/acmelog"
	"github.com/jogit/gatewyn/internal/caddyadmin"
	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/checks"
	"github.com/jogit/gatewyn/internal/store"
)

const goodPassword = "une phrase de passe correcte"
const goodUsername = "alice"

type fakeCaddy struct {
	mu       sync.Mutex
	applied  [][]caddyconf.Host
	crowdsec *caddyconf.CrowdSec // dernière configuration CrowdSec publiée
	global   caddyconf.Global    // derniers réglages globaux publiés
	csStatus caddyadmin.CrowdSecStatus
	csErr    error
	failNext error
	down     bool
}

func (f *fakeCaddy) ApplyAll(_ context.Context, h []caddyconf.Host, g caddyconf.Global) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.applied = append(f.applied, append([]caddyconf.Host(nil), h...))
	f.crowdsec, f.global = g.CrowdSec, g
	return nil
}

func (f *fakeCaddy) CrowdSecStatus(context.Context) (caddyadmin.CrowdSecStatus, error) {
	return f.csStatus, f.csErr
}

func (f *fakeCaddy) Ping(context.Context) error {
	if f.down {
		return errors.New("down")
	}
	return nil
}

func (f *fakeCaddy) last() []caddyconf.Host {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return nil
	}
	return f.applied[len(f.applied)-1]
}

type env struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	caddy  *fakeCaddy
	store  *store.Store
	client *http.Client
	dns    checks.Result
	target checks.Result
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secrets.Open(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, store: st, caddy: &fakeCaddy{},
		dns:    checks.Result{Status: checks.OK, Code: "dns_ok", Message: "dns ok"},
		target: checks.Result{Status: checks.OK, Code: "target_ok", Message: "cible ok"}}
	e.srv, err = New(Config{
		Store: st, Caddy: e.caddy, Secrets: box, AccessLogFile: "/data/logs/access.log", GoAccessURL: "http://127.0.0.1:1",
		CheckDNS:    func(context.Context, string) checks.Result { return e.dns },
		CheckTarget: func(context.Context, string, bool) checks.Result { return e.target },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(e.ts.Close)
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return e
}

func (e *env) do(method, path string, form url.Values, headers ...string) (*http.Response, string) {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// setup crée le compte administrateur et ouvre la session.
func (e *env) setup() {
	e.t.Helper()
	resp, _ := e.do("POST", "/setup", url.Values{"username": {goodUsername}, "password": {goodPassword}, "confirm": {goodPassword}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("installation : %d", resp.StatusCode)
	}
}

func TestEverythingRedirectsToSetupBeforeAccountExists(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/", "/hosts/new", "/login"} {
		resp, _ := e.do("GET", p, nil)
		if resp.StatusCode != 303 || resp.Header.Get("Location") != "/setup" {
			t.Errorf("%s → %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestSetupValidatesPassword(t *testing.T) {
	e := newEnv(t)
	cases := []struct{ pw, confirm, want string }{
		{"court", "court", "au moins 12"},
		{goodPassword, "autre chose entièrement", "pas identiques"},
	}
	for _, c := range cases {
		resp, body := e.do("POST", "/setup", url.Values{"username": {goodUsername}, "password": {c.pw}, "confirm": {c.confirm}})
		if resp.StatusCode != 422 || !strings.Contains(body, c.want) {
			t.Errorf("%q : %d", c.pw, resp.StatusCode)
		}
	}
	if ok, _ := e.store.AdminExists(context.Background()); ok {
		t.Fatal("compte créé avec un mot de passe refusé")
	}
}

func TestSetupValidatesUsername(t *testing.T) {
	e := newEnv(t)
	for _, u := range []string{"", "ab", "avec espace", "accentué", strings.Repeat("a", 33)} {
		resp, body := e.do("POST", "/setup", url.Values{"username": {u}, "password": {goodPassword}, "confirm": {goodPassword}})
		if resp.StatusCode != 422 || !strings.Contains(body, "identifiant") {
			t.Errorf("%q : %d", u, resp.StatusCode)
		}
	}
	if ok, _ := e.store.AdminExists(context.Background()); ok {
		t.Fatal("compte créé avec un identifiant refusé")
	}
}

func TestLoginNeedsUsernameAndPassword(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.do("POST", "/logout", nil)
	for _, u := range []string{"", "bob"} {
		resp, body := e.do("POST", "/login", url.Values{"username": {u}, "password": {goodPassword}})
		if resp.StatusCode != 401 || !strings.Contains(body, "Identifiant ou mot de passe incorrect") {
			t.Errorf("identifiant %q avec le bon mot de passe : %d", u, resp.StatusCode)
		}
	}
	// L'identifiant n'est pas sensible à la casse ni aux espaces autour.
	if resp, _ := e.do("POST", "/login", url.Values{"username": {"  Alice "}, "password": {goodPassword}}); resp.StatusCode != 303 {
		t.Errorf("identifiant en majuscules : %d", resp.StatusCode)
	}
}

func TestSetupCreatesAccountAndSession(t *testing.T) {
	e := newEnv(t)
	e.setup()
	user, hash, _ := e.store.AdminCredentials(context.Background())
	if user != goodUsername {
		t.Errorf("identifiant stocké : %q", user)
	}
	if strings.Contains(hash, goodPassword) || !strings.HasPrefix(hash, "argon2id$") {
		t.Errorf("empreinte stockée : %s", hash)
	}
	resp, body := e.do("GET", "/", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Hôtes") {
		t.Errorf("accès après installation : %d", resp.StatusCode)
	}
	// Le formulaire d'installation n'est plus disponible.
	if resp, _ := e.do("GET", "/setup", nil); resp.Header.Get("Location") != "/login" {
		t.Errorf("/setup après installation → %s", resp.Header.Get("Location"))
	}
	if resp, _ := e.do("POST", "/setup", url.Values{"username": {goodUsername}, "password": {goodPassword}, "confirm": {goodPassword}}); resp.Header.Get("Location") != "/login" {
		t.Errorf("POST /setup après installation → %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSessionCookieFlags(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.do("POST", "/setup", url.Values{"username": {goodUsername}, "password": {goodPassword}, "confirm": {goodPassword}})
	var c *http.Cookie
	for _, k := range resp.Cookies() {
		if k.Name == cookieName {
			c = k
		}
	}
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || len(c.Value) < 40 {
		t.Fatalf("cookie = %+v", c)
	}
	// Le jeton n'est jamais stocké tel quel.
	if ok, _ := e.store.SessionValid(context.Background(), c.Value); ok {
		t.Error("le jeton brut est stocké dans la base")
	}
}

func TestProtectedPagesRequireLogin(t *testing.T) {
	e := newEnv(t)
	e.setup()
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/hosts/new"}, {"GET", "/hosts/1/edit"}, {"POST", "/hosts/1"}, {"POST", "/hosts"}, {"POST", "/hosts/check/dns"}, {"POST", "/hosts/check/target"},
		{"GET", "/hosts/1/status"}, {"POST", "/hosts/1/toggle"}, {"POST", "/hosts/1/delete"},
	} {
		req, _ := http.NewRequest(tc.method, e.ts.URL+tc.path, nil)
		resp, err := anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 303 || resp.Header.Get("Location") != "/login" {
			t.Errorf("%s %s sans session → %d %s", tc.method, tc.path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// Une requête htmx sans session reçoit HX-Redirect (htmx ignore les 3xx).
	req, _ := http.NewRequest("POST", e.ts.URL+"/hosts/check/dns", nil)
	req.Header.Set("HX-Request", "true")
	resp, _ := anon.Do(req)
	resp.Body.Close()
	if resp.Header.Get("HX-Redirect") != "/login" {
		t.Errorf("HX-Redirect = %q", resp.Header.Get("HX-Redirect"))
	}
	// Un faux cookie ne donne rien.
	req, _ = http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "jeton-invente"})
	resp, _ = anon.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("faux cookie → %d", resp.StatusCode)
	}
}

func TestLoginWrongPasswordThenRateLimit(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.do("POST", "/logout", url.Values{})
	for i := 0; i < 5; i++ {
		resp, body := e.do("POST", "/login", url.Values{"username": {goodUsername}, "password": {"mauvais mot de passe"}})
		if resp.StatusCode != 401 || !strings.Contains(body, "Identifiant ou mot de passe incorrect") {
			t.Fatalf("essai %d : %d", i, resp.StatusCode)
		}
	}
	// Même le bon mot de passe est refusé pendant le blocage.
	resp, body := e.do("POST", "/login", url.Values{"username": {goodUsername}, "password": {goodPassword}})
	if resp.StatusCode != 429 || !strings.Contains(body, "Trop d&#39;essais") || resp.Header.Get("Retry-After") == "" {
		t.Errorf("blocage : %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	entries, _ := e.store.RecentAudit(context.Background(), 20)
	failed := 0
	for _, en := range entries {
		if en.Action == "login.failed" {
			failed++
		}
		if strings.Contains(en.Detail, goodPassword) || strings.Contains(en.Detail, "mauvais") {
			t.Errorf("mot de passe dans l'audit : %+v", en)
		}
	}
	if failed != 5 {
		t.Errorf("%d échecs dans l'audit, attendu 5", failed)
	}
}

func TestLoginAndLogout(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.do("POST", "/logout", url.Values{})
	if resp, _ := e.do("GET", "/", nil); resp.StatusCode != 303 {
		t.Fatalf("encore connecté après déconnexion : %d", resp.StatusCode)
	}
	resp, _ := e.do("POST", "/login", url.Values{"username": {goodUsername}, "password": {goodPassword}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("connexion : %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/", nil); resp.StatusCode != 200 {
		t.Errorf("accès après connexion : %d", resp.StatusCode)
	}
}

func TestLogoutInvalidatesSessionServerSide(t *testing.T) {
	e := newEnv(t)
	e.setup()
	u, _ := url.Parse(e.ts.URL)
	stolen := e.client.Jar.Cookies(u)[0]
	e.do("POST", "/logout", url.Values{})
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(stolen)
	resp, _ := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("ancien cookie encore valable : %d", resp.StatusCode)
	}
}

func TestCrossOriginPostIsRejected(t *testing.T) {
	e := newEnv(t)
	e.setup()
	resp, _ := e.do("POST", "/hosts", url.Values{"domain": {"x.example.com"}, "target": {"http://192.0.2.1"}},
		"Origin", "https://evil.example.com")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST inter-site → %d", resp.StatusCode)
	}
	resp, _ = e.do("POST", "/hosts", url.Values{"domain": {"x.example.com"}, "target": {"http://192.0.2.1"}},
		"Sec-Fetch-Site", "cross-site")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST Sec-Fetch-Site cross-site → %d", resp.StatusCode)
	}
	if hosts, _ := e.store.ListHosts(context.Background()); len(hosts) != 0 {
		t.Errorf("hôte créé par une requête inter-site : %v", hosts)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.do("GET", "/login", nil)
	h := resp.Header
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") || strings.Contains(h.Get("Content-Security-Policy"), "unsafe") ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("en-têtes : %v", h)
	}
}

func TestStaticAssetsAreEmbedded(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/static/htmx.min.js", "/static/style.css"} {
		if resp, body := e.do("GET", p, nil); resp.StatusCode != 200 || len(body) < 1000 {
			t.Errorf("%s → %d (%d octets)", p, resp.StatusCode, len(body))
		}
	}
	// Aucune ressource externe dans les pages.
	e.setup()
	_, body := e.do("GET", "/hosts/new", nil)
	for _, bad := range []string{"http://cdn", "https://cdn", "googleapis", "unpkg", "jsdelivr"} {
		if strings.Contains(body, bad) {
			t.Errorf("dépendance externe %q dans la page", bad)
		}
	}
}

func TestCreateHostPublishesToCaddy(t *testing.T) {
	e := newEnv(t)
	e.setup()
	resp, _ := e.do("POST", "/hosts", url.Values{"domain": {"  Wiki.Example.COM "}, "target": {"192.0.2.21:8080"}})
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/hosts?added=wiki.example.com") {
		t.Fatalf("création : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	got := e.caddy.last()
	if len(got) != 1 || got[0].Domain != "wiki.example.com" || got[0].Target != "http://192.0.2.21:8080" {
		t.Errorf("publié dans Caddy : %+v", got)
	}
	_, body := e.do("GET", resp.Header.Get("Location"), nil)
	if !strings.Contains(body, "wiki.example.com") || !strings.Contains(body, "est publié") {
		t.Errorf("liste : %s", body)
	}
	entries, _ := e.store.RecentAudit(context.Background(), 5)
	if entries[0].Action != "host.create" {
		t.Errorf("audit = %+v", entries)
	}
}

func TestCreateHostBlockedByDNSErrorUnlessForced(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.dns = checks.Result{Status: checks.Error, Code: "dns_wrong_ip", Message: "Le domaine wiki.example.com ne pointe pas vers votre IP."}
	form := url.Values{"domain": {"wiki.example.com"}, "target": {"http://192.0.2.21"}}

	resp, body := e.do("POST", "/hosts", form)
	if resp.StatusCode != 422 || !strings.Contains(body, "ne pointe pas vers votre IP") || !strings.Contains(body, "Créer quand même") {
		t.Fatalf("pas de blocage : %d", resp.StatusCode)
	}
	if hosts, _ := e.store.ListHosts(context.Background()); len(hosts) != 0 || len(e.caddy.applied) != 0 {
		t.Fatal("hôte enregistré malgré l'erreur DNS")
	}
	form.Set("force", "1")
	if resp, _ := e.do("POST", "/hosts", form); resp.StatusCode != 303 {
		t.Errorf("création forcée : %d", resp.StatusCode)
	}
	if hosts, _ := e.store.ListHosts(context.Background()); len(hosts) != 1 {
		t.Error("hôte non créé après confirmation")
	}
}

func TestCreateHostRejectsInvalidInputWithoutForceOption(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for _, form := range []url.Values{
		{"domain": {"https://wiki.example.com"}, "target": {"http://192.0.2.1"}},
		{"domain": {"wiki.example.com"}, "target": {"ftp://192.0.2.1"}},
		{"domain": {""}, "target": {"http://192.0.2.1"}},
		{"domain": {"wiki.example.com"}, "target": {""}},
	} {
		form.Set("force", "1") // même forcé, une saisie invalide est refusée
		resp, body := e.do("POST", "/hosts", form)
		if resp.StatusCode != 422 || strings.Contains(body, "Créer quand même") {
			t.Errorf("%v → %d", form, resp.StatusCode)
		}
	}
	if hosts, _ := e.store.ListHosts(context.Background()); len(hosts) != 0 {
		t.Errorf("hôtes créés : %v", hosts)
	}
}

func TestCreateHostRollsBackWhenCaddyRefuses(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.caddy.failNext = &caddyadmin.APIError{Status: 500, Message: "unknown module: http.handlers.nope"}
	resp, body := e.do("POST", "/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"http://192.0.2.21"}})
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "n&#39;a pas été publié") || !strings.Contains(body, "unknown module") {
		t.Fatalf("refus de Caddy : %d", resp.StatusCode)
	}
	if hosts, _ := e.store.ListHosts(context.Background()); len(hosts) != 0 {
		t.Errorf("hôte gardé alors que Caddy a refusé : %v", hosts)
	}
}

func TestCreateDuplicateHost(t *testing.T) {
	e := newEnv(t)
	e.setup()
	form := url.Values{"domain": {"wiki.example.com"}, "target": {"http://192.0.2.21"}}
	e.do("POST", "/hosts", form)
	resp, body := e.do("POST", "/hosts", form)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "existe déjà") {
		t.Errorf("doublon : %d", resp.StatusCode)
	}
}

func TestCheckEndpointsShowPlainLanguageResultsIndependently(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.dns = checks.Result{Status: checks.Error, Code: "dns_not_found", Message: "Le domaine x n'existe pas dans le DNS."}
	e.target = checks.Result{Status: checks.OK, Code: "target_ok", Message: "Le service répond (200, 3 ms)."}
	form := url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21"}}

	resp, body := e.do("POST", "/hosts/check/dns", form, "HX-Request", "true")
	if resp.StatusCode != 200 || !strings.Contains(body, "n&#39;existe pas dans le DNS") || !strings.Contains(body, `class="pill err"`) || strings.Contains(body, "Le service répond") {
		t.Errorf("DNS : %d %s", resp.StatusCode, body)
	}
	_, body = e.do("POST", "/hosts/check/target", form, "HX-Request", "true")
	if !strings.Contains(body, "Le service répond") || !strings.Contains(body, `class="pill ok"`) || strings.Contains(body, "DNS") {
		t.Errorf("cible : %s", body)
	}
	// Saisie invalide : message de format, sans interroger le DNS ni la cible.
	e.dns.Message = "NE DOIT PAS APPARAÎTRE"
	_, body = e.do("POST", "/hosts/check/dns", url.Values{"domain": {"https://x.example.com"}, "target": {""}})
	if !strings.Contains(body, "Domaine invalide") || strings.Contains(body, "NE DOIT PAS") {
		t.Errorf("domaine invalide : %s", body)
	}
	_, body = e.do("POST", "/hosts/check/target", url.Values{"domain": {""}, "target": {"ftp://192.0.2.1"}})
	if !strings.Contains(body, "non pris en charge") {
		t.Errorf("cible invalide : %s", body)
	}
	// Champ vide : rien à vérifier, pas d'erreur.
	for _, path := range []string{"/hosts/check/dns", "/hosts/check/target"} {
		if resp, body := e.do("POST", path, url.Values{"domain": {""}, "target": {""}}); resp.StatusCode != 200 || strings.Contains(body, "pill") {
			t.Errorf("%s vide : %d %s", path, resp.StatusCode, body)
		}
	}
}

func TestNoInlineStylesOrScripts(t *testing.T) {
	// La politique de sécurité interdit les styles et scripts en ligne : ils casseraient la page en silence.
	e := newEnv(t)
	_, login := e.do("GET", "/setup", nil)
	e.setup()
	pages := []string{login}
	for _, p := range []string{"/", "/hosts/new"} {
		_, body := e.do("GET", p, nil)
		pages = append(pages, body)
	}
	for i, body := range pages {
		for _, bad := range []string{" style=", "<script>", " onclick=", " onsubmit=", "javascript:"} {
			if strings.Contains(body, bad) {
				t.Errorf("page %d contient %q", i, bad)
			}
		}
	}
}

func TestToggleAndDeleteHostFromEditPage(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21")
	path := "/hosts/" + itoa(id)

	// La page Modifier propose Désactiver et Supprimer ; la liste n'a que « Modifier ».
	_, edit := e.do("GET", path+"/edit", nil)
	for _, want := range []string{">Désactiver<", ">Supprimer<", `class="danger-zone"`, `hx-confirm="Supprimer wiki.example.com`, `id="flash"`} {
		if !strings.Contains(edit, want) {
			t.Errorf("page Modifier sans %q", want)
		}
	}
	_, list := e.do("GET", "/hosts", nil)
	if strings.Contains(list, ">Désactiver<") || strings.Contains(list, ">Supprimer<") || !strings.Contains(list, `href="`+path+`/edit"`) {
		t.Error("la liste ne doit proposer que le lien vers la page Modifier")
	}

	// Désactiver : retour à la liste avec un message, et Caddy ne publie plus l'hôte.
	resp, _ := e.do("POST", path+"/toggle", nil, "HX-Request", "true")
	if resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/hosts?disabled=wiki.example.com" || !e.caddy.last()[0].Disabled {
		t.Errorf("désactivation : %d %q, Caddy %+v", resp.StatusCode, resp.Header.Get("HX-Redirect"), e.caddy.last())
	}
	_, edit = e.do("GET", path+"/edit", nil)
	if !strings.Contains(edit, ">Activer<") {
		t.Error("un hôte désactivé doit proposer « Activer »")
	}
	_, list = e.do("GET", "/hosts?disabled=wiki.example.com", nil)
	if !strings.Contains(list, "wiki.example.com est désactivé") || !strings.Contains(list, ">Désactivé<") {
		t.Errorf("message ou état absent après désactivation : %s", list)
	}

	// Caddy refuse la réactivation : état précédent conservé et message dans #flash de la page.
	e.caddy.failNext = errors.New("connexion refusée")
	resp, body := e.do("POST", path+"/toggle", nil, "HX-Request", "true")
	if resp.Header.Get("HX-Retarget") != "#flash" || resp.Header.Get("HX-Redirect") != "" || !strings.Contains(body, "n&#39;a pas été publié") {
		t.Errorf("erreur de réactivation : %q %q", resp.Header.Get("HX-Retarget"), body)
	}
	if h, _ := e.store.HostByID(context.Background(), id); !h.Disabled {
		t.Error("état non restauré après refus de Caddy")
	}
	resp, _ = e.do("POST", path+"/toggle", nil, "HX-Request", "true")
	if resp.Header.Get("HX-Redirect") != "/hosts?enabled=wiki.example.com" || e.caddy.last()[0].Disabled {
		t.Errorf("réactivation : %q", resp.Header.Get("HX-Redirect"))
	}

	// Supprimer : retour à la liste avec un message.
	resp, body = e.do("POST", path+"/delete", nil, "HX-Request", "true")
	if resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/hosts?deleted=wiki.example.com" || body != "" || len(e.caddy.last()) != 0 {
		t.Errorf("suppression : %d %q %q %+v", resp.StatusCode, resp.Header.Get("HX-Redirect"), body, e.caddy.last())
	}
	if resp, _ := e.do("POST", path+"/delete", nil); resp.StatusCode != 404 {
		t.Errorf("suppression d'un hôte absent : %d", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/hosts/abc/delete", nil); resp.StatusCode != 404 {
		t.Errorf("identifiant invalide : %d", resp.StatusCode)
	}
}

func TestDeleteRestoresRedirectWithItsOptionsWhenCaddyRefuses(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"old.example.com"}, "target": {"https://new.example.org"}, "preserve": {"1"}, "code": {"302"}})
	h, _ := e.srvHostByDomain("old.example.com")
	e.caddy.failNext = errors.New("injoignable")
	e.do("POST", "/hosts/"+itoa(h.ID)+"/delete", nil, "HX-Request", "true")
	again, err := e.srvHostByDomain("old.example.com")
	if err != nil || again.Kind != "redirect" || again.Code != 302 || !again.PreservePath || again.Target != "https://new.example.org" {
		t.Errorf("redirection mal restaurée : %+v, %v", again, err)
	}
}

func TestDeleteRestoresHostWhenCaddyRefuses(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.do("POST", "/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"http://192.0.2.21"}})
	hosts, _ := e.store.ListHosts(context.Background())
	e.caddy.failNext = errors.New("injoignable")
	e.do("POST", "/hosts/"+itoa(hosts[0].ID)+"/delete", nil, "HX-Request", "true")
	if again, _ := e.store.ListHosts(context.Background()); len(again) != 1 || again[0].Domain != "wiki.example.com" {
		t.Errorf("hôte perdu après un refus de Caddy : %+v", again)
	}
}

func TestHostStatusFragment(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.do("POST", "/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"http://192.0.2.21"}})
	hosts, _ := e.store.ListHosts(context.Background())
	_, body := e.do("GET", "/hosts/"+itoa(hosts[0].ID)+"/status", nil)
	if !strings.Contains(body, "En ligne") {
		t.Errorf("statut : %s", body)
	}
	e.target = checks.Result{Status: checks.Error, Code: "target_refused", Message: "Connexion refusée par 192.0.2.21:80."}
	_, body = e.do("GET", "/hosts/"+itoa(hosts[0].ID)+"/status", nil)
	if !strings.Contains(body, "Cible injoignable") || !strings.Contains(body, "Connexion refusée") {
		t.Errorf("statut en échec : %s", body)
	}
}

func TestPageEscapesUserInput(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, body := e.do("POST", "/hosts", url.Values{"domain": {`"><script>alert(1)</script>`}, "target": {`<img src=x onerror=alert(1)>`}})
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
		t.Errorf("saisie non échappée : %s", body)
	}
}

func TestSyncPublishesStoredHosts(t *testing.T) {
	e := newEnv(t)
	e.store.AddHostFull(context.Background(), store.Host{Domain: "b.example.com", Target: "http://192.0.2.2"})
	e.store.AddHostFull(context.Background(), store.Host{Domain: "a.example.com", Target: "http://192.0.2.1"})
	if err := e.srv.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.caddy.last(); len(got) != 2 {
		t.Errorf("publiés : %+v", got)
	}
}

func TestReadForm(t *testing.T) {
	post := func(kind string, kv ...string) formInput {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		r := httptest.NewRequest("POST", "/hosts", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ParseForm()
		return readForm(r, kind)
	}
	if f := post("proxy", "domain", " Wiki.Example.com ", "target", " 192.0.2.21:8080 "); f.Domain != "wiki.example.com" || f.Target != "http://192.0.2.21:8080" {
		t.Errorf("service : %+v", f)
	}
	if f := post("proxy", "domain", "a", "target", "https://x"); f.Target != "https://x" {
		t.Errorf("protocole modifié : %+v", f)
	}
	if f := post("proxy", "domain", "a", "target", ""); f.Target != "" {
		t.Errorf("cible vide devenue %q", f.Target)
	}
	// Redirection : https par défaut, 301 par défaut, chemin gardé seulement si coché.
	f := post("redirect", "domain", "old.example.com", "target", "nouveau.example.org", "preserve", "1")
	if f.Target != "https://nouveau.example.org" || f.Code != 301 || !f.Preserve {
		t.Errorf("redirection : %+v", f)
	}
	if f := post("redirect", "domain", "a", "target", "https://x", "code", "302"); f.Code != 302 || f.Preserve {
		t.Errorf("redirection temporaire : %+v", f)
	}
	if f := post("redirect", "domain", "a", "target", "https://x", "code", "307"); f.Code != 301 {
		t.Errorf("code inconnu accepté : %+v", f)
	}
	// Page introuvable : la cible saisie est ignorée.
	if f := post("404", "domain", "gone.example.com", "target", "http://ignore", "preserve", "1", "code", "302"); f.Target != "" || f.Code != 0 || f.Preserve {
		t.Errorf("404 : %+v", f)
	}
	if kindFromForm("n'importe quoi") != "proxy" || kindFromForm("redirect") != "redirect" || kindFromForm("404") != "404" {
		t.Error("kindFromForm")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (e *env) addHost(domain, target string) int64 {
	e.t.Helper()
	if resp, _ := e.do("POST", "/hosts", url.Values{"domain": {domain}, "target": {target}}); resp.StatusCode != 303 {
		e.t.Fatalf("ajout de %s : %d", domain, resp.StatusCode)
	}
	h, err := e.srvHostByDomain(domain)
	if err != nil {
		e.t.Fatal(err)
	}
	return h.ID
}

func (e *env) srvHostByDomain(domain string) (store.Host, error) {
	return e.srv.hostByDomain(context.Background(), domain)
}

func TestEditFormIsPrefilledAndChecksRunOnLoad(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	resp, body := e.do("GET", "/hosts/"+itoa(id)+"/edit", nil)
	for _, want := range []string{"Modifier wiki.example.com", `value="wiki.example.com"`, `value="http://192.0.2.21:8080"`,
		`action="/hosts/` + itoa(id) + `"`, "Enregistrer", `hx-trigger="load, input from:closest form`} {
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Errorf("formulaire de modification sans %q (%d)", want, resp.StatusCode)
		}
	}
	if resp, _ := e.do("GET", "/hosts/999/edit", nil); resp.StatusCode != 404 {
		t.Errorf("hôte absent : %d", resp.StatusCode)
	}
}

func TestEditHostUpdatesAndPublishes(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	resp, _ := e.do("POST", "/hosts/"+itoa(id), url.Values{"domain": {"Wiki2.example.com"}, "target": {"192.0.2.22:9000"}})
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/hosts?changed=wiki2.example.com") {
		t.Fatalf("modification : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if h, _ := e.store.HostByID(context.Background(), id); h.Domain != "wiki2.example.com" || h.Target != "http://192.0.2.22:9000" {
		t.Errorf("hôte = %+v", h)
	}
	if got := e.caddy.last(); len(got) != 1 || got[0].Domain != "wiki2.example.com" || got[0].Target != "http://192.0.2.22:9000" {
		t.Errorf("publié dans Caddy : %+v", got)
	}
	_, body := e.do("GET", resp.Header.Get("Location"), nil)
	if !strings.Contains(body, "est mis à jour") {
		t.Error("message de confirmation absent")
	}
}

func TestEditHostWithoutChangeDoesNothing(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	applied := len(e.caddy.applied)
	resp, _ := e.do("POST", "/hosts/"+itoa(id), url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/hosts" || len(e.caddy.applied) != applied {
		t.Errorf("%d %s, publications %d → %d", resp.StatusCode, resp.Header.Get("Location"), applied, len(e.caddy.applied))
	}
}

func TestEditHostBlockedByCheckUnlessForcedAndRejectsDuplicates(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	e.addHost("other.example.com", "http://192.0.2.30")
	form := url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.99:1"}}

	e.target = checks.Result{Status: checks.Error, Code: "target_refused", Message: "Connexion refusée par 192.0.2.99:1."}
	resp, body := e.do("POST", "/hosts/"+itoa(id), form)
	if resp.StatusCode != 422 || !strings.Contains(body, "Enregistrer quand même") || !strings.Contains(body, "Connexion refusée") {
		t.Fatalf("pas de blocage : %d", resp.StatusCode)
	}
	if h, _ := e.store.HostByID(context.Background(), id); h.Target != "http://192.0.2.21:8080" {
		t.Error("cible modifiée malgré le blocage")
	}
	form.Set("force", "1")
	if resp, _ := e.do("POST", "/hosts/"+itoa(id), form); resp.StatusCode != 303 {
		t.Errorf("modification forcée : %d", resp.StatusCode)
	}

	e.target = checks.Result{Status: checks.OK, Code: "target_ok", Message: "ok"}
	resp, body = e.do("POST", "/hosts/"+itoa(id), url.Values{"domain": {"other.example.com"}, "target": {"192.0.2.99:1"}})
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "existe déjà") {
		t.Errorf("doublon : %d", resp.StatusCode)
	}
	// Une saisie invalide n'est jamais forcée.
	resp, _ = e.do("POST", "/hosts/"+itoa(id), url.Values{"domain": {"https://x.example.com"}, "target": {"192.0.2.1"}, "force": {"1"}})
	if resp.StatusCode != 422 {
		t.Errorf("saisie invalide forcée : %d", resp.StatusCode)
	}
}

func TestEditHostRollsBackWhenCaddyRefuses(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	e.caddy.failNext = &caddyadmin.APIError{Status: 500, Message: "unknown module"}
	resp, body := e.do("POST", "/hosts/"+itoa(id), url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.50:80"}})
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "unknown module") {
		t.Fatalf("refus de Caddy : %d", resp.StatusCode)
	}
	if h, _ := e.store.HostByID(context.Background(), id); h.Target != "http://192.0.2.21:8080" {
		t.Errorf("cible gardée alors que Caddy a refusé : %s", h.Target)
	}
	if got := e.caddy.last(); got[0].Target != "http://192.0.2.21:8080" {
		t.Errorf("Caddy n'est pas revenu à l'ancien état : %+v", got)
	}
}

func (e *env) post(path string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	return e.do("POST", path, form)
}

func TestCreateRedirectPublishesToCaddy(t *testing.T) {
	e := newEnv(t)
	e.setup()
	resp, _ := e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"Old.Example.com"}, "target": {"nouveau.example.org"}, "preserve": {"1"}, "code": {"301"}})
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/redirections?added=old.example.com") {
		t.Fatalf("création : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	got := e.caddy.last()
	if len(got) != 1 || got[0].Kind != "redirect" || got[0].Target != "https://nouveau.example.org" || got[0].Code != 301 || !got[0].PreservePath {
		t.Errorf("publié dans Caddy : %+v", got)
	}
	// La liste « Hôtes » ne montre que les services ; les redirections auront leur page.
	_, body := e.do("GET", "/hosts", nil)
	if strings.Contains(body, "old.example.com") {
		t.Error("une redirection ne doit pas apparaître dans la liste des hôtes")
	}
}

func TestCreateNotFoundNeedsOnlyADomain(t *testing.T) {
	e := newEnv(t)
	e.setup()
	resp, _ := e.post("/hosts", url.Values{"kind": {"404"}, "domain": {"gone.example.com"}, "target": {"http://ignore.example.com"}})
	if resp.StatusCode != 303 {
		t.Fatalf("création : %d", resp.StatusCode)
	}
	if got := e.caddy.last(); len(got) != 1 || got[0].Kind != "404" || got[0].Target != "" {
		t.Errorf("publié dans Caddy : %+v", got)
	}
	// Une page 404 sans domaine est refusée avec un message adapté.
	resp, body := e.post("/hosts", url.Values{"kind": {"404"}, "domain": {""}})
	if resp.StatusCode != 422 || !strings.Contains(body, "Indiquez le domaine.") {
		t.Errorf("sans domaine : %d", resp.StatusCode)
	}
}

func TestRedirectRefusalsAreNeverForceable(t *testing.T) {
	e := newEnv(t)
	e.setup()
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"boucle", url.Values{"domain": {"a.example.com"}, "target": {"https://a.example.com"}}, "en boucle"},
		{"chemin gardé avec chemin", url.Values{"domain": {"a.example.com"}, "target": {"https://b.example.org/page"}, "preserve": {"1"}}, "garder le chemin"},
		{"accolades", url.Values{"domain": {"a.example.com"}, "target": {"https://b.example.org/{http.request.host}"}}, "non autorisés"},
		{"destination absente", url.Values{"domain": {"a.example.com"}, "target": {""}}, "Indiquez le domaine et la destination"},
	}
	for _, c := range cases {
		c.form.Set("kind", "redirect")
		c.form.Set("force", "1") // même forcé, une saisie invalide est refusée
		resp, body := e.post("/hosts", c.form)
		if resp.StatusCode != 422 || !strings.Contains(body, c.want) || strings.Contains(body, "Créer quand même") {
			t.Errorf("%s : %d", c.name, resp.StatusCode)
		}
	}
	if hosts, _ := e.store.ListHosts(context.Background()); len(hosts) != 0 {
		t.Errorf("hôtes créés : %+v", hosts)
	}
}

func TestRedirectDoesNotRunServiceCheckButRunsDNS(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.target = checks.Result{Status: checks.Error, Code: "target_refused", Message: "NE DOIT PAS ÊTRE APPELÉ"}
	e.dns = checks.Result{Status: checks.Error, Code: "dns_not_found", Message: "Le domaine n'existe pas dans le DNS."}
	// Le DNS bloque, la cible (injoignable) ne bloque pas : seul le DNS apparaît.
	resp, body := e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"a.example.com"}, "target": {"https://b.example.org"}})
	if resp.StatusCode != 422 || !strings.Contains(body, "n&#39;existe pas dans le DNS") || strings.Contains(body, "NE DOIT PAS") {
		t.Fatalf("%d", resp.StatusCode)
	}
	// Le contrôle en direct de la destination est local : forme valide = OK, sans réseau.
	_, body = e.post("/hosts/check/target", url.Values{"kind": {"redirect"}, "domain": {"a.example.com"}, "target": {"b.example.org"}})
	if !strings.Contains(body, "envoyés vers https://b.example.org") || strings.Contains(body, "NE DOIT PAS") {
		t.Errorf("contrôle de destination : %s", body)
	}
	_, body = e.post("/hosts/check/target", url.Values{"kind": {"redirect"}, "domain": {"a.example.com"}, "target": {"https://a.example.com"}})
	if !strings.Contains(body, "en boucle") {
		t.Errorf("boucle non signalée en direct : %s", body)
	}
	_, body = e.post("/hosts/check/target", url.Values{"kind": {"404"}, "domain": {"a.example.com"}, "target": {"x"}})
	if strings.Contains(body, "pill") {
		t.Errorf("une page 404 n'a rien à vérifier côté cible : %s", body)
	}
}

func TestNewFormShowsFieldsForEachKind(t *testing.T) {
	e := newEnv(t)
	e.setup()
	tests := []struct {
		path        string
		has, hasNot []string
	}{
		{"/hosts/new", []string{`name="target"`, "Nouvel hôte", "Créer l&#39;hôte"}, []string{`name="preserve"`, `name="code"`}},
		{"/hosts/new?kind=redirect", []string{`name="target"`, `name="preserve"`, `name="code"`, "Garder le chemin", "Permanente (301)", "Créer la redirection"}, []string{"Cible"}},
		{"/hosts/new?kind=404", []string{`name="domain"`, "Créer l&#39;erreur 404"}, []string{`name="target"`, `name="preserve"`, "Vérification du service"}},
		{"/hosts/new?kind=n-importe-quoi", []string{`name="target"`}, []string{`name="preserve"`}},
	}
	for _, tt := range tests {
		_, body := e.do("GET", tt.path, nil)
		for _, w := range tt.has {
			if !strings.Contains(body, w) {
				t.Errorf("%s sans %q", tt.path, w)
			}
		}
		for _, w := range tt.hasNot {
			if strings.Contains(body, w) {
				t.Errorf("%s contient %q", tt.path, w)
			}
		}
	}
}

func TestEditRedirectKeepsKindAndUpdatesOptions(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"old.example.com"}, "target": {"https://new.example.org"}, "preserve": {"1"}})
	h, _ := e.srvHostByDomain("old.example.com")
	// Le formulaire de modification est prérempli, sans choix de type.
	_, body := e.do("GET", "/hosts/"+itoa(h.ID)+"/edit", nil)
	for _, w := range []string{`name="preserve" value="1" checked`, `value="https://new.example.org"`, "Garder le chemin"} {
		if !strings.Contains(body, w) {
			t.Errorf("modification sans %q", w)
		}
	}
	if strings.Contains(body, "Autre besoin") {
		t.Error("le type d'un hôte existant ne se change pas")
	}
	// On peut passer en temporaire et ne plus garder le chemin ; un « kind » falsifié est ignoré.
	resp, _ := e.post("/hosts/"+itoa(h.ID), url.Values{"kind": {"proxy"}, "domain": {"old.example.com"}, "target": {"https://new.example.org/accueil"}, "code": {"302"}})
	if resp.StatusCode != 303 {
		t.Fatalf("modification : %d", resp.StatusCode)
	}
	after, _ := e.store.HostByID(context.Background(), h.ID)
	if after.Kind != "redirect" || after.Code != 302 || after.PreservePath || after.Target != "https://new.example.org/accueil" {
		t.Errorf("après modification : %+v", after)
	}
	if got := e.caddy.last(); got[0].Kind != "redirect" || got[0].Code != 302 || got[0].PreservePath {
		t.Errorf("Caddy : %+v", got)
	}
}

func TestEditRedirectRollsBackWhenCaddyRefuses(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"old.example.com"}, "target": {"https://new.example.org"}, "preserve": {"1"}})
	h, _ := e.srvHostByDomain("old.example.com")
	e.caddy.failNext = errors.New("refus")
	resp, _ := e.post("/hosts/"+itoa(h.ID), url.Values{"domain": {"old.example.com"}, "target": {"https://autre.example.org"}, "preserve": {"1"}, "code": {"302"}})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("%d", resp.StatusCode)
	}
	after, _ := e.store.HostByID(context.Background(), h.ID)
	if after.Target != "https://new.example.org" || after.Code != 301 || !after.PreservePath {
		t.Errorf("état non restauré : %+v", after)
	}
}

func TestFirstFormShowsTheTypePickerThenDomainAndTarget(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, body := e.do("GET", "/hosts/new", nil)
	for _, bad := range []string{`class="tabs"`, `name="preserve"`, `name="code"`} {
		if strings.Contains(body, bad) {
			t.Errorf("le formulaire d'accueil contient %q", bad)
		}
	}
	for _, want := range []string{"Nouvel hôte", "Cible"} {
		if !strings.Contains(body, want) {
			t.Errorf("formulaire d'accueil sans %q", want)
		}
	}
	// Le choix du type (service, redirection, page 404) vient en premier ; les réglages propres à une
	// redirection n'apparaissent qu'une fois ce type choisi.
	for _, want := range []string{`href="/hosts/new?kind=redirect"`, `href="/hosts/new?kind=404"`, `aria-current="true"`, "Redirection", "Page 404"} {
		if !strings.Contains(body, want) {
			t.Errorf("le formulaire d'accueil doit proposer le type : %q manque", want)
		}
	}
}

func TestHostsListSearchAndRow(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	e.addHost("photos.example.com", "http://192.0.2.22:2283")
	e.post("/hosts", url.Values{"kind": {"404"}, "domain": {"gone.example.com"}})

	// Page complète : domaine en gras, cible en dessous, la ligne entière mène à la page Modifier.
	_, body := e.do("GET", "/hosts", nil)
	for _, want := range []string{`<b>wiki.example.com</b>`, `class="dest">http://192.0.2.21:8080`, `/edit"`, `type="search"`, "<span>Domaine</span><span>Destination</span>"} {
		if !strings.Contains(body, want) {
			t.Errorf("liste sans %q", want)
		}
	}
	for _, bad := range []string{`class="menu"`, "gone.example.com"} {
		if strings.Contains(body, bad) {
			t.Errorf("la liste contient %q", bad)
		}
	}
	// Recherche par domaine, par cible, sans tenir compte de la casse (services seulement).
	for q, want := range map[string]string{"wiki": "wiki.example.com", "2283": "photos.example.com", "PHOTOS": "photos.example.com"} {
		_, b := e.do("GET", "/hosts?q="+q, nil)
		if !strings.Contains(b, want) || strings.Count(b, ` id="host-`) != 1 {
			t.Errorf("recherche %q : %d lignes", q, strings.Count(b, ` id="host-`))
		}
	}
	_, b := e.do("GET", "/hosts?q=rien-de-tel", nil)
	if !strings.Contains(b, "Aucun résultat pour") {
		t.Error("message de recherche vide absent")
	}
	// Requête htmx : seulement la liste, pas la page.
	_, frag := e.do("GET", "/hosts?q=wiki", nil, "HX-Request", "true")
	if strings.Contains(frag, "<html") || strings.Contains(frag, "Nouvel hôte") || !strings.Contains(frag, "wiki.example.com") {
		t.Errorf("fragment htmx inattendu : %s", frag)
	}
	// La saisie de recherche est échappée.
	_, b = e.do("GET", "/hosts?q="+url.QueryEscape(`"><script>alert(1)</script>`), nil)
	if strings.Contains(b, "<script>alert") {
		t.Error("recherche non échappée")
	}
}

func TestCaddyfilePreview(t *testing.T) {
	tests := []struct {
		f    formInput
		want string
	}{
		{formInput{Kind: "proxy", Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"}, "wiki.example.com {\n  reverse_proxy 192.0.2.21:8080\n}"},
		{formInput{Kind: "proxy", Domain: "nas.example.com", Target: "https://192.0.2.30:5001"}, "nas.example.com {\n  reverse_proxy https://192.0.2.30:5001 {\n    header_up Host {hostport}\n  }\n}"},
		{formInput{Kind: "redirect", Domain: "old.example.com", Target: "https://new.example.org", Code: 301, Preserve: true}, "old.example.com {\n  redir https://new.example.org{uri} 301\n}"},
		{formInput{Kind: "redirect", Domain: "old.example.com", Target: "https://new.example.org/landing", Code: 302}, "old.example.com {\n  redir https://new.example.org/landing 302\n}"},
		{formInput{Kind: "404", Domain: "gone.example.com"}, "gone.example.com {\n  respond \"404 Not Found\" 404\n}"},
	}
	for _, tt := range tests {
		if got := caddyfilePreview(tt.f, nil); got != tt.want {
			t.Errorf("%+v →\n%s\nattendu\n%s", tt.f, got, tt.want)
		}
	}
}

func TestPreviewEndpoint(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, body := e.post("/hosts/check/preview", url.Values{"kind": {"proxy"}, "domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	if !strings.Contains(body, "<pre>wiki.example.com {") || !strings.Contains(body, "reverse_proxy 192.0.2.21:8080") {
		t.Errorf("aperçu : %s", body)
	}
	// Saisie incomplète ou invalide : pas d'aperçu trompeur.
	for _, form := range []url.Values{
		{"kind": {"proxy"}, "domain": {""}, "target": {"x"}},
		{"kind": {"proxy"}, "domain": {"wiki.example.com"}, "target": {""}},
		{"kind": {"redirect"}, "domain": {"a.example.com"}, "target": {"https://a.example.com"}},
	} {
		if _, b := e.post("/hosts/check/preview", form); strings.Contains(b, "<pre>") {
			t.Errorf("aperçu pour une saisie invalide %v : %s", form, b)
		}
	}
}

func TestRedirectAndNotFoundListsAndMenu(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"old.example.com"}, "target": {"nouveau.example.org"}, "preserve": {"1"}, "code": {"302"}})
	e.post("/hosts", url.Values{"kind": {"404"}, "domain": {"vieux.example.com"}})
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})

	_, body := e.do("GET", "/redirections", nil)
	for _, w := range []string{"old.example.com", "→\u00a0https://nouveau.example.org", "Temporaire", "garde le chemin", "Nouvelle redirection", `class="chip on" href="/redirections"`} {
		if !strings.Contains(body, w) {
			t.Errorf("/redirections sans %q", w)
		}
	}
	for _, w := range []string{"vieux.example.com", "wiki.example.com"} {
		if strings.Contains(body, w) {
			t.Errorf("/redirections contient %q", w)
		}
	}
	_, body = e.do("GET", "/erreurs-404", nil)
	if !strings.Contains(body, "vieux.example.com") || !strings.Contains(body, "Répond « 404 Not Found »") || strings.Contains(body, "old.example.com") {
		t.Error("/erreurs-404 : contenu inattendu")
	}
	_, body = e.do("GET", "/hosts", nil)
	if !strings.Contains(body, "wiki.example.com") || strings.Contains(body, "old.example.com") || !strings.Contains(body, `href="/erreurs-404"`) {
		t.Error("/ : contenu ou menu inattendu")
	}

	// Supprimer une redirection ramène à la liste des redirections.
	hosts, _ := e.srv.cfg.Store.ListHosts(context.Background())
	var id int64
	for _, h := range hosts {
		if h.Domain == "old.example.com" {
			id = h.ID
		}
	}
	resp, _ := e.post("/hosts/"+strconv.FormatInt(id, 10)+"/delete", nil)
	if got := resp.Header.Get("HX-Redirect"); got != "/redirections?deleted=old.example.com" {
		t.Errorf("HX-Redirect = %q", got)
	}
}

func TestDashboardShowsOnlineHostsAndEvents(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, body := e.do("GET", "/", nil)
	// Sans hôte : l'accueil pour le premier service, pas de cases de chiffres.
	if !strings.Contains(body, "Publiez votre premier service") || strings.Contains(body, `hx-get="/dashboard/online"`) || strings.Contains(body, "Votre passerelle") {
		t.Errorf("vue d'ensemble vide : contenu inattendu : %s", body)
	}
	_, frag := e.do("GET", "/dashboard/online", nil)
	if !strings.Contains(frag, "Aucun service à vérifier") {
		t.Errorf("aucun hôte : %s", frag)
	}

	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	e.post("/hosts", url.Values{"domain": {"blog.example.com"}, "target": {"192.0.2.22:8080"}})
	e.post("/hosts", url.Values{"kind": {"404"}, "domain": {"vieux.example.com"}})
	_, body = e.do("GET", "/", nil)
	if !strings.Contains(body, `hx-get="/dashboard/online"`) || strings.Contains(body, "Publiez votre premier service") {
		t.Error("cases de chiffres absentes alors que des hôtes existent")
	}
	_, settings := e.do("GET", "/settings", nil)
	if !strings.Contains(settings, "Hôte vieux.example.com créé") || !strings.Contains(settings, "à l&#39;instant") {
		t.Errorf("événements absents du journal d'audit : %s", settings)
	}
	_, frag = e.do("GET", "/dashboard/online", nil)
	if !strings.Contains(frag, "2 / 2") || !strings.Contains(frag, "Tous répondent") {
		t.Errorf("hôtes en ligne : %s", frag)
	}

	e.srv.cfg.CheckTarget = func(ctx context.Context, target string, _ bool) checks.Result {
		if strings.Contains(target, "192.0.2.22") {
			return checks.Result{Status: checks.Error}
		}
		return checks.Result{Status: checks.OK}
	}
	_, frag = e.do("GET", "/dashboard/online", nil)
	if !strings.Contains(frag, "1 / 2") || !strings.Contains(frag, "1 en erreur") {
		t.Errorf("hôte en erreur : %s", frag)
	}
	// « À surveiller » nomme l'hôte en erreur.
	if !strings.Contains(frag, `id="watch"`) || !strings.Contains(frag, "À surveiller") || !strings.Contains(frag, "blog.example.com") || !strings.Contains(frag, `<span class="pill err">Injoignable</span>`) {
		t.Errorf("hôte en erreur non signalé : %s", frag)
	}
}

func TestDashboardTilesAndWatchList(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})

	// Rien d'installé ni d'activé (journal d'accès désactivé à la main) : cases sobres, rien à surveiller.
	if err := e.srv.saveAccessLog(ctx, false, 0); err != nil {
		t.Fatal(err)
	}
	_, body := e.do("GET", "/", nil)
	for _, w := range []string{"CrowdSec non installé", "journal d'accès désactivé", "illisibles dans cette configuration"} {
		if !strings.Contains(body, w) {
			t.Errorf("page sans %q", w)
		}
	}
	if _, frag := e.do("GET", "/dashboard/online", nil); strings.Contains(frag, "À surveiller") || strings.Contains(frag, "tile-protection") {
		t.Errorf("rien à surveiller : %s", frag)
	}

	// Certificats : nombre et prochaine échéance ; ceux qui expirent bientôt sont à surveiller.
	dir := t.TempDir()
	e.srv.cfg.CertDir = dir
	now := e.srv.cfg.Now()
	for name, left := range map[string]time.Duration{"ok.example.com": 62 * 24 * time.Hour, "bientot.example.com": 9 * 24 * time.Hour} {
		d := filepath.Join(dir, "acme-v02.api.letsencrypt.org-directory", name)
		os.MkdirAll(d, 0o755)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-100 * 24 * time.Hour), NotAfter: now.Add(left)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		os.WriteFile(filepath.Join(d, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	}
	// Un certificat expiré resté sur le disque, sans hôte, n'est ni une alerte ni une couleur rouge.
	writeFakeCert(t, dir, "orphelin.example.com", now, -30*24*time.Hour)
	for _, d := range []string{"ok.example.com", "bientot.example.com"} {
		e.post("/hosts", url.Values{"domain": {d}, "target": {"192.0.2.9:8080"}})
	}
	_, body = e.do("GET", "/", nil)
	if !strings.Contains(body, "<strong>3</strong>") || !strings.Contains(body, "prochaine échéance dans 8 j") || strings.Contains(body, "status-cell err") {
		t.Errorf("case Certificats : %s", body)
	}
	_, frag := e.do("GET", "/dashboard/online", nil)
	if !strings.Contains(frag, "<b>bientot.example.com</b> Le certificat expire dans 8 j.") || strings.Contains(frag, "ok.example.com") || strings.Contains(frag, "orphelin.example.com") {
		t.Errorf("certificat à surveiller : %s", frag)
	}

	// Trafic : résumé du journal, une fois activé.
	file := filepath.Join(t.TempDir(), "access.log")
	e.srv.cfg.AccessLogFile = file
	os.WriteFile(file, []byte(`{"ts":1793743000,"request":{"client_ip":"192.0.2.10","host":"a","method":"GET","uri":"/"},"status":200}
{"ts":1793743100,"request":{"client_ip":"192.0.2.11","host":"a","method":"GET","uri":"/x"},"status":404}
`), 0o600)
	e.post("/settings", url.Values{"goaccess_report_url": {"http://127.0.0.1:8091"}, "accesslog": {"1"}, "accesslog_days": {"30"}})
	if _, b := e.do("GET", "/", nil); !strings.Contains(b, "<strong>2</strong>") || !strings.Contains(b, "requêtes · 1 erreur") {
		t.Errorf("case Trafic : %s", b)
	}

	// Protection : CrowdSec connecté, décisions lues à la volée.
	lapi := fakeLAPI(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}})
	if _, b := e.do("GET", "/", nil); strings.Contains(b, "CrowdSec non installé") {
		t.Error("CrowdSec connecté affiché comme non installé")
	}
	if _, frag = e.do("GET", "/dashboard/online", nil); !strings.Contains(frag, `id="tile-protection" hx-swap-oob="innerHTML"`) || !strings.Contains(frag, "<strong>2</strong>") || !strings.Contains(frag, "CrowdSec connecté") {
		t.Errorf("case Protection : %s", frag)
	}

	_ = ctx
}

func TestNoLoginSkipsAuthentication(t *testing.T) {
	e := newEnv(t)
	if resp, _ := e.do("GET", "/hosts", nil); resp.StatusCode != 303 {
		t.Fatalf("sans NoLogin : %d", resp.StatusCode)
	}
	e.srv.cfg.NoLogin = true
	if resp, body := e.do("GET", "/hosts", nil); resp.StatusCode != 200 || !strings.Contains(body, "Nouvel hôte") {
		t.Errorf("avec NoLogin : %d", resp.StatusCode)
	}
}

func TestAccessListsLifecycle(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, body := e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "Aucune liste pour l'instant") {
		t.Error("état vide absent")
	}

	// Saisie invalide : refusée, rien n'est enregistré.
	resp, body := e.post("/security/lists", url.Values{"name": {"Bureau"}, "addresses": {"192.0.2.0/24 n-importe-quoi"}})
	if resp.StatusCode != 422 || !strings.Contains(body, "n-importe-quoi") {
		t.Errorf("adresse invalide : %d", resp.StatusCode)
	}
	if resp, _ := e.post("/security/lists", url.Values{"name": {" "}, "addresses": {"192.0.2.7"}}); resp.StatusCode != 422 {
		t.Errorf("nom vide : %d", resp.StatusCode)
	}

	resp, _ = e.post("/security/lists", url.Values{"name": {"Bureau"}, "addresses": {"192.0.2.9/24, 198.51.100.7\n2001:db8::1"}})
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/security/protection?added=Bureau") {
		t.Fatalf("création : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	lists, _ := e.srv.cfg.Store.AccessLists(context.Background())
	if len(lists) != 1 || strings.Join(lists[0].Addresses, " ") != "192.0.2.0/24 198.51.100.7 2001:db8::1" {
		t.Fatalf("listes : %+v", lists)
	}
	if resp, _ := e.post("/security/lists", url.Values{"name": {"Bureau"}, "addresses": {"192.0.2.7"}}); resp.StatusCode != 409 {
		t.Errorf("doublon : %d", resp.StatusCode)
	}
	_, body = e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "Bureau") || !strings.Contains(body, "192.0.2.0/24 · 198.51.100.7") {
		t.Error("liste absente de la page")
	}

	id := itoa(lists[0].ID)
	resp, _ = e.post("/security/lists/"+id, url.Values{"name": {"Bureau"}, "addresses": {"192.0.2.7"}})
	if resp.StatusCode != 303 {
		t.Errorf("modification : %d", resp.StatusCode)
	}
	lists, _ = e.srv.cfg.Store.AccessLists(context.Background())
	if len(lists[0].Addresses) != 1 {
		t.Errorf("après modification : %+v", lists)
	}
	resp, _ = e.post("/security/lists/"+id+"/delete", nil)
	if resp.Header.Get("HX-Redirect") != "/security/protection?deleted=Bureau#listes" {
		t.Errorf("suppression : %q", resp.Header.Get("HX-Redirect"))
	}
	if lists, _ = e.srv.cfg.Store.AccessLists(context.Background()); len(lists) != 0 {
		t.Error("liste toujours présente")
	}
}

func TestHostAccessList(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()

	// Sans liste, le formulaire n'affiche pas le choix « Accès ».
	_, body := e.do("GET", "/hosts/new", nil)
	if strings.Contains(body, `name="access"`) {
		t.Error("choix Accès affiché sans liste")
	}
	listID, _ := e.srv.cfg.Store.AddAccessList(ctx, store.AccessList{Name: "Bureau", Addresses: []string{"192.0.2.0/24"}})
	_, body = e.do("GET", "/hosts/new", nil)
	if !strings.Contains(body, `name="access"`) || !strings.Contains(body, "Limité à « Bureau »") || !strings.Contains(body, "Public : tout le monde") {
		t.Error("choix Accès absent")
	}
	if _, b := e.do("GET", "/hosts/new?kind=404", nil); strings.Contains(b, `name="access"`) {
		t.Error("choix Accès affiché pour une erreur 404")
	}

	// Liste inexistante : refusé.
	if resp, _ := e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "access": {"99"}}); resp.StatusCode != 422 {
		t.Errorf("liste inexistante : %d", resp.StatusCode)
	}
	resp, _ := e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "access": {itoa(listID)}})
	if resp.StatusCode != 303 {
		t.Fatalf("création : %d", resp.StatusCode)
	}
	if got := e.caddy.last(); len(got) != 1 || strings.Join(got[0].Access, " ") != "192.0.2.0/24" {
		t.Fatalf("Caddy : %+v", got)
	}
	// La page Modifier présélectionne la liste ; la page Sécurité compte l'hôte.
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	_, body = e.do("GET", "/hosts/"+itoa(hosts[0].ID)+"/edit", nil)
	if !strings.Contains(body, `value="`+itoa(listID)+`" selected`) {
		t.Error("liste non présélectionnée")
	}
	_, body = e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "1 hôte<") {
		t.Errorf("compteur d'hôtes absent : %s", body)
	}

	// Modifier la liste republie l'hôte avec les nouvelles adresses.
	e.post("/security/lists/"+itoa(listID), url.Values{"name": {"Bureau"}, "addresses": {"198.51.100.0/24"}})
	if got := e.caddy.last(); strings.Join(got[0].Access, " ") != "198.51.100.0/24" {
		t.Errorf("après modification de la liste : %+v", got)
	}
	// Si Caddy refuse, la liste revient à son état d'avant.
	e.caddy.failNext = errors.New("refus")
	resp, _ = e.post("/security/lists/"+itoa(listID), url.Values{"name": {"Bureau"}, "addresses": {"203.0.113.0/24"}})
	if resp.StatusCode != 502 {
		t.Errorf("refus de Caddy : %d", resp.StatusCode)
	}
	if l, _ := e.srv.cfg.Store.AccessListByID(ctx, listID); strings.Join(l.Addresses, " ") != "198.51.100.0/24" {
		t.Errorf("liste non restaurée : %+v", l)
	}

	// Une liste utilisée ne se supprime pas.
	resp, body = e.post("/security/lists/"+itoa(listID)+"/delete", nil)
	if resp.Header.Get("HX-Redirect") != "" || !strings.Contains(body, "limite l&#39;accès de 1 hôte") {
		t.Errorf("suppression d'une liste utilisée : %q %q", resp.Header.Get("HX-Redirect"), body)
	}
	// Repasser l'hôte en public libère la liste.
	e.post("/hosts/"+itoa(hosts[0].ID), url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "access": {"0"}})
	if got := e.caddy.last(); len(got[0].Access) != 0 {
		t.Errorf("hôte public : %+v", got)
	}
	if resp, _ := e.post("/security/lists/"+itoa(listID)+"/delete", nil); resp.Header.Get("HX-Redirect") != "/security/protection?deleted=Bureau#listes" {
		t.Errorf("suppression : %q", resp.Header.Get("HX-Redirect"))
	}
}

func TestCertificatesPage(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, body := e.do("GET", "/certificates", nil)
	if !strings.Contains(body, "ne peut pas lire les certificats") {
		t.Error("message « indisponible » absent sans dossier")
	}

	dir := t.TempDir()
	e.srv.cfg.CertDir = dir
	_, body = e.do("GET", "/certificates", nil)
	if !strings.Contains(body, "Aucun certificat pour l'instant") {
		t.Error("état vide absent")
	}

	now := e.srv.cfg.Now()
	for name, left := range map[string]time.Duration{"ok.example.com": 62 * 24 * time.Hour, "bientot.example.com": 9 * 24 * time.Hour, "perime.example.com": -time.Hour} {
		d := filepath.Join(dir, "acme-v02.api.letsencrypt.org-directory", name)
		os.MkdirAll(d, 0o755)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-100 * 24 * time.Hour), NotAfter: now.Add(left)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		os.WriteFile(filepath.Join(d, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	}
	_, body = e.do("GET", "/certificates", nil)
	for _, w := range []string{"Let&#39;s Encrypt", `<span class="pill ok">61 j</span>`, `<span class="pill warn">8 j</span>`, `<span class="pill err">expiré</span>`} {
		if !strings.Contains(body, w) {
			t.Errorf("page sans %q", w)
		}
	}
}

func TestDNSAccountsLifecycleAndChallenge(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()

	// Le formulaire propose les 8 fournisseurs et les champs du premier ; les champs d'un autre se chargent par htmx.
	_, body := e.do("GET", "/certificates/dns/new", nil)
	for _, w := range []string{"Cloudflare", "OVH", "Gandi", "Amazon Route 53", "DigitalOcean", "Hetzner", "Infomaniak", "IONOS", `name="f_api_token"`} {
		if !strings.Contains(body, w) {
			t.Errorf("formulaire sans %q", w)
		}
	}
	_, frag := e.do("GET", "/certificates/dns/fields?provider=ovh", nil)
	if !strings.Contains(frag, `name="f_consumer_key"`) || !strings.Contains(frag, `value="ovh-eu"`) || strings.Contains(frag, "<html") {
		t.Errorf("champs OVH : %s", frag)
	}

	// Champ obligatoire absent : refusé.
	if resp, _ := e.post("/certificates/dns", url.Values{"name": {"Mon OVH"}, "provider": {"ovh"}, "f_endpoint": {"ovh-eu"}}); resp.StatusCode != 422 {
		t.Errorf("champs manquants : %d", resp.StatusCode)
	}
	resp, _ := e.post("/certificates/dns", url.Values{"name": {"Mon OVH"}, "provider": {"ovh"}, "f_endpoint": {"ovh-eu"},
		"f_application_key": {"ak-fictif"}, "f_application_secret": {"as-secret-fictif"}, "f_consumer_key": {"ck-secret-fictif"}})
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/certificates?added=") {
		t.Fatalf("création : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	accounts, _ := e.srv.cfg.Store.DNSAccounts(ctx)
	if len(accounts) != 1 || accounts[0].Provider != "ovh" {
		t.Fatalf("comptes : %+v", accounts)
	}
	// Rien de lisible en base : ni secret, ni clé d'application.
	if strings.Contains(accounts[0].Secret, "secret-fictif") || strings.Contains(accounts[0].Secret, "ak-fictif") {
		t.Error("identifiants en clair dans la base")
	}
	id := itoa(accounts[0].ID)

	// Modifier : les secrets ne sont jamais réaffichés ; un secret laissé vide est conservé.
	_, body = e.do("GET", "/certificates/dns/"+id+"/edit", nil)
	if strings.Contains(body, "secret-fictif") || !strings.Contains(body, "ak-fictif") || !strings.Contains(body, "Inchangé") {
		t.Error("page Modifier : secret réaffiché ou clé d'application absente")
	}
	e.post("/certificates/dns/"+id, url.Values{"name": {"Mon OVH"}, "f_endpoint": {"ovh-ca"}, "f_application_key": {"ak-fictif"}, "f_application_secret": {""}, "f_consumer_key": {""}})
	accounts, _ = e.srv.cfg.Store.DNSAccounts(ctx)
	values, err := e.srv.dnsValues(accounts[0])
	if err != nil || values["endpoint"] != "ovh-ca" || values["consumer_key"] != "ck-secret-fictif" || values["application_secret"] != "as-secret-fictif" {
		t.Errorf("après modification : %v %v", values, err)
	}

	// Un hôte qui utilise le compte est publié avec son défi DNS ; un hôte sans compte, non.
	_, body = e.do("GET", "/hosts/new", nil)
	if !strings.Contains(body, "Défi DNS : Mon OVH (OVH)") || !strings.Contains(body, "Automatique (défi HTTP)") {
		t.Error("choix du certificat absent du formulaire d'hôte")
	}
	if resp, _ := e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "dns": {"99"}}); resp.StatusCode != 422 {
		t.Errorf("compte inexistant : %d", resp.StatusCode)
	}
	e.post("/hosts", url.Values{"domain": {"*.example.org"}, "kind": {"404"}, "dns": {id}})
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	var withDNS, without int
	for _, h := range e.caddy.last() {
		if h.DNS != nil && h.DNS.Provider["name"] == "ovh" && h.DNS.Provider["consumer_key"] == "ck-secret-fictif" {
			withDNS++
		} else if h.DNS == nil {
			without++
		}
	}
	if withDNS != 1 || without != 1 {
		t.Errorf("publication : %+v", e.caddy.last())
	}
	_, body = e.do("GET", "/certificates", nil)
	if !strings.Contains(body, "Mon OVH") || !strings.Contains(body, "1 hôte<") || strings.Contains(body, "secret-fictif") {
		t.Error("page Certificats : compte absent, compteur faux ou secret affiché")
	}

	// Compte utilisé : suppression refusée. Une fois l'hôte repassé en automatique : acceptée.
	resp, body = e.post("/certificates/dns/"+id+"/delete", nil)
	if resp.Header.Get("HX-Redirect") != "" || !strings.Contains(body, "sert aux certificats de 1 hôte") {
		t.Errorf("suppression d'un compte utilisé : %q %q", resp.Header.Get("HX-Redirect"), body)
	}
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	for _, h := range hosts {
		if h.DNSAccountID != 0 {
			e.post("/hosts/"+itoa(h.ID), url.Values{"domain": {h.Domain}, "dns": {"0"}})
		}
	}
	if resp, _ := e.post("/certificates/dns/"+id+"/delete", nil); resp.Header.Get("HX-Redirect") != "/certificates?deleted=Mon+OVH#dns" {
		t.Errorf("suppression : %q", resp.Header.Get("HX-Redirect"))
	}
}

func TestHostCertificateChoicesSelfSignedAndHTTPOnly(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()

	// Le choix est dans le bloc « Avancé », dès la création et sans compte DNS.
	_, body := e.do("GET", "/hosts/new", nil)
	for _, w := range []string{`name="dns"`, `<option value="internal">Auto-signé (Caddy)</option>`, `<option value="http">Aucun : HTTP seulement</option>`, "Automatique (défi HTTP)"} {
		if !strings.Contains(body, w) {
			t.Errorf("formulaire sans %q", w)
		}
	}
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	e.post("/hosts", url.Values{"domain": {"lan.example.com"}, "target": {"192.0.2.22:8080"}, "dns": {"internal"}})
	e.post("/hosts", url.Values{"domain": {"plain.example.com"}, "target": {"192.0.2.23:8080"}, "dns": {"http"}})
	got := map[string][2]bool{}
	for _, h := range e.caddy.last() {
		got[h.Domain] = [2]bool{h.SelfSigned, h.HTTPOnly}
	}
	if got["wiki.example.com"] != [2]bool{false, false} || got["lan.example.com"] != [2]bool{true, false} || got["plain.example.com"] != [2]bool{false, true} {
		t.Fatalf("publication : %v", got)
	}

	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	for _, h := range hosts {
		switch h.Domain {
		case "lan.example.com":
			_, b := e.do("GET", "/hosts/"+itoa(h.ID)+"/edit", nil)
			if !strings.Contains(b, `<option value="internal" selected>`) {
				t.Error("auto-signé non présélectionné ou bloc Avancé fermé")
			}
		case "plain.example.com":
			_, b := e.do("GET", "/hosts/"+itoa(h.ID)+"/edit", nil)
			if !strings.Contains(b, `<option value="http" selected>`) {
				t.Error("HTTP seulement non présélectionné")
			}
			// Retour au certificat automatique.
			e.post("/hosts/"+itoa(h.ID), url.Values{"domain": {"plain.example.com"}, "target": {"192.0.2.23:8080"}, "dns": {"0"}})
		}
	}
	for _, h := range e.caddy.last() {
		if h.Domain == "plain.example.com" && (h.HTTPOnly || h.SelfSigned) {
			t.Errorf("retour à Automatique : %+v", h)
		}
	}

	// L'aperçu montre `tls internal` ou l'adresse en http://.
	_, prev := e.do("POST", "/hosts/check/preview", url.Values{"domain": {"a.example.com"}, "target": {"192.0.2.1:80"}, "dns": {"internal"}})
	if !strings.Contains(prev, "tls internal") {
		t.Errorf("aperçu auto-signé : %s", prev)
	}
	_, prev = e.do("POST", "/hosts/check/preview", url.Values{"domain": {"a.example.com, b.example.com"}, "target": {"192.0.2.1:80"}, "dns": {"http"}})
	if !strings.Contains(prev, "http://a.example.com, http://b.example.com {") {
		t.Errorf("aperçu HTTP seulement : %s", prev)
	}
}

func TestCertificatesPageShowsChallengeAndDates(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	dir := t.TempDir()
	e.srv.cfg.CertDir = dir
	now := e.srv.cfg.Now()
	issued, expires := now.Add(-1*24*time.Hour), now.Add(89*24*time.Hour)
	for _, name := range []string{"auto.example.com", "dns.example.com", "off.example.com", "orphan.example.com"} {
		d := filepath.Join(dir, "acme-v02.api.letsencrypt.org-directory", name)
		os.MkdirAll(d, 0o755)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name, "www." + name}, NotBefore: issued, NotAfter: expires}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		os.WriteFile(filepath.Join(d, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	}
	sealed, _ := e.srv.cfg.Secrets.Seal(`{"api_token":"x"}`)
	acc, _ := e.srv.cfg.Store.AddDNSAccount(ctx, store.DNSAccount{Name: "Mon Cloudflare", Provider: "cloudflare", Secret: sealed})
	e.srv.cfg.Store.AddHostFull(ctx, store.Host{Domain: "auto.example.com", Kind: "404"})
	e.srv.cfg.Store.AddHostFull(ctx, store.Host{Domain: "dns.example.com", Kind: "404", DNSAccountID: acc})
	e.srv.cfg.Store.AddHostFull(ctx, store.Host{Domain: "off.example.com", Kind: "404", HTTPOnly: true})

	_, body := e.do("GET", "/certificates", nil)
	for _, w := range []string{
		"Automatique (HTTP)", "DNS · Cloudflare (Mon Cloudflare)", "Aucun (HTTP seulement)", "Aucun hôte",
		"couvre aussi www.auto.example.com", issued.Local().Format("02/01/2006"), "le " + expires.Local().Format("02/01/2006"),
		"Défi configuré",
	} {
		if !strings.Contains(body, w) {
			t.Errorf("page sans %q", w)
		}
	}
}

func TestDNSAccountsHaveTheirOwnPageUnderCertificates(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.srv.cfg.CertDir = t.TempDir()
	_, certs := e.do("GET", "/certificates", nil)
	if !strings.Contains(certs, `id="dns"`) || !strings.Contains(certs, "Comptes DNS") || !strings.Contains(certs, `href="/certificates/dns/new"`) {
		t.Error("/certificates : la section des comptes DNS est absente")
	}
	if resp, _ := e.do("GET", "/certificates/dns", nil); resp.StatusCode != 303 || resp.Header.Get("Location") != "/certificates#dns" {
		t.Errorf("/certificates/dns doit renvoyer vers la section : %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestHostWithSeveralDomains(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	var checked []string
	var mu sync.Mutex
	e.srv.cfg.CheckDNS = func(_ context.Context, d string) checks.Result {
		mu.Lock()
		checked = append(checked, d)
		mu.Unlock()
		return e.dns
	}

	resp, _ := e.post("/hosts", url.Values{"domain": {"Wiki.example.com, docs.example.com  wiki.example.org"}, "target": {"192.0.2.21:8080"}})
	if resp.StatusCode != 303 {
		t.Fatalf("création : %d", resp.StatusCode)
	}
	sort.Strings(checked)
	if strings.Join(checked, " ") != "docs.example.com wiki.example.com wiki.example.org" {
		t.Errorf("DNS vérifié pour : %v", checked)
	}
	got := e.caddy.last()
	if len(got) != 1 || got[0].Domain != "wiki.example.com" || strings.Join(got[0].Aliases, " ") != "docs.example.com wiki.example.org" {
		t.Fatalf("publication : %+v", got)
	}

	// La liste montre les autres noms, la recherche les trouve, la page Modifier les réaffiche.
	_, body := e.do("GET", "/hosts", nil)
	if !strings.Contains(body, "aussi : docs.example.com, wiki.example.org") {
		t.Error("autres noms absents de la liste")
	}
	if _, b := e.do("GET", "/hosts?q=docs", nil); !strings.Contains(b, "wiki.example.com") {
		t.Error("recherche par alias sans résultat")
	}
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	_, body = e.do("GET", "/hosts/"+itoa(hosts[0].ID)+"/edit", nil)
	if strings.Count(body, `name="domain"`) != 3 || !strings.Contains(body, `value="docs.example.com"`) || !strings.Contains(body, `value="wiki.example.org"`) {
		t.Error("noms non réaffichés, un par ligne, dans le champ Domaine")
	}

	// Un nom déjà pris (domaine ou alias d'un autre hôte), un doublon dans la saisie, un nom invalide : refusés.
	for name, domain := range map[string]string{
		"alias d'un autre hôte":  "autre.example.com, docs.example.com",
		"domaine d'un autre":     "wiki.example.org",
		"doublon dans la saisie": "x.example.com, x.example.com",
		"nom invalide":           "y.example.com, pas un nom!",
	} {
		resp, _ := e.post("/hosts", url.Values{"domain": {domain}, "target": {"192.0.2.22:8080"}})
		if resp.StatusCode != 409 && resp.StatusCode != 422 {
			t.Errorf("%s : %d", name, resp.StatusCode)
		}
	}
	if len(e.caddy.last()) != 1 {
		t.Errorf("un refus a modifié la publication : %+v", e.caddy.last())
	}

	// Retirer un alias en modifiant l'hôte.
	e.post("/hosts/"+itoa(hosts[0].ID), url.Values{"domain": {"wiki.example.com, docs.example.com"}, "target": {"192.0.2.21:8080"}})
	if got := e.caddy.last(); strings.Join(got[0].Aliases, " ") != "docs.example.com" {
		t.Errorf("après retrait : %+v", got)
	}
}

func TestHSTSOptionInAdvancedBlock(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	_, body := e.do("GET", "/hosts/new", nil)
	if strings.Contains(body, `class="adv"`) || !strings.Contains(body, `name="hsts"`) {
		t.Error("bloc Avancé présent ou HSTS absent à la création")
	}

	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "hsts": {"1"}})
	e.post("/hosts", url.Values{"domain": {"docs.example.com"}, "target": {"192.0.2.22:8080"}, "hsts": {"1"}, "hsts_sub": {"1"}})
	e.post("/hosts", url.Values{"domain": {"plain.example.com"}, "target": {"192.0.2.23:8080"}, "hsts_sub": {"1"}}) // sous-domaines sans HSTS : ignoré
	got := map[string]int{}
	for _, h := range e.caddy.last() {
		got[h.Domain] = h.HSTS
	}
	if got["wiki.example.com"] != 1 || got["docs.example.com"] != 2 || got["plain.example.com"] != 0 {
		t.Errorf("HSTS publié : %v", got)
	}

	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	for _, h := range hosts {
		if h.Domain == "docs.example.com" {
			_, body = e.do("GET", "/hosts/"+itoa(h.ID)+"/edit", nil)
			if !strings.Contains(body, `name="hsts_sub" value="1" checked`) {
				t.Error("page Modifier : bloc Avancé fermé ou sous-domaines non coché")
			}
			// Désactiver HSTS : l'hôte est republié sans en-tête.
			e.post("/hosts/"+itoa(h.ID), url.Values{"domain": {"docs.example.com"}, "target": {"192.0.2.22:8080"}})
		}
	}
	for _, h := range e.caddy.last() {
		if h.HSTS != 0 && h.Domain == "docs.example.com" {
			t.Errorf("HSTS toujours actif : %+v", h)
		}
	}

	// L'aperçu montre l'en-tête.
	_, prev := e.do("POST", "/hosts/check/preview", url.Values{"domain": {"a.example.com"}, "target": {"192.0.2.1:80"}, "hsts": {"1"}, "hsts_sub": {"1"}})
	if !strings.Contains(prev, `header Strict-Transport-Security &#34;max-age=31536000; includeSubDomains&#34;`) {
		t.Errorf("aperçu : %s", prev)
	}
}

func TestRootCertificateDownload(t *testing.T) {
	e := newEnv(t)
	e.setup()
	base := t.TempDir()
	e.srv.cfg.CertDir = filepath.Join(base, "certificates")
	os.MkdirAll(e.srv.cfg.CertDir, 0o755)

	// Pas encore de certificat racine : ni bouton, ni téléchargement.
	_, body := e.do("GET", "/certificates", nil)
	if strings.Contains(body, "Certificat racine de Caddy") {
		t.Error("bouton affiché sans certificat racine")
	}
	if resp, _ := e.do("GET", "/certificates/root.crt", nil); resp.StatusCode != 404 {
		t.Errorf("sans certificat racine : %d", resp.StatusCode)
	}

	dir := filepath.Join(base, "pki", "authorities", "local")
	os.MkdirAll(dir, 0o755)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	os.WriteFile(filepath.Join(dir, "root.crt"), crt, 0o644)
	os.WriteFile(filepath.Join(dir, "root.key"), []byte("clé privée fictive"), 0o600)

	_, body = e.do("GET", "/certificates", nil)
	if !strings.Contains(body, "Certificat racine de Caddy") || !strings.Contains(body, `href="/certificates/root.crt"`) {
		t.Error("bouton de téléchargement absent")
	}
	resp, got := e.do("GET", "/certificates/root.crt", nil)
	if resp.StatusCode != 200 || got != string(crt) || !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("téléchargement : %d %q", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	if strings.Contains(got, "clé privée") {
		t.Error("la clé privée est servie")
	}
	// Un fichier qui n'est pas un certificat n'est jamais servi.
	os.WriteFile(filepath.Join(dir, "root.crt"), []byte("autre chose"), 0o644)
	if resp, _ := e.do("GET", "/certificates/root.crt", nil); resp.StatusCode != 404 {
		t.Errorf("fichier invalide servi : %d", resp.StatusCode)
	}
}

func TestHostLocations(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	office, _ := e.srv.cfg.Store.AddAccessList(ctx, store.AccessList{Name: "Bureau", Addresses: []string{"198.51.100.0/24"}})
	lan, _ := e.srv.cfg.Store.AddAccessList(ctx, store.AccessList{Name: "Réseau local", Addresses: []string{"192.0.2.0/24"}})

	// Le bloc Avancé n'a aucune ligne au départ ; un clic en ajoute une (htmx). Rien pour une erreur 404.
	_, body := e.do("GET", "/hosts/new", nil)
	if strings.Contains(body, `name="loc_path"`) || !strings.Contains(body, "Ajouter une règle") {
		t.Error("le bloc Avancé ne doit proposer que le bouton d'ajout")
	}
	if _, row := e.do("GET", "/hosts/locations/row", nil); !strings.Contains(row, `name="loc_target"`) || !strings.Contains(row, "Comme le reste de l'hôte") || !strings.Contains(row, "Limité à « Bureau »") || strings.Contains(row, "<html") {
		t.Errorf("ligne htmx : %s", row)
	}
	if _, b := e.do("GET", "/hosts/new?kind=404", nil); strings.Contains(b, `name="loc_path"`) {
		t.Error("chemins proposés pour une erreur 404")
	}

	// Saisies invalides : refusées, jamais contournables, rien n'est publié.
	for name, f := range map[string]url.Values{
		"chemin sans cible": {"loc_path": {"/api"}, "loc_target": {""}, "loc_access": {"0"}},
		"cible sans chemin": {"loc_path": {""}, "loc_target": {"192.0.2.5:3000"}, "loc_access": {"0"}},
		"chemin invalide":   {"loc_path": {"api"}, "loc_target": {"192.0.2.5:3000"}, "loc_access": {"0"}},
		"cible invalide":    {"loc_path": {"/api"}, "loc_target": {"http://"}, "loc_access": {"0"}},
		"doublon":           {"loc_path": {"/api", "/api"}, "loc_target": {"a:1", "b:2"}, "loc_access": {"0", "0"}},
		"liste inexistante": {"loc_path": {"/api"}, "loc_target": {"a:1"}, "loc_access": {"99"}},
	} {
		f.Set("domain", "wiki.example.com")
		f.Set("target", "192.0.2.21:8080")
		f.Set("force", "1")
		if resp, _ := e.post("/hosts", f); resp.StatusCode != 422 {
			t.Errorf("%s : %d", name, resp.StatusCode)
		}
	}
	if len(e.caddy.applied) != 0 {
		t.Fatalf("une saisie invalide a été publiée : %+v", e.caddy.last())
	}

	// Une ligne vide est ignorée ; chaque chemin a son accès.
	resp, _ := e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "access": {itoa(lan)},
		"loc_path":   {"/api", "/admin", "/open", "/vault", ""},
		"loc_target": {"192.0.2.5:3000", "https://192.0.2.6:8443", "192.0.2.7:80", "", ""},
		"loc_access": {"0", itoa(office), "-1", itoa(office), "0"},
		"loc_strip":  {"0", "0", "0", "1", "0"}})
	if resp.StatusCode != 303 {
		t.Fatalf("création : %d", resp.StatusCode)
	}
	got := e.caddy.last()
	if len(got) != 1 || len(got[0].Locations) != 4 {
		t.Fatalf("publication : %+v", got)
	}
	byPath := map[string]caddyconf.Location{}
	for _, l := range got[0].Locations {
		byPath[l.Path] = l
	}
	if l := byPath["/api"]; l.Target != "http://192.0.2.5:3000" || l.Public || len(l.Access) != 0 {
		t.Errorf("/api (comme l'hôte) : %+v", l)
	}
	if l := byPath["/admin"]; strings.Join(l.Access, " ") != "198.51.100.0/24" || l.Target != "https://192.0.2.6:8443" {
		t.Errorf("/admin (liste propre) : %+v", l)
	}
	// Sans autre service, le chemin garde la cible de l'hôte, seul son accès change (le préfixe retiré est ignoré).
	if l := byPath["/vault"]; l.Target != "" || l.StripPath || strings.Join(l.Access, " ") != "198.51.100.0/24" {
		t.Errorf("/vault (même service, accès propre) : %+v", l)
	}
	if l := byPath["/open"]; !l.Public {
		t.Errorf("/open (public) : %+v", l)
	}

	// La page Modifier réaffiche les chemins et leur accès ; la page Sécurité compte l'hôte une fois par liste.
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	_, body = e.do("GET", "/hosts/"+itoa(hosts[0].ID)+"/edit", nil)
	for _, w := range []string{`value="/admin"`, `value="https://192.0.2.6:8443"`, `value="` + itoa(office) + `" selected`, `value="-1" selected`} {
		if !strings.Contains(body, w) {
			t.Errorf("page Modifier sans %q", w)
		}
	}
	_, sec := e.do("GET", "/security/protection", nil)
	if strings.Count(sec, "1 hôte<") != 2 {
		t.Errorf("compteurs de la page Sécurité : %s", sec)
	}

	// Une liste utilisée par un chemin ne se supprime pas ; modifier la liste republie.
	if resp, b := e.post("/security/lists/"+itoa(office)+"/delete", nil); resp.Header.Get("HX-Redirect") != "" || !strings.Contains(b, "limite l&#39;accès de 1 hôte") {
		t.Errorf("suppression d'une liste utilisée par un chemin : %q %q", resp.Header.Get("HX-Redirect"), b)
	}
	e.post("/security/lists/"+itoa(office), url.Values{"name": {"Bureau"}, "addresses": {"203.0.113.0/24"}})
	for _, l := range e.caddy.last()[0].Locations {
		if l.Path == "/admin" && strings.Join(l.Access, " ") != "203.0.113.0/24" {
			t.Errorf("liste modifiée non republiée : %+v", l)
		}
	}

	// Retirer un chemin : vider ses champs.
	e.post("/hosts/"+itoa(hosts[0].ID), url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "access": {itoa(lan)},
		"loc_path": {"/api", "", "/open"}, "loc_target": {"192.0.2.5:3000", "", "192.0.2.7:80"}, "loc_access": {"0", "0", "-1"}})
	if got := e.caddy.last(); len(got[0].Locations) != 2 {
		t.Errorf("après retrait d'un chemin : %+v", got[0].Locations)
	}

	// L'aperçu montre le refus propre à chaque chemin.
	_, prev := e.do("POST", "/hosts/check/preview", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "access": {itoa(lan)},
		"loc_path": {"/admin", "/open"}, "loc_target": {"192.0.2.6:80", "192.0.2.7:80"}, "loc_access": {itoa(office), "-1"}})
	for _, w := range []string{"handle /admin* {", "@refuse not client_ip 203.0.113.0/24", "handle /open* {", "@refuse not client_ip 192.0.2.0/24"} {
		if !strings.Contains(prev, w) {
			t.Errorf("aperçu sans %q : %s", w, prev)
		}
	}
}

func fakeLAPI(t *testing.T, key string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions" || r.Header.Get("X-Api-Key") != key {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`[{"duration":"3h41m10s","id":1,"origin":"crowdsec","scenario":"crowdsecurity/http-probing","scope":"Ip","type":"ban","value":"192.0.2.99"},
		{"duration":"47h","id":2,"origin":"cscli","scenario":"motif libre","scope":"Range","type":"ban","value":"198.51.100.0/24"}]`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCrowdSecConnectionLifecycle(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	lapi := fakeLAPI(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})

	_, body := e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "Installer CrowdSec") || !strings.Contains(body, "J'utilise déjà CrowdSec") || strings.Contains(body, "/security/crowdsec/status") {
		t.Error("carte CrowdSec non connecté : contenu inattendu")
	}
	for _, want := range []string{`<span>Sécurité</span>`, `href="/security/protection"`, `id="listes"`, `id="proxies"`, "Protection CrowdSec", "Listes d'accès", "Proxies de confiance"} {
		if !strings.Contains(body, want) {
			t.Errorf("menu Sécurité sans %q", want)
		}
	}
	_, install := e.do("GET", "/security/crowdsec/install", nil)
	for _, want := range []string{"Activer CrowdSec", "COMPOSE_PROFILES=crowdsec", "CrowdSec crée lui-même la clé de Gatewyn", "Continuer", "Utiliser un CrowdSec existant"} {
		if !strings.Contains(install, want) {
			t.Errorf("assistant CrowdSec : %q absent", want)
		}
	}
	if strings.Contains(install, `id="crowdsec-compose"`) || strings.Contains(install, "profiles:") || strings.Contains(install, "install-rail") || strings.Contains(install, "install-aside") || strings.Contains(install, "step-number") || strings.Contains(install, ">Annuler<") || strings.Contains(install, "ready-step") {
		t.Error("assistant CrowdSec contient encore du contenu secondaire")
	}
	if e.caddy.crowdsec != nil || e.caddy.last()[0].CrowdSec {
		t.Error("CrowdSec publié sans connexion")
	}

	// Refus : champs vides, adresse sans protocole, mauvaise clé, CrowdSec injoignable. Rien n'est enregistré.
	for name, f := range map[string]url.Values{
		"clé absente":    {"url": {lapi.URL}, "key": {""}},
		"sans protocole": {"url": {"crowdsec:8080"}, "key": {"cle-fictive"}},
		"mauvaise clé":   {"url": {lapi.URL}, "key": {"mauvaise"}},
		"injoignable":    {"url": {"http://127.0.0.1:1"}, "key": {"cle-fictive"}},
	} {
		resp, b := e.post("/security/crowdsec", f)
		if resp.StatusCode != 422 {
			t.Errorf("%s : %d", name, resp.StatusCode)
		}
		if name == "mauvaise clé" && !strings.Contains(b, "cscli bouncers add gatewyn") {
			t.Errorf("mauvaise clé : message sans la commande : %s", b)
		}
		if name == "injoignable" && !strings.Contains(b, "n&#39;arrive pas à joindre CrowdSec") {
			t.Errorf("injoignable : %s", b)
		}
	}
	if e.srv.crowdSecView(ctx, "127.0.0.1").Configured {
		t.Fatal("une connexion refusée a été enregistrée")
	}

	// Caddy refuse : retour à l'état d'avant.
	e.caddy.failNext = errors.New("refus")
	if resp, _ := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}}); resp.StatusCode != 502 {
		t.Errorf("refus de Caddy : %d", resp.StatusCode)
	}
	if v := e.srv.crowdSecView(ctx, "127.0.0.1"); v.Enabled {
		t.Errorf("connexion gardée malgré le refus de Caddy : %+v", v)
	}

	// Connexion réussie : publiée dans Caddy, tous les hôtes protégés, clé chiffrée en base.
	resp, _ := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}})
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/security/protection?csconnected") {
		t.Fatalf("connexion : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.caddy.crowdsec == nil || e.caddy.crowdsec.URL != lapi.URL || e.caddy.crowdsec.Key != "cle-fictive" || !e.caddy.last()[0].CrowdSec {
		t.Errorf("publication : %+v %+v", e.caddy.crowdsec, e.caddy.last())
	}
	if stored, _ := e.srv.cfg.Store.Setting(ctx, settingCSKey); stored == "" || strings.Contains(stored, "cle-fictive") {
		t.Errorf("clé stockée : %q", stored)
	}
	// Un hôte créé ensuite est protégé aussi.
	e.post("/hosts", url.Values{"domain": {"blog.example.com"}, "target": {"192.0.2.22:8080"}})
	for _, h := range e.caddy.last() {
		if !h.CrowdSec {
			t.Errorf("hôte non protégé : %+v", h)
		}
	}

	// La page Sécurité charge un diagnostic compact, sans exposer la liste brute des décisions.
	_, body = e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, `hx-get="/security/crowdsec/status"`) || !strings.Contains(body, "Désactiver") || strings.Contains(body, "cle-fictive") {
		t.Error("carte CrowdSec connecté : contenu inattendu")
	}
	for _, want := range []string{`class="nav on"`, `id="listes"`, "Protection CrowdSec"} {
		if !strings.Contains(body, want) {
			t.Errorf("organisation Sécurité sans %q", want)
		}
	}
	// Les anciennes adresses renvoient vers les sections de la page Sécurité.
	for path, to := range map[string]string{"/security/access": "/security/protection#listes", "/security/proxies": "/security/protection#proxies"} {
		if resp, _ := e.do("GET", path, nil); resp.StatusCode != 303 || resp.Header.Get("Location") != to {
			t.Errorf("%s : %d %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	e.caddy.csStatus = caddyadmin.CrowdSecStatus{Healthy: true, Streaming: true, Interval: "10s", Decisions: 2}
	_, frag := e.do("GET", "/security/crowdsec/status", nil)
	for _, want := range []string{`class="status-grid"`, "Décisions actives", ">2</strong>"} {
		if !strings.Contains(frag, want) {
			t.Errorf("organisation CrowdSec sans %q", want)
		}
	}
	for _, w := range []string{"Connecté", "Blocage actif", "Mode flux · liste mise à jour toutes les 10 s"} {
		if !strings.Contains(frag, w) {
			t.Errorf("état sans %q", w)
		}
	}
	if strings.Contains(frag, "<html") || strings.Contains(frag, "Débannir") || strings.Contains(frag, "192.0.2.99") || strings.Contains(frag, "<th>Adresse</th>") {
		t.Error("fragment complet, action d'écriture ou liste brute présente")
	}
	// Bouncer absent de Caddy, CrowdSec injoignable.
	e.caddy.csErr = errors.New("404")
	if _, f := e.do("GET", "/security/crowdsec/status", nil); !strings.Contains(f, "Le bouncer n&#39;est pas chargé dans Caddy") && !strings.Contains(f, "Le bouncer n'est pas chargé dans Caddy") {
		t.Errorf("bouncer absent : %s", f)
	}
	e.caddy.csErr = nil
	lapi.Close()
	if _, f := e.do("GET", "/security/crowdsec/status", nil); !strings.Contains(f, "Injoignable") {
		t.Errorf("LAPI injoignable : %s", f)
	}

	// Désactiver retire le bouncer ; réactiver le remet. La connexion reste enregistrée.
	resp, _ = e.post("/security/crowdsec/disable", nil)
	if resp.Header.Get("HX-Redirect") != "/security/protection?csdisabled=1" || e.caddy.crowdsec != nil || e.caddy.last()[0].CrowdSec {
		t.Errorf("désactivation : %q %+v", resp.Header.Get("HX-Redirect"), e.caddy.crowdsec)
	}
	if _, b := e.do("GET", "/security/protection", nil); !strings.Contains(b, "Réactiver") {
		t.Error("bouton Réactiver absent")
	}
	resp, _ = e.post("/security/crowdsec/enable", nil)
	if resp.Header.Get("HX-Redirect") != "/security/protection?csenabled=1" || e.caddy.crowdsec == nil {
		t.Errorf("réactivation : %q %+v", resp.Header.Get("HX-Redirect"), e.caddy.crowdsec)
	}
	if _, b := e.do("GET", "/security/protection", nil); !strings.Contains(b, ">Supprimer</button>") || !strings.Contains(b, "Le conteneur CrowdSec et ses données seront conservés") || strings.Contains(b, "Retirer de Gatewyn") || strings.Contains(b, "Revenir à l&#39;état initial") {
		t.Error("action Supprimer absente, ambiguë ou encore dupliquée en bas de page")
	}

	// Le retrait est transactionnel : si Caddy refuse, la connexion complète est restaurée.
	e.caddy.failNext = errors.New("refus")
	resp, _ = e.post("/security/crowdsec/remove", nil)
	if resp.Header.Get("HX-Redirect") != "" || e.caddy.crowdsec == nil {
		t.Error("retrait CrowdSec non restauré après refus de Caddy")
	}
	if c, err := e.srv.loadCrowdSec(ctx); err != nil || c.URL == "" || c.Key != "cle-fictive" || !c.Enabled {
		t.Errorf("connexion non restaurée après refus : %+v, %v", c, err)
	}

	// Une réussite efface la clé et revient exactement à l'état de première installation.
	resp, _ = e.post("/security/crowdsec/remove", nil)
	if resp.Header.Get("HX-Redirect") != "/security/protection?csremoved=1" || e.caddy.crowdsec != nil || e.caddy.last()[0].CrowdSec {
		t.Errorf("retrait CrowdSec : %q %+v", resp.Header.Get("HX-Redirect"), e.caddy.crowdsec)
	}
	if c, err := e.srv.loadCrowdSec(ctx); err != nil || c.URL != "" || c.Key != "" || c.Enabled || c.AppSecURL != "" {
		t.Errorf("connexion CrowdSec encore présente : %+v, %v", c, err)
	}
	if _, b := e.do("GET", "/security/protection?csremoved=1", nil); !strings.Contains(b, "Installer CrowdSec") || strings.Contains(b, `id="configuration"`) {
		t.Error("la page ne revient pas à l'état initial après retrait")
	}
}

func TestCrowdSecComposeShowsWebUILink(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	if err := e.srv.saveCrowdSec(ctx, csConfig{URL: defaultCrowdSecURL, Key: "cle-fictive", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, body := e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, `href="http://127.0.0.1:8090" target="_blank" rel="noopener"`) || !strings.Contains(body, ">Interface ↗</a>") || strings.Contains(body, "Ouvrir l'interface") {
		t.Error("lien vers l'interface CrowdSec absent")
	}
	_, settings := e.do("GET", "/settings", nil)
	if !strings.Contains(settings, `name="crowdsec_ui_url" value="http://127.0.0.1:8090"`) || !strings.Contains(settings, "Publier en HTTPS") || !strings.Contains(settings, `href="/settings" class="nav on"`) {
		t.Error("lien de l'interface absent des réglages")
	}
	if resp, _ := e.post("/settings", url.Values{"crowdsec_ui_url": {"https://crowdsec.example.com"}}); resp.StatusCode != 303 {
		t.Fatalf("enregistrement du lien : %d", resp.StatusCode)
	}
	_, body = e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, `href="https://crowdsec.example.com" target="_blank" rel="noopener"`) {
		t.Error("lien HTTPS non appliqué")
	}
	if resp, b := e.post("/settings", url.Values{"crowdsec_ui_url": {"javascript:alert(1)"}}); resp.StatusCode != 422 || !strings.Contains(b, "adresse HTTP ou HTTPS complète") {
		t.Errorf("lien invalide accepté : %d", resp.StatusCode)
	}
	e.post("/settings", url.Values{"crowdsec_ui_url": {""}})
	_, body = e.do("GET", "/security/protection", nil)
	if strings.Contains(body, ">Interface ↗</a>") {
		t.Error("bouton encore affiché après suppression du lien")
	}
	_, hostForm := e.do("GET", "/hosts/new?target=http%3A%2F%2Fcrowdsec-web-ui%3A3000", nil)
	if !strings.Contains(hostForm, `name="target" value="http://crowdsec-web-ui:3000"`) {
		t.Error("cible de l'interface non préremplie")
	}
}

func TestCrowdSecEditKeepsKeyWhenLeftEmpty(t *testing.T) {
	e := newEnv(t)
	e.setup()
	lapi := fakeLAPI(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}})
	_, body := e.do("GET", "/security/crowdsec", nil)
	if !strings.Contains(body, "Inchangée") || strings.Contains(body, "cle-fictive") || !strings.Contains(body, lapi.URL) {
		t.Error("page de connexion : clé réaffichée ou adresse absente")
	}
	// Clé laissée vide : l'ancienne est réutilisée (la fausse LAPI n'accepte qu'elle).
	if resp, _ := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {""}}); resp.StatusCode != 303 {
		t.Errorf("clé laissée vide : %d", resp.StatusCode)
	}
	if e.caddy.crowdsec == nil || e.caddy.crowdsec.Key != "cle-fictive" {
		t.Errorf("clé non conservée : %+v", e.caddy.crowdsec)
	}
}

func TestHostOptionsPunycodeAndStrip(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()

	// Un nouvel hôte a la compression cochée ; le bloc Avancé propose les autres options.
	_, body := e.do("GET", "/hosts/new", nil)
	for _, w := range []string{`name="compress" value="1" checked`, `name="no_buffering"`, `name="noindex"`, `name="frame"`, "Seulement depuis ce même domaine", "h2c://hôte:port"} {
		if !strings.Contains(body, w) {
			t.Errorf("formulaire sans %q", w)
		}
	}
	if _, b := e.do("GET", "/hosts/new?kind=404", nil); strings.Contains(b, `name="compress"`) || !strings.Contains(b, `name="noindex"`) {
		t.Error("options d'une erreur 404 : compression absente attendue, noindex présent attendu")
	}

	// Nom accentué converti, options enregistrées et publiées, chemin retiré, cible h2c.
	resp, _ := e.post("/hosts", url.Values{"domain": {"Café.example.com"}, "target": {"h2c://192.0.2.5:50051"},
		"compress": {"1"}, "no_buffering": {"1"}, "noindex": {"1"}, "frame": {"SAMEORIGIN"},
		"loc_path": {"/api"}, "loc_target": {"192.0.2.6:3000"}, "loc_access": {"0"}, "loc_strip": {"1"}})
	if resp.StatusCode != 303 {
		t.Fatalf("création : %d", resp.StatusCode)
	}
	got := e.caddy.last()
	if len(got) != 1 || got[0].Domain != "xn--caf-dma.example.com" || got[0].Target != "h2c://192.0.2.5:50051" ||
		!got[0].Compress || !got[0].NoBuffering || !got[0].NoIndex || got[0].FrameOptions != "SAMEORIGIN" ||
		len(got[0].Locations) != 1 || !got[0].Locations[0].StripPath {
		t.Fatalf("publication : %+v", got)
	}
	// Un joker accentué et une valeur de cadre inconnue.
	e.post("/hosts", url.Values{"domain": {"*.Été.example.org"}, "target": {"192.0.2.7:80"}, "frame": {"ALLOWALL"}})
	for _, h := range e.caddy.last() {
		if h.Domain == "*.xn--t-9la.example.org" && h.FrameOptions != "" {
			t.Errorf("cadre inconnu publié : %q", h.FrameOptions)
		}
	}

	// Modifier : les options sont réaffichées ; décocher la compression l'enlève.
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	var id int64
	for _, h := range hosts {
		if h.Domain == "xn--caf-dma.example.com" {
			id = h.ID
		}
	}
	_, body = e.do("GET", "/hosts/"+itoa(id)+"/edit", nil)
	for _, w := range []string{`name="compress" value="1" checked`, `name="no_buffering" value="1" checked`, `name="noindex" value="1" checked`, `value="SAMEORIGIN" selected`, `value="1" selected>Préfixe retiré`} {
		if !strings.Contains(body, w) {
			t.Errorf("page Modifier sans %q", w)
		}
	}
	e.post("/hosts/"+itoa(id), url.Values{"domain": {"xn--caf-dma.example.com"}, "target": {"h2c://192.0.2.5:50051"}})
	for _, h := range e.caddy.last() {
		if h.Domain == "xn--caf-dma.example.com" && (h.Compress || h.NoBuffering || h.NoIndex || h.FrameOptions != "" || len(h.Locations) != 0) {
			t.Errorf("options non retirées : %+v", h)
		}
	}

	// L'aperçu montre les options.
	_, prev := e.do("POST", "/hosts/check/preview", url.Values{"domain": {"wiki.example.com"}, "target": {"h2c://192.0.2.5:50051"},
		"compress": {"1"}, "no_buffering": {"1"}, "noindex": {"1"}, "frame": {"DENY"}, "loc_path": {"/api"}, "loc_target": {"192.0.2.6:3000"}, "loc_access": {"0"}, "loc_strip": {"1"}})
	for _, w := range []string{"encode zstd gzip", "header X-Frame-Options &#34;DENY&#34;", "header X-Robots-Tag &#34;noindex&#34;", "flush_interval -1", "reverse_proxy h2c://192.0.2.5:50051", "uri strip_prefix /api"} {
		if !strings.Contains(prev, w) {
			t.Errorf("aperçu sans %q : %s", w, prev)
		}
	}
}

func TestTrustedProxiesSetting(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})

	_, body := e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "Proxies de confiance") || len(e.caddy.global.TrustedProxies) != 0 {
		t.Error("carte absente ou proxies publiés sans réglage")
	}
	// Saisie invalide : refusée, rien n'est enregistré.
	resp, b := e.post("/security/proxies", url.Values{"proxies": {"173.245.48.0/20\ncloudflare.com"}})
	if resp.StatusCode != 422 || !strings.Contains(b, "cloudflare.com") || !strings.Contains(b, "173.245.48.0/20") {
		t.Errorf("saisie invalide : %d", resp.StatusCode)
	}
	if v, _ := e.srv.cfg.Store.Setting(ctx, settingTrustedProxies); v != "" {
		t.Errorf("enregistré malgré l'erreur : %q", v)
	}
	// Caddy refuse : retour à l'état d'avant.
	e.caddy.failNext = errors.New("refus")
	if resp, _ := e.post("/security/proxies", url.Values{"proxies": {"192.0.2.7"}}); resp.StatusCode != 422 {
		t.Errorf("refus de Caddy : %d", resp.StatusCode)
	}
	if v, _ := e.srv.cfg.Store.Setting(ctx, settingTrustedProxies); v != "" {
		t.Errorf("enregistré malgré le refus de Caddy : %q", v)
	}

	// Enregistré (plage normalisée), publié dans Caddy, réaffiché.
	resp, _ = e.post("/security/proxies", url.Values{"proxies": {"173.245.48.9/20, 192.0.2.7"}})
	if resp.StatusCode != 303 || strings.Join(e.caddy.global.TrustedProxies, " ") != "173.245.48.0/20 192.0.2.7" {
		t.Fatalf("enregistrement : %d %v", resp.StatusCode, e.caddy.global.TrustedProxies)
	}
	_, body = e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "173.245.48.0/20\n192.0.2.7") {
		t.Error("proxies non réaffichés")
	}
	// Vider la saisie retire les proxies de confiance.
	e.post("/security/proxies", url.Values{"proxies": {"  "}})
	if len(e.caddy.global.TrustedProxies) != 0 {
		t.Errorf("proxies non retirés : %v", e.caddy.global.TrustedProxies)
	}
}

func fakeAppSec(t *testing.T, key string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Crowdsec-Appsec-Api-Key") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"action":"allow","http_status":200}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAppSecConnectionAndPerHostWAF(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	lapi := fakeLAPI(t, "cle-fictive")
	appsec := fakeAppSec(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "waf": {"1"}}) // sans CrowdSec : réglage retenu mais sans effet

	// Sans AppSec connecté : pas d'interrupteur WAF, et le réglage de l'hôte ne part pas vers Caddy.
	_, body := e.do("GET", "/hosts/new", nil)
	if strings.Contains(body, `name="waf"`) {
		t.Error("interrupteur WAF affiché sans AppSec")
	}
	if e.caddy.last()[0].WAF {
		t.Error("WAF publié sans AppSec")
	}

	// Le formulaire de connexion propose AppSec, « laisser passer » est coché par défaut.
	_, body = e.do("GET", "/security/crowdsec", nil)
	if !strings.Contains(body, `name="appsec_url"`) || !strings.Contains(body, `name="appsec_failopen" value="1" checked`) || strings.Contains(body, "Paramètres avancés") || strings.Contains(body, "Ce que fait la connexion") {
		t.Error("formulaire sans les champs AppSec")
	}
	// En venant de l'assistant Gatewyn, l'adresse AppSec du compose est préremplie.
	_, guided := e.do("GET", "/security/crowdsec?appsec=1", nil)
	if !strings.Contains(guided, `action="/security/crowdsec?appsec=1"`) || !strings.Contains(guided, `name="url" value="http://crowdsec:8080"`) || !strings.Contains(guided, `name="appsec_url" value="http://crowdsec:7422"`) || !strings.Contains(guided, `name="key" type="password"`) || strings.Contains(guided, "AppSec avec le compose Gatewyn") || strings.Contains(guided, "Ce que fait la connexion") {
		t.Error("adresse AppSec non préremplie depuis l'assistant")
	}
	// Refus : adresse sans protocole, mauvaise clé AppSec, AppSec injoignable.
	for name, appsecURL := range map[string]string{"sans protocole": "crowdsec:7422", "injoignable": "http://127.0.0.1:1"} {
		resp, b := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}, "appsec_url": {appsecURL}})
		if resp.StatusCode != 422 {
			t.Errorf("%s : %d", name, resp.StatusCode)
		}
		if name == "injoignable" && !strings.Contains(b, "Vérifiez que le composant AppSec est activé") {
			t.Errorf("injoignable : %s", b)
		}
	}
	bad := fakeAppSec(t, "autre-cle")
	if resp, b := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}, "appsec_url": {bad.URL}}); resp.StatusCode != 422 || !strings.Contains(b, "AppSec a refusé la clé") {
		t.Errorf("mauvaise clé AppSec : %d", resp.StatusCode)
	}
	if e.srv.crowdSecView(ctx, "127.0.0.1").Configured {
		t.Fatal("une connexion refusée a été enregistrée")
	}

	// Connexion avec AppSec : publiée avec l'adresse et le mode « laisser passer ».
	resp, _ := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}, "appsec_url": {appsec.URL}, "appsec_failopen": {"1"}})
	if resp.StatusCode != 303 {
		t.Fatalf("connexion : %d", resp.StatusCode)
	}
	if cs := e.caddy.crowdsec; cs == nil || cs.AppSecURL != appsec.URL || !cs.AppSecFailOpen {
		t.Fatalf("publication : %+v", cs)
	}
	// Le réglage de l'hôte (enregistré plus tôt) prend effet ; le formulaire propose l'interrupteur.
	if !e.caddy.last()[0].WAF {
		t.Error("WAF de l'hôte non publié une fois AppSec connecté")
	}
	_, body = e.do("GET", "/hosts/new", nil)
	if !strings.Contains(body, `name="waf"`) || !strings.Contains(body, "WAF (CrowdSec AppSec)") {
		t.Error("interrupteur WAF absent avec AppSec connecté")
	}
	// Éteindre le WAF d'un hôte seulement.
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	e.post("/hosts/"+itoa(hosts[0].ID), url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	if e.caddy.last()[0].WAF {
		t.Error("WAF non retiré pour l'hôte")
	}
	e.post("/hosts", url.Values{"domain": {"blog.example.com"}, "target": {"192.0.2.22:8080"}, "waf": {"1"}})
	var onFor []string
	for _, h := range e.caddy.last() {
		if h.WAF {
			onFor = append(onFor, h.Domain)
		}
	}
	if strings.Join(onFor, " ") != "blog.example.com" {
		t.Errorf("WAF publié pour : %v", onFor)
	}

	// La page d'état montre le WAF ; AppSec qui tombe se voit.
	e.caddy.csStatus = caddyadmin.CrowdSecStatus{Healthy: true, Streaming: true, Interval: "10s"}
	_, frag := e.do("GET", "/security/crowdsec/status", nil)
	for _, w := range []string{"AppSec", "Actif", "les requêtes passent si AppSec tombe"} {
		if !strings.Contains(frag, w) {
			t.Errorf("état sans %q", w)
		}
	}
	appsec.Close()
	if _, f := e.do("GET", "/security/crowdsec/status", nil); !strings.Contains(f, "n&#39;arrive pas à joindre AppSec") {
		t.Errorf("AppSec injoignable : %s", f)
	}

	// Mode « refuser » : décocher la case est publié.
	e.srv.cfg.CrowdSecClient = lapi.Client()
	appsec2 := fakeAppSec(t, "cle-fictive")
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {""}, "appsec_url": {appsec2.URL}})
	if cs := e.caddy.crowdsec; cs == nil || cs.AppSecFailOpen {
		t.Errorf("mode refus non publié : %+v", cs)
	}
}

func TestWAFStatsAreShownFromCrowdSecMetrics(t *testing.T) {
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`cs_appsec_reqs_total{appsec_engine="x",source="10.0.0.2"} 28
cs_appsec_block_total{appsec_engine="x",source="10.0.0.2"} 17
cs_appsec_rule_hits{appsec_engine="x",rule_name="crowdsecurity/vpatch-env-access",source="10.0.0.2",type="inband"} 15
cs_appsec_rule_hits{appsec_engine="x",rule_name="crowdsecurity/vpatch-CVE-2024-1234",source="10.0.0.2",type="inband"} 2
`))
	}))
	defer metrics.Close()
	e := newEnv(t)
	e.setup()
	lapi := fakeLAPI(t, "cle-fictive")
	appsec := fakeAppSec(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.srv.cfg.CrowdSecMetricsURL = metrics.URL
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}, "appsec_url": {appsec.URL}, "appsec_failopen": {"1"}})
	e.caddy.csStatus = caddyadmin.CrowdSecStatus{Healthy: true, Streaming: true, Interval: "10s"}

	_, frag := e.do("GET", "/security/crowdsec/status", nil)
	for _, w := range []string{"Requêtes examinées", ">28</strong>", "Requêtes bloquées", ">17</strong>", "Règles déclenchées", "Accès à un fichier .env", "crowdsecurity/vpatch-env-access", ">15<", "Faille connue (CVE-2024-1234)", "depuis le dernier démarrage"} {
		if !strings.Contains(frag, w) {
			t.Errorf("état sans %q", w)
		}
	}
	// Métriques injoignables : message discret, le reste de l'état est intact.
	metrics.Close()
	_, frag = e.do("GET", "/security/crowdsec/status", nil)
	if !strings.Contains(frag, "compteurs du WAF ne sont pas joignables") || strings.Contains(frag, "Règles du WAF déclenchées") || !strings.Contains(frag, "Actif") {
		t.Errorf("métriques injoignables : %s", frag)
	}
	// Sans AppSec, ni carte ni compteurs.
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {""}})
	if _, f := e.do("GET", "/security/crowdsec/status", nil); strings.Contains(f, "WAF") {
		t.Error("WAF affiché sans AppSec")
	}
}

func TestAccessLogSetting(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})

	// Activé par défaut pour 30 jours, publié sans réglage.
	_, body := e.do("GET", "/settings", nil)
	if !strings.Contains(body, "Journal d'accès") || !strings.Contains(body, `name="accesslog" value="1" checked`) || !strings.Contains(body, `<option value="30" selected>30 jours</option>`) {
		t.Error("réglage absent, désactivé par défaut ou 30 jours non préselectionné")
	}
	if al := e.caddy.global.AccessLog; al == nil || al.KeepDays != 30 {
		t.Errorf("journal non publié par défaut : %+v", al)
	}

	// Désactivé à la main : retiré de Caddy, et ça reste désactivé.
	if resp, _ := e.post("/settings", url.Values{}); resp.StatusCode != 303 {
		t.Fatalf("désactivation : %d", resp.StatusCode)
	}
	if e.caddy.global.AccessLog != nil {
		t.Errorf("journal publié malgré la désactivation : %+v", e.caddy.global.AccessLog)
	}
	if d, _ := e.srv.accessLogDays(ctx); d != 0 {
		t.Errorf("désactivation oubliée : %d", d)
	}

	// Activé pour 90 jours : publié avec le fichier configuré.
	resp, _ := e.post("/settings", url.Values{"accesslog": {"1"}, "accesslog_days": {"90"}})
	if resp.StatusCode != 303 {
		t.Fatalf("enregistrement : %d", resp.StatusCode)
	}
	if al := e.caddy.global.AccessLog; al == nil || al.File != "/data/logs/access.log" || al.KeepDays != 90 {
		t.Fatalf("journal publié : %+v", al)
	}
	_, body = e.do("GET", "/settings", nil)
	if !strings.Contains(body, `name="accesslog" value="1" checked`) || !strings.Contains(body, `<option value="90" selected>90 jours</option>`) {
		t.Error("réglage non réaffiché")
	}

	// Durée hors liste : ignorée (la durée déjà enregistrée est gardée), jamais enregistrée telle quelle.
	e.post("/settings", url.Values{"accesslog": {"1"}, "accesslog_days": {"9999"}})
	if al := e.caddy.global.AccessLog; al == nil || al.KeepDays != 90 {
		t.Errorf("durée invalide : %+v", al)
	}

	// Caddy refuse : retour à l'état d'avant.
	e.caddy.failNext = errors.New("refus")
	if resp, _ := e.post("/settings", url.Values{"accesslog": {"1"}, "accesslog_days": {"7"}}); resp.StatusCode != 422 {
		t.Errorf("refus de Caddy : %d", resp.StatusCode)
	}
	if d, _ := e.srv.accessLogDays(ctx); d != 90 {
		t.Errorf("enregistré malgré le refus de Caddy : %d", d)
	}

	// Décoché : le journal est retiré.
	e.post("/settings", url.Values{"accesslog_days": {"30"}})
	if e.caddy.global.AccessLog != nil {
		t.Errorf("journal encore publié : %+v", e.caddy.global.AccessLog)
	}
}

func TestStatsPageWithoutAndWithGoAccess(t *testing.T) {
	e := newEnv(t)
	e.setup()
	file := filepath.Join(t.TempDir(), "access.log")
	e.srv.cfg.AccessLogFile = file
	line := func(ts int, ip, uri string, status int) string {
		return fmt.Sprintf(`{"level":"info","ts":%d,"logger":"http.log.access.gatewyn_access","request":{"client_ip":%q,"host":"wiki.example.com","method":"GET","uri":%q},"status":%d}`, ts, ip, uri, status)
	}
	os.WriteFile(file, []byte(line(1793743000, "192.0.2.10", "/ancienne", 200)+"\n"+line(1793743100, "192.0.2.10", "/absente", 404)+"\nligne coupée {\n"+line(1793743200, "198.51.100.7", "/erreur", 502)+"\n"), 0o600)
	e.srv.cfg.GoAccessURL = "http://127.0.0.1:1" // personne n'écoute

	// Journal désactivé à la main : on l'explique, rien n'est lu même si le fichier existe.
	if err := e.srv.saveAccessLog(context.Background(), false, 0); err != nil {
		t.Fatal(err)
	}
	_, body := e.do("GET", "/stats", nil)
	if !strings.Contains(body, "Le journal d'accès est désactivé") || !strings.Contains(body, `action="/stats/journal"`) || !strings.Contains(body, `href="/settings"`) || strings.Contains(body, "198.51.100.7") || strings.Contains(body, "Dernières requêtes") {
		t.Errorf("journal désactivé : %s", body)
	}
	if _, b := e.do("GET", "/hosts", nil); !strings.Contains(b, "Trafic</span>") {
		t.Error("entrée « Trafic » absente du menu")
	}

	// Activé, sans GoAccess : résumé, dernières requêtes (la plus récente d'abord), invitation à l'installer.
	e.post("/settings", url.Values{"goaccess_report_url": {"http://127.0.0.1:8091"}, "accesslog": {"1"}, "accesslog_days": {"30"}})
	_, body = e.do("GET", "/stats", nil)
	for _, w := range []string{"<span>Requêtes</span><strong>3</strong>", "<span>Visiteurs</span><strong>2</strong>", "<span>Erreurs</span><strong>2</strong>",
		"Dernières requêtes", "198.51.100.7", `<span class="pill err">502</span>`, `<span class="pill warn">404</span>`, "Installer GoAccess", `href="/stats/install"`} {
		if !strings.Contains(body, w) {
			t.Errorf("page sans %q", w)
		}
	}
	if strings.Contains(body, "Ouvrir le rapport") || strings.Index(body, "/erreur") > strings.Index(body, "/ancienne") {
		t.Error("rapport proposé sans GoAccess, ou requêtes mal triées")
	}
	if _, b := e.do("GET", "/stats/install", nil); !strings.Contains(b, "COMPOSE_PROFILES=stats") || strings.Contains(b, "docker compose") || !strings.Contains(b, "fichier <code>.env</code>") || !strings.Contains(b, "Journal d'accès activé · 30 jours") || !strings.Contains(b, `href="/settings"`) {
		t.Errorf("page d'installation incomplète : %s", b)
	}

	// En marche : le bouton ouvre le rapport local par défaut ; plus de carte d'installation.
	ga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("rapport")) }))
	defer ga.Close()
	e.srv.cfg.GoAccessURL = ga.URL
	_, body = e.do("GET", "/stats", nil)
	if strings.Contains(body, "Installer GoAccess") || !strings.Contains(body, `href="http://127.0.0.1:8091"`) || !strings.Contains(body, "Ouvrir le rapport") {
		t.Errorf("GoAccess en marche : %s", body)
	}

	// L'adresse du rapport est un réglage, comme l'interface CrowdSec ; « Publier en HTTPS » est dans Réglages.
	_, body = e.do("GET", "/settings", nil)
	if !strings.Contains(body, `name="goaccess_report_url" value="http://127.0.0.1:8091"`) || !strings.Contains(body, "/hosts/new?target="+url.QueryEscape(ga.URL)) {
		t.Errorf("réglage du rapport : %s", body)
	}
	if resp, b := e.post("/settings", url.Values{"goaccess_report_url": {"stats.example.com"}}); resp.StatusCode != 422 || !strings.Contains(b, "adresse HTTP ou HTTPS complète") {
		t.Errorf("adresse invalide : %d", resp.StatusCode)
	}
	e.post("/settings", url.Values{"goaccess_report_url": {"https://stats.example.com"}, "accesslog": {"1"}, "accesslog_days": {"30"}})
	if _, b := e.do("GET", "/stats", nil); !strings.Contains(b, `href="https://stats.example.com"`) {
		t.Error("le bouton ne suit pas le réglage")
	}
	e.post("/settings", url.Values{"goaccess_report_url": {""}, "accesslog": {"1"}, "accesslog_days": {"30"}})
	if _, b := e.do("GET", "/stats", nil); strings.Contains(b, "Ouvrir le rapport") {
		t.Error("bouton affiché alors que l'adresse est vide")
	}

	// Journal activé mais vide : message explicite.
	os.WriteFile(file, nil, 0o600)
	if _, b := e.do("GET", "/stats", nil); !strings.Contains(b, "Aucune requête pour l'instant") {
		t.Error("message de journal vide absent")
	}
}

func TestStatsJournalOneClick(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}})
	e.srv.cfg.GoAccessURL = "http://127.0.0.1:1"
	if err := e.srv.saveAccessLog(ctx, false, 0); err != nil {
		t.Fatal(err)
	}

	// Étape 1 non faite : le bouton est proposé sur la page d'installation.
	if _, b := e.do("GET", "/stats/install", nil); !strings.Contains(b, "Journal d'accès désactivé") || !strings.Contains(b, `action="/stats/journal"`) {
		t.Errorf("bouton absent : %s", b)
	}
	// Un clic : activé pour 30 jours, publié, retour sur la page d'installation.
	resp, _ := e.post("/stats/journal", url.Values{"back": {"install"}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/stats/install" {
		t.Fatalf("activation : %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if al := e.caddy.global.AccessLog; al == nil || al.KeepDays != 30 {
		t.Fatalf("journal publié : %+v", al)
	}
	if _, b := e.do("GET", "/stats/install", nil); !strings.Contains(b, "Journal d'accès activé · 30 jours") || strings.Contains(b, `action="/stats/journal"`) {
		t.Error("étape 1 non cochée après activation")
	}

	// La durée choisie dans Réglages est gardée.
	e.post("/settings", url.Values{"goaccess_report_url": {"http://127.0.0.1:8091"}, "accesslog": {"1"}, "accesslog_days": {"90"}})
	e.post("/stats/journal", url.Values{})
	if d, _ := e.srv.accessLogDays(ctx); d != 90 {
		t.Errorf("durée écrasée : %d", d)
	}

	// Caddy refuse : rien n'est enregistré, l'erreur est affichée.
	e.post("/settings", url.Values{"goaccess_report_url": {"http://127.0.0.1:8091"}})
	e.caddy.failNext = errors.New("refus")
	resp, body := e.post("/stats/journal", url.Values{"back": {"install"}})
	if resp.StatusCode != 422 || !strings.Contains(body, "le réglage n&#39;a pas été enregistré") {
		t.Errorf("refus de Caddy : %d", resp.StatusCode)
	}
	if d, _ := e.srv.accessLogDays(ctx); d != 0 {
		t.Errorf("enregistré malgré le refus : %d", d)
	}
}

func TestCertificateFailuresFromCaddyLogsAreExplained(t *testing.T) {
	e := newEnv(t)
	e.setup()
	tr := acmelog.New()
	e.srv.cfg.CertFailures = tr
	logs := tr.Wrap(io.Discard)
	e.post("/hosts", url.Values{"domain": {"wiki.example.com", "docs.example.com"}, "target": {"192.0.2.21:8080"}})
	e.post("/hosts", url.Values{"domain": {"lan.example.com"}, "target": {"192.0.2.22:8080"}, "dns": {"internal"}})

	// Aucun échec connu : rien d'affiché.
	_, body := e.do("GET", "/hosts", nil)
	if strings.Contains(body, "Certificat non obtenu") {
		t.Error("échec affiché sans journal")
	}

	// Échec lu dans les journaux de Caddy : message clair sur la liste et dans « À surveiller »,
	// jamais le code brut de Let's Encrypt.
	fmt.Fprintln(logs, `{"level":"error","logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"wiki.example.com","error":"HTTP 400 urn:ietf:params:acme:error:unauthorized - Invalid response from http://wiki.example.com/x"}`)
	fmt.Fprintln(logs, `{"level":"error","logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"lan.example.com","error":"HTTP 400 urn:ietf:params:acme:error:unauthorized"}`)
	_, body = e.do("GET", "/hosts", nil)
	if strings.Count(body, "Certificat non obtenu") != 1 || !strings.Contains(body, "Let&#39;s Encrypt a joint un autre serveur") || strings.Contains(body, "urn:ietf") {
		t.Errorf("liste des hôtes : %s", body)
	}
	_, frag := e.do("GET", "/dashboard/online", nil)
	if !strings.Contains(frag, `<span class="pill err">Certificat</span>`) || !strings.Contains(frag, "<b>wiki.example.com</b> Let&#39;s Encrypt") || strings.Contains(frag, "lan.example.com") {
		t.Errorf("à surveiller : %s", frag)
	}

	// Un échec sur un alias compte pour l'hôte ; un certificat obtenu efface le problème.
	fmt.Fprintln(logs, `{"level":"info","logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"wiki.example.com"}`)
	fmt.Fprintln(logs, `{"level":"error","logger":"tls.renew","msg":"could not get certificate from issuer","identifier":"docs.example.com","error":"no valid A records found for docs.example.com"}`)
	_, body = e.do("GET", "/hosts", nil)
	if strings.Count(body, "Certificat non obtenu") != 1 || !strings.Contains(body, "ne trouve pas le domaine dans le DNS") {
		t.Errorf("alias : %s", body)
	}
	fmt.Fprintln(logs, `{"level":"info","logger":"tls.renew","msg":"certificate renewed successfully","identifier":"docs.example.com"}`)
	if _, body = e.do("GET", "/hosts", nil); strings.Contains(body, "Certificat non obtenu") {
		t.Error("problème encore affiché après un renouvellement réussi")
	}
}

// Avec « no-referrer », Chrome envoie « Origin: null » sur les formulaires en HTTP
// et la protection inter-sites les refuse : la politique doit rester same-origin.
func TestReferrerPolicyKeepsOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	securityHeaders(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin", got)
	}
}

// Les liens par défaut vers les applications du compose suivent l'adresse par laquelle
// on ouvre Gatewyn, pas 127.0.0.1 (l'interface est ouverte depuis un autre poste).
func TestPageHost(t *testing.T) {
	for host, want := range map[string]string{
		"192.168.1.250:8080": "192.168.1.250",
		"gw.example.com":     "gw.example.com",
		"[2001:db8::1]:8080": "[2001:db8::1]",
		"[2001:db8::1]":      "[2001:db8::1]",
	} {
		if got := pageHost(&http.Request{Host: host}); got != want {
			t.Errorf("pageHost(%q) = %q, want %q", host, got, want)
		}
	}
}

// La page Protection liste les services publiés et indique lesquels ont le WAF.
func TestSecurityPageListsProtectedSites(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	if err := e.srv.saveCrowdSec(ctx, csConfig{URL: defaultCrowdSecURL, Key: "cle-fictive", Enabled: true, AppSecURL: defaultAppSecURL}); err != nil {
		t.Fatal(err)
	}
	e.post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "waf": {"1"}})
	e.post("/hosts", url.Values{"domain": {"blog.example.com"}, "target": {"192.0.2.22:8080"}})
	e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"old.example.com"}, "target": {"https://new.example.org"}})
	_, body := e.do("GET", "/security/protection", nil)
	if !strings.Contains(body, "Sites protégés") || !strings.Contains(body, "wiki.example.com") || !strings.Contains(body, "blog.example.com") {
		t.Fatalf("services absents de la page : %s", body)
	}
	if strings.Contains(body, "old.example.com") {
		t.Error("une redirection ne doit pas figurer parmi les sites protégés")
	}
	if strings.Count(body, `<span class="pill ok">Actif</span>`) < 3 { // blocage ×2, WAF ×1 (le troisième service n'a pas le WAF)
		t.Error("indicateurs Actif manquants")
	}
}

// Enregistrer les Réglages (pour changer la langue, par exemple) ne doit pas figer les liens
// proposés par défaut : ils doivent continuer à suivre l'adresse par laquelle on ouvre Gatewyn.
func TestSettingsDoNotFreezeDefaultLinks(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	if err := e.srv.saveCrowdSec(ctx, csConfig{URL: defaultCrowdSecURL, Key: "cle-fictive", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, form := e.do("GET", "/settings", nil)
	if !strings.Contains(form, `name="crowdsec_ui_url" value="http://127.0.0.1:8090"`) {
		t.Fatalf("lien par défaut absent : %s", form)
	}
	// Le formulaire renvoie tel quel les liens par défaut, comme le fait le navigateur.
	if resp, _ := e.post("/settings", url.Values{"crowdsec_ui_url": {"http://127.0.0.1:8090"}, "goaccess_report_url": {"http://127.0.0.1:8091"}, "ui_language": {"en"}}); resp.StatusCode != 303 {
		t.Fatalf("enregistrement : %d", resp.StatusCode)
	}
	for key, name := range map[string]string{settingCSWebUI: "interface CrowdSec", settingGoAccessReport: "rapport GoAccess"} {
		if v, _ := e.srv.cfg.Store.Setting(ctx, key); v != "" {
			t.Errorf("%s : le lien par défaut a été figé (%q)", name, v)
		}
	}
	// Un lien choisi par la personne, lui, est bien conservé ; « effacer » masque le bouton.
	e.post("/settings", url.Values{"crowdsec_ui_url": {"https://crowdsec.example.com"}, "goaccess_report_url": {""}})
	if v, _ := e.srv.cfg.Store.Setting(ctx, settingCSWebUI); v != "https://crowdsec.example.com" {
		t.Errorf("lien choisi non conservé : %q", v)
	}
	if v, _ := e.srv.cfg.Store.Setting(ctx, settingGoAccessReport); v != "-" {
		t.Errorf("lien effacé non masqué : %q", v)
	}
}

// /healthz sert à la sonde de santé de l'image : 200 si la base et Caddy répondent, 503 sinon,
// sans authentification.
func TestHealthz(t *testing.T) {
	e := newEnv(t)
	if resp, body := e.do("GET", "/healthz", nil); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("en bonne santé : %d %q", resp.StatusCode, body)
	}
	e.caddy.down = true
	if resp, body := e.do("GET", "/healthz", nil); resp.StatusCode != 503 || !strings.Contains(body, "caddy unavailable") {
		t.Errorf("Caddy arrêté : %d %q", resp.StatusCode, body)
	}
}

// Avec le compose Gatewyn, CrowdSec crée lui-même la clé du bouncer dans un fichier : le formulaire
// ne la demande plus, et la connexion réussit sans saisie.
func TestCrowdSecKeyFoundAutomatically(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	lapi := fakeLAPI(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()

	// Sans fichier : la clé est demandée, comme avant.
	_, form := e.do("GET", "/security/crowdsec?appsec=1", nil)
	if strings.Contains(form, "rien à saisir") || !strings.Contains(form, "cscli bouncers add gatewyn") {
		t.Fatalf("clé non demandée sans fichier : %s", form)
	}
	if resp, _ := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}}); resp.StatusCode != 422 {
		t.Errorf("connexion sans clé ni fichier : %d", resp.StatusCode)
	}

	if _, b := e.do("GET", "/security/protection", nil); !strings.Contains(b, "Installer CrowdSec") || strings.Contains(b, "déjà déployé") {
		t.Error("sans fichier de clé, la page devrait proposer d'installer CrowdSec")
	}

	// Avec le fichier déposé par CrowdSec : rien à saisir.
	keyFile := filepath.Join(t.TempDir(), "key")
	os.WriteFile(keyFile, []byte("cle-fictive\n"), 0o644)
	e.srv.cfg.CrowdSecKeyFile = keyFile
	// CrowdSec est déjà déployé par le compose : la page propose de le connecter, pas de l'installer.
	if _, b := e.do("GET", "/security/protection", nil); strings.Contains(b, "Installer CrowdSec") || !strings.Contains(b, "déjà déployé avec Gatewyn") || !strings.Contains(b, `href="/security/crowdsec?appsec=1"`) {
		t.Errorf("CrowdSec déployé mais non connecté : %s", b)
	}
	_, form = e.do("GET", "/security/crowdsec?appsec=1", nil)
	if !strings.Contains(form, "rien à saisir") || strings.Contains(form, "cle-fictive") || strings.Contains(form, `type="password"`) {
		t.Fatalf("formulaire avec clé automatique : %s", form)
	}
	if resp, body := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {""}}); resp.StatusCode != 303 {
		t.Fatalf("connexion avec la clé du fichier : %d %s", resp.StatusCode, body)
	}
	if c, err := e.srv.loadCrowdSec(ctx); err != nil || c.Key != "cle-fictive" || !c.Enabled {
		t.Errorf("clé non enregistrée : %+v, %v", c, err)
	}

	// Une fois connecté, le formulaire redevient celui de la modification (clé inchangée si vide).
	_, form = e.do("GET", "/security/crowdsec", nil)
	if strings.Contains(form, "rien à saisir") || !strings.Contains(form, "Inchangée") {
		t.Error("formulaire de modification altéré")
	}
	// Un fichier à la clé mauvaise est refusé comme n'importe quelle clé.
	e.post("/security/crowdsec/remove", nil)
	os.WriteFile(keyFile, []byte("autre-cle"), 0o644)
	if resp, _ := e.post("/security/crowdsec", url.Values{"url": {lapi.URL}}); resp.StatusCode != 422 {
		t.Errorf("clé du fichier refusée par CrowdSec : %d", resp.StatusCode)
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t)
	e.setup()
	// Une seconde session, ouverte ailleurs : elle doit être fermée par le changement.
	other := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"username": {goodUsername}, "password": {goodPassword}}
	resp, err := other.PostForm(e.ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	otherCookie := resp.Cookies()[0]

	newPw := goodPassword + "-nouveau"
	for name, f := range map[string]url.Values{
		"ancien faux": {"current": {"faux"}, "password": {newPw}, "confirm": {newPw}},
		"trop court":  {"current": {goodPassword}, "password": {"court"}, "confirm": {"court"}},
		"différents":  {"current": {goodPassword}, "password": {newPw}, "confirm": {newPw + "x"}},
	} {
		if resp, _ := e.do("POST", "/settings/password", f); resp.StatusCode < 400 {
			t.Errorf("%s accepté : %d", name, resp.StatusCode)
		}
	}
	if resp, _ := e.do("POST", "/login", url.Values{"username": {goodUsername}, "password": {goodPassword}}); resp.StatusCode != 303 {
		t.Fatalf("l'ancien mot de passe a cessé de marcher après des refus : %d", resp.StatusCode)
	}

	resp, _ = e.do("POST", "/settings/password", url.Values{"current": {goodPassword}, "password": {newPw}, "confirm": {newPw}})
	if resp.StatusCode != 303 {
		t.Fatalf("changement : %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/", nil); resp.StatusCode != 200 {
		t.Errorf("la session courante doit rester ouverte : %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(otherCookie)
	r2, _ := other.Do(req)
	r2.Body.Close()
	if r2.StatusCode != 303 {
		t.Errorf("l'autre session doit être fermée : %d", r2.StatusCode)
	}
	e.do("POST", "/logout", url.Values{})
	if resp, _ := e.do("POST", "/login", url.Values{"username": {goodUsername}, "password": {goodPassword}}); resp.StatusCode != 401 {
		t.Errorf("l'ancien mot de passe marche encore : %d", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/login", url.Values{"username": {goodUsername}, "password": {newPw}}); resp.StatusCode != 303 {
		t.Errorf("le nouveau mot de passe ne marche pas : %d", resp.StatusCode)
	}
}

func TestChangePasswordRequiresLoginAndIsRateLimited(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for i := 0; i < 20; i++ {
		e.do("POST", "/settings/password", url.Values{"current": {"faux"}})
	}
	resp, _ := e.do("POST", "/settings/password", url.Values{"current": {goodPassword}, "password": {goodPassword + "x"}, "confirm": {goodPassword + "x"}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("pas de limitation des essais : %d", resp.StatusCode)
	}
	e.do("POST", "/logout", url.Values{})
	if resp, _ := e.do("POST", "/settings/password", url.Values{"current": {goodPassword}}); resp.StatusCode != 303 {
		t.Errorf("accessible sans connexion : %d", resp.StatusCode)
	}
}

func TestHostListShowsAccessAndSecurityTags(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	listID, err := e.store.AddAccessList(ctx, store.AccessList{Name: "Bureau", Addresses: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	e.store.AddHostFull(ctx, store.Host{Domain: "plain.example.com", Target: "http://192.0.2.1"})
	e.store.AddHostFull(ctx, store.Host{Domain: "full.example.com", Target: "http://192.0.2.2",
		AccessListID: listID, WAF: true, HSTS: 1, HTTPOnly: true, SelfSigned: true, Compress: true})
	e.store.AddHostFull(ctx, store.Host{Domain: "redir.example.com", Kind: "redirect", Target: "https://example.org", Code: 301, AccessListID: listID})

	_, body := e.do("GET", "/hosts", nil)
	rows := strings.Split(body, ` id="host-`)
	var plain, full string
	for _, r := range rows {
		switch {
		case strings.Contains(r, "plain.example.com"):
			plain = r
		case strings.Contains(r, "full.example.com"):
			full = r
		}
	}
	if strings.Contains(plain, `class="pill sm`) {
		t.Errorf("un hôte sans option ne doit montrer aucune pastille : %s", plain)
	}
	// La liste d'accès a sa propre colonne : pas de pastille en double.
	if !strings.Contains(full, "Bureau") || strings.Contains(full, "Liste d&#39;accès : Bureau") {
		t.Errorf("la liste d'accès se lit dans la colonne Accès : %s", full)
	}
	for _, want := range []string{"WAF", "HSTS", "HTTP seulement", "Certificat auto-signé"} {
		if !strings.Contains(full, want) {
			t.Errorf("pastille %q absente : %s", want, full)
		}
	}
	if strings.Contains(full, "Compression") {
		t.Error("les réglages de confort ne doivent pas apparaître")
	}
	_, redirs := e.do("GET", "/redirections", nil)
	if strings.Contains(redirs, `class="pill sm`) {
		t.Error("pas de pastilles sur les redirections")
	}
	_, en := e.do("GET", "/hosts", nil, "Accept-Language", "en")
	if !strings.Contains(en, "HTTP only") || !strings.Contains(en, "Self-signed certificate") {
		t.Errorf("traduction anglaise absente : %s", en)
	}
}

func TestDecisionsPageIsReadOnlyAndNeedsCrowdSec(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if resp, _ := e.do("GET", "/security/decisions", nil); resp.StatusCode != 303 || resp.Header.Get("Location") != "/security/protection" {
		t.Errorf("sans CrowdSec : %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	lapi := fakeLAPI(t, "cle-fictive")
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}})
	_, body := e.do("GET", "/security/decisions", nil)
	for _, want := range []string{"Adresses bloquées", "192.0.2.99", "crowdsecurity/http-probing", "198.51.100.0/24", "1 j 23 h", "3 h 41", "2 décisions actives", "lecture seule"} {
		if !strings.Contains(body, want) {
			t.Errorf("page des adresses bloquées sans %q : %s", want, body)
		}
	}
	for _, bad := range []string{"Débannir", "Bannir", "hx-post", `action="/security`, "cle-fictive"} {
		if strings.Contains(body, bad) {
			t.Errorf("la page est en lecture seule, elle contient %q", bad)
		}
	}
	// La page de protection y renvoie depuis la case « Décisions actives ».
	e.caddy.csStatus = caddyadmin.CrowdSecStatus{Healthy: true, Streaming: true, Interval: "10s", Decisions: 2}
	if _, frag := e.do("GET", "/security/crowdsec/status", nil); !strings.Contains(frag, `href="/security/decisions"`) {
		t.Error("lien vers la liste absent de la case Décisions actives")
	}
	if _, en := e.do("GET", "/security/decisions", nil, "Accept-Language", "en"); !strings.Contains(en, "Blocked addresses") || !strings.Contains(en, "read only") {
		t.Errorf("traduction anglaise absente : %s", en)
	}
}

func TestHostsHomeFiltersCountsAndCertificateColumn(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	e.store.AddHostFull(ctx, store.Host{Domain: "wiki.example.com", Target: "http://192.0.2.1"})
	e.store.AddHostFull(ctx, store.Host{Domain: "old.example.com", Kind: "redirect", Target: "https://example.org", Code: 301})
	e.store.AddHostFull(ctx, store.Host{Domain: "gone.example.com", Kind: "404"})
	offID, _ := e.store.AddHostFull(ctx, store.Host{Domain: "off.example.com", Target: "http://192.0.2.2"})
	e.store.SetHostDisabled(ctx, offID, true)

	_, all := e.do("GET", "/", nil)
	for _, want := range []string{"wiki.example.com", "old.example.com", "gone.example.com", "off.example.com", `class="chip on" href="/"`, `href="/hosts"`, `href="/redirections"`, `href="/erreurs-404"`, `id="watch-filter"`} {
		if !strings.Contains(all, want) {
			t.Errorf("accueil sans %q", want)
		}
	}
	// Compteurs des types : 4 hôtes, 2 services, 1 redirection, 1 page 404 (la recherche ne les change pas).
	for _, want := range []string{`Tous <span class="n">4</span>`, `Services <span class="n">2</span>`, `Redirections <span class="n">1</span>`, `Pages 404 <span class="n">1</span>`} {
		if !strings.Contains(all, want) {
			t.Errorf("compteur absent : %q", want)
		}
	}
	_, q := e.do("GET", "/?q=wiki", nil)
	if strings.Contains(q, "gone.example.com") || !strings.Contains(q, `Tous <span class="n">4</span>`) {
		t.Error("la recherche doit filtrer la liste sans changer les compteurs")
	}
	// Un hôte désactivé n'a pas de certificat à montrer.
	if !strings.Contains(all, `<span class="dot" title="Désactivé">`) {
		t.Error("point gris des hôtes désactivés absent")
	}
	// Un certificat lu sur le disque s'affiche dans la colonne HTTPS.
	e.srv.cfg.CertDir = t.TempDir()
	writeFakeCert(t, e.srv.cfg.CertDir, "wiki.example.com", e.srv.cfg.Now(), 62*24*time.Hour)
	if _, withCert := e.do("GET", "/", nil); !strings.Contains(withCert, "61 j") {
		t.Errorf("colonne HTTPS sans la durée restante : %s", withCert)
	}
}

func TestTrafficPageShowsRequestsPerHost(t *testing.T) {
	e := newEnv(t)
	e.setup()
	file := filepath.Join(t.TempDir(), "access.log")
	e.srv.cfg.AccessLogFile = file
	line := func(ts int, host string, status int) string {
		return fmt.Sprintf(`{"ts":%d,"status":%d,"request":{"client_ip":"192.0.2.10","host":%q,"method":"GET","uri":"/"}}`, ts, status, host)
	}
	os.WriteFile(file, []byte(line(1793743000, "wiki.example.com", 200)+"\n"+line(1793743001, "wiki.example.com", 200)+"\n"+line(1793743002, "wiki.example.com", 404)+"\n"+line(1793743003, "blog.example.com", 502)+"\n"), 0o600)
	_, body := e.do("GET", "/stats", nil)
	for _, want := range []string{"<h1>Trafic</h1>", "Par hôte", "wiki.example.com", "blog.example.com", `data-rfilter="err"`, `data-class="warn"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page Trafic sans %q", want)
		}
	}
	// wiki : 3 requêtes dont 1 erreur, en tête ; blog : 1 requête, 1 erreur.
	i, j := strings.Index(body, "<b>wiki.example.com</b>"), strings.Index(body, "<b>blog.example.com</b>")
	if i < 0 || j < 0 || i > j {
		t.Error("l'hôte le plus sollicité doit venir en premier")
	}
}

// writeFakeCert dépose dans dir un certificat fictif qui expire dans « left », comme Caddy le range.
func writeFakeCert(t *testing.T, dir, name string, now time.Time, left time.Duration) {
	t.Helper()
	d := filepath.Join(dir, "acme-v02.api.letsencrypt.org-directory", name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-100 * 24 * time.Hour), NotAfter: now.Add(left)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	os.WriteFile(filepath.Join(d, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func TestManyAlertsAreFoldedAfterTheFirstFour(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for i := 1; i <= 6; i++ {
		e.post("/hosts", url.Values{"domain": {fmt.Sprintf("h%d.example.com", i)}, "target": {fmt.Sprintf("192.0.2.%d:8080", i)}})
	}
	e.srv.cfg.CheckTarget = func(ctx context.Context, target string, _ bool) checks.Result {
		return checks.Result{Status: checks.Error}
	}
	_, frag := e.do("GET", "/dashboard/online", nil)
	if strings.Count(frag, `class="alert"`) != 6 || !strings.Contains(frag, `class="alerts-more"`) || !strings.Contains(frag, "2 autres alertes") {
		t.Errorf("les alertes en plus des quatre premières doivent se déplier : %s", frag)
	}
	if i, j := strings.Index(frag, "h4.example.com"), strings.Index(frag, `class="alerts-more"`); i < 0 || j < 0 || i > j {
		t.Error("les quatre premières alertes doivent rester visibles")
	}
	_, en := e.do("GET", "/dashboard/online", nil, "Accept-Language", "en")
	if !strings.Contains(en, "2 other alerts") {
		t.Errorf("traduction anglaise absente : %s", en)
	}
}

func TestHostPageShowsItsRequestsAndHelpsWhenTheServiceIsDown(t *testing.T) {
	e := newEnv(t)
	e.setup()
	id := e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	file := filepath.Join(t.TempDir(), "access.log")
	e.srv.cfg.AccessLogFile = file
	line := func(ts int, host, uri string, status int) string {
		return fmt.Sprintf(`{"ts":%d,"status":%d,"request":{"client_ip":"192.0.2.10","host":%q,"method":"GET","uri":%q}}`, ts, status, host, uri)
	}
	os.WriteFile(file, []byte(line(1793743000, "wiki.example.com", "/doku.php", 200)+"\n"+line(1793743001, "autre.example.com", "/pas-pour-wiki", 200)+"\n"+line(1793743002, "wiki.example.com", "/absente", 404)+"\n"), 0o600)

	_, body := e.do("GET", "/hosts/"+itoa(id)+"/edit", nil)
	if !strings.Contains(body, "/doku.php") || !strings.Contains(body, "/absente") || strings.Contains(body, "/pas-pour-wiki") {
		t.Errorf("la page doit montrer les requêtes de son hôte, et seulement les siennes : %s", body)
	}
	e.srv.cfg.CheckTarget = func(ctx context.Context, target string, _ bool) checks.Result {
		return checks.Result{Status: checks.Error, Message: "Connexion refusée."}
	}
	_, cell := e.do("GET", "/hosts/"+itoa(id)+"/status?cell=1", nil)
	for _, want := range []string{"Cible injoignable", "Connexion refusée.", `id="host-note" hx-swap-oob="innerHTML"`, "Relancer la vérification", `hx-target="#cell-response"`} {
		if !strings.Contains(cell, want) {
			t.Errorf("la case réponse sans %q : %s", want, cell)
		}
	}
	e.srv.cfg.CheckTarget = func(ctx context.Context, target string, _ bool) checks.Result {
		return checks.Result{Status: checks.OK}
	}
	if _, ok := e.do("GET", "/hosts/"+itoa(id)+"/status?cell=1", nil); strings.Contains(ok, "Relancer la vérification") {
		t.Error("pas de bouton quand le service répond")
	}
	// Hôte désactivé : un mot d'explication, pas de vérification du service.
	e.post("/hosts/"+itoa(id)+"/toggle", nil)
	_, off := e.do("GET", "/hosts/"+itoa(id)+"/edit", nil)
	if !strings.Contains(off, "Cet hôte est désactivé") || strings.Contains(off, `id="cell-response"`) || strings.Contains(off, "status?pill=1") {
		t.Errorf("hôte désactivé : %s", off)
	}
}

func TestEnglishHostsHomeHasNoMixedLanguage(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.addHost("wiki.example.com", "http://192.0.2.21:8080")
	_, en := e.do("GET", "/", nil, "Accept-Language", "en")
	for _, want := range []string{`placeholder="Domain, target…"`, "Needs attention", "404 pages", "Hosts"} {
		if !strings.Contains(en, want) {
			t.Errorf("accueil anglais sans %q", want)
		}
	}
	if strings.Contains(en, "cible") {
		t.Error("du français est resté mélangé à l'anglais (« cible »)")
	}
	// Page d'un hôte : la case Protection et la bande d'état sont traduites.
	hosts, _ := e.srv.cfg.Store.ListHosts(context.Background())
	_, edit := e.do("GET", "/hosts/"+itoa(hosts[0].ID)+"/edit", nil, "Accept-Language", "en")
	if !strings.Contains(edit, ">None<") || strings.Contains(edit, ">Aucune<") {
		t.Errorf("la case Protection doit être traduite : %s", edit)
	}
}

func TestExpiredCertOfHTTPOnlyHostIsNotAnAlert(t *testing.T) {
	e := newEnv(t)
	e.setup()
	dir := t.TempDir()
	e.srv.cfg.CertDir = dir
	writeFakeCert(t, dir, "ancien.example.com", e.srv.cfg.Now(), -30*24*time.Hour)
	e.post("/hosts", url.Values{"domain": {"ancien.example.com"}, "target": {"192.0.2.9:8080"}, "dns": {"http"}, "force": {"1"}})
	_, frag := e.do("GET", "/dashboard/online", nil)
	if strings.Contains(frag, "Expiré") || strings.Contains(frag, "ancien.example.com") {
		t.Errorf("un hôte repassé en HTTP ne doit pas alerter : %s", frag)
	}
	if _, body := e.do("GET", "/", nil); strings.Contains(body, "status-cell err") {
		t.Error("la tuile Certificats ne doit pas être rouge")
	}
}
