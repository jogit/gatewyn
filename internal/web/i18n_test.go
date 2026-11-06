package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/jogit/gatewyn/internal/acmelog"
	"github.com/jogit/gatewyn/internal/caddyadmin"
	"github.com/jogit/gatewyn/internal/i18n"
	"github.com/jogit/gatewyn/internal/store"
)

// Ces tests empêchent d'oublier une traduction : le français est la langue de référence, et tout
// texte de l'interface doit avoir son équivalent anglais (internal/i18n/en.go).

// neutral : textes de gabarit identiques en français et en anglais (noms propres, commandes,
// sigles, valeurs d'exemple). Ils n'ont pas besoin d'entrée dans le catalogue.
var neutral = map[string]bool{
	"OK": true, "Site": true, "WAF": true, "Caddy": true, "CrowdSec": true, "AppSec": true, "GoAccess": true, "Gatewyn": true, "TLS": true,
	"HTTPS": true, "HSTS": true, "DNS": true, "WAF (CrowdSec AppSec)": true, "Services": true,
	"Compression": true, "Protection": true, "Public": true, "Destination": true, "Type": true, "Applications": true,
	"Administration": true, "Interface ↗": true, "· Gatewyn": true, "cscli bouncers add gatewyn": true, ".env": true,
	"COMPOSE_PROFILES=crowdsec": true, "COMPOSE_PROFILES=stats": true, "COMPOSE_PROFILES=crowdsec,stats": true,
	"docker compose logs gatewyn":                             true,
	"docker compose exec crowdsec cscli bouncers add gatewyn": true, "old.example.com": true,
	"https://new.example.org": true, "wiki.example.com": true, "http://192.0.2.21:8080": true, "http://crowdsec:8080": true,
	"/admin": true, "Français": true, "English": true, "Interface": true,
}

// templateTexts relève le texte fixe des gabarits : ce qui est écrit entre les balises et les
// actions {{ }}, et les attributs lus par la personne.
func templateTexts(t *testing.T) (texts, attrs map[string]string) {
	t.Helper()
	texts, attrs = map[string]string{}, map[string]string{}
	files, _ := filepath.Glob("templates/*.html")
	if len(files) == 0 {
		t.Fatal("aucun gabarit trouvé")
	}
	action := regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	script := regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>`)
	tag := regexp.MustCompile(`<[^>]*>`)
	attr := regexp.MustCompile(`\b(placeholder|title|aria-label|alt|hx-confirm|data-l)="([^"]*)"`)
	letters := regexp.MustCompile(`[A-Za-zÀ-ÿ]{2}`)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		src := string(b)
		for _, m := range attr.FindAllStringSubmatch(src, -1) {
			v := strings.TrimSpace(action.ReplaceAllString(m[2], "%s"))
			if v != "" && letters.MatchString(v) {
				attrs[v] = f
			}
		}
		src = action.ReplaceAllString(src, "\x01")
		src = script.ReplaceAllString(src, "")
		src = tag.ReplaceAllString(src, "\x02")
		// Seuls les textes entre deux balises sont relevés ici : un texte collé à une valeur
		// variable ({{ }}) fait partie d'une phrase construite, vérifiée par le rendu des pages.
		delim := regexp.MustCompile("[\x01\x02]")
		cuts := delim.FindAllStringIndex(src, -1)
		prev := 0
		for i, c := range cuts {
			seg := src[prev:c[0]]
			leftTag := i == 0 || src[cuts[i-1][0]] == '\x02'
			rightTag := src[c[0]] == '\x02'
			prev = c[1]
			s := strings.Join(strings.Fields(seg), " ")
			if s != "" && letters.MatchString(s) && leftTag && rightTag {
				texts[s] = f
			}
		}
	}
	return texts, attrs
}

func TestEnglishCoversTemplateText(t *testing.T) {
	texts, attrs := templateTexts(t)
	var missing []string
	check := func(s, file string) {
		if neutral[s] || strings.HasPrefix(s, "{") {
			return
		}
		en := i18n.Text(s)
		if en == s || i18n.LooksFrench(en) {
			missing = append(missing, fmt.Sprintf("%s : %q → %q", filepath.Base(file), s, en))
		}
	}
	for s, f := range texts {
		check(s, f)
	}
	for s, f := range attrs {
		check(s, f)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d texte(s) de gabarit sans traduction anglaise :\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}

// goNotUI : littéraux Go qui ressemblent à du français mais ne sont jamais montrés à la personne
// (clés de journal, SQL, noms de modèles, messages d'erreur internes).
var goNotUI = map[string]string{
	// Préfixe d'une date (« le 03/11 23:05 ») : traduit par les entrées « le %d/%d %d:%d » du catalogue.
	// Une règle « le %s » serait trop large : elle changerait n'importe quel « le » restant.
	"le %s": "date, voir le catalogue",
}

var verbs = strings.NewReplacer("%s", "example", "%d", "3", "%q", `"example"`, "%w", "example", "%v", "example")

func TestEnglishCoversGoMessages(t *testing.T) {
	dirs := []string{".", "../checks", "../caddyconf", "../dnsprov", "../auth", "../caddyadmin", "../secrets", "../crowdsec"}
	var missing []string
	fset := token.NewFileSet()
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil || !i18n.LooksFrench(v) {
					return true
				}
				if _, skip := goNotUI[v]; skip {
					return true
				}
				sample := verbs.Replace(v)
				if en := i18n.Text(sample); en == sample || i18n.LooksFrench(en) {
					pos := fset.Position(lit.Pos())
					missing = append(missing, fmt.Sprintf("%s:%d : %q", filepath.ToSlash(pos.Filename), pos.Line, v))
				}
				return true
			})
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d message(s) Go sans traduction anglaise :\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}

// frenchIn renvoie les textes qui semblent encore français dans une page ou un fragment HTML.
func frenchIn(body string) []string {
	var found []string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			if p := n.Parent; p != nil && (p.Data == "script" || p.Data == "style" || p.Data == "pre" || p.Data == "textarea") {
				return
			}
			if s := strings.TrimSpace(n.Data); s != "" && i18n.LooksFrench(s) {
				found = append(found, s)
			}
		case html.ElementNode:
			if n.Data == "script" || n.Data == "style" || n.Data == "pre" || n.Data == "textarea" {
				return
			}
			for _, a := range n.Attr {
				switch a.Key {
				case "title", "placeholder", "aria-label", "alt", "hx-confirm", "data-l":
					if i18n.LooksFrench(a.Val) {
						found = append(found, a.Key+"="+a.Val)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return []string{"HTML illisible : " + err.Error()}
	}
	walk(doc)
	return found
}

func TestFrenchIsTheDefaultAndEnglishFollowsTheBrowser(t *testing.T) {
	for header, want := range map[string]string{
		"": "fr", "fr": "fr", "fr-FR,fr;q=0.9,en;q=0.8": "fr", "en-US,en;q=0.9": "en", "en": "en",
		"de-DE,de;q=0.9,en;q=0.5": "en", "de-DE,de;q=0.9": "en", "fr;q=0.3,en;q=0.9": "en", "en;q=0": "fr", "*": "en",
	} {
		if got := fromAcceptLanguage(header); got != want {
			t.Errorf("Accept-Language %q → %q, attendu %q", header, got, want)
		}
	}
}

// englishFixture prépare une installation riche : tous les types d'hôtes, des listes, un compte DNS,
// CrowdSec avec son WAF, des certificats, un journal d'accès, GoAccess, une vérification des versions
// et un échec de certificat. De quoi afficher chaque page avec du contenu.
func englishFixture(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.setup()
	ctx := context.Background()

	// Fournisseurs externes simulés.
	lapi := fakeLAPI(t, "cle-fictive")
	appsec := fakeAppSec(t, "cle-fictive")
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("cs_appsec_reqs_total{appsec_engine=\"x\",source=\"10.0.0.2\"} 28\ncs_appsec_block_total{appsec_engine=\"x\",source=\"10.0.0.2\"} 17\n" +
			"cs_appsec_rule_hits{appsec_engine=\"x\",rule_name=\"crowdsecurity/vpatch-env-access\",source=\"10.0.0.2\",type=\"inband\"} 15\n" +
			"cs_appsec_rule_hits{appsec_engine=\"x\",rule_name=\"crowdsecurity/vpatch-CVE-2024-1234\",source=\"10.0.0.2\",type=\"inband\"} 2\n" +
			"cs_info{version=\"v1.8.2-3d369d64\"} 0\n"))
	}))
	t.Cleanup(metrics.Close)
	goaccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version": "1.9.4"}`)) }))
	t.Cleanup(goaccess.Close)
	e.srv.cfg.CrowdSecClient = lapi.Client()
	e.srv.cfg.CrowdSecMetricsURL = metrics.URL
	e.srv.cfg.GoAccessURL = goaccess.URL

	// Certificats : valide, bientôt expiré, expiré.
	dir := t.TempDir()
	e.srv.cfg.CertDir = dir
	now := e.srv.cfg.Now()
	for name, left := range map[string]time.Duration{"ok.example.com": 62 * 24 * time.Hour, "bientot.example.com": 9 * 24 * time.Hour, "perime.example.com": -time.Hour} {
		d := filepath.Join(dir, "acme-v02.api.letsencrypt.org-directory", name)
		os.MkdirAll(d, 0o755)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-100 * 24 * time.Hour), NotAfter: now.Add(left)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		os.WriteFile(filepath.Join(d, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	}
	pki := filepath.Join(filepath.Dir(dir), "pki", "authorities", "local")
	os.MkdirAll(pki, 0o755)
	os.WriteFile(filepath.Join(pki, "root.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("racine")}), 0o644)

	// Journal d'accès avec des requêtes de tous les statuts.
	file := filepath.Join(t.TempDir(), "access.log")
	e.srv.cfg.AccessLogFile = file
	var logLines []string
	for i, st := range []int{200, 301, 404, 502} {
		logLines = append(logLines, fmt.Sprintf(`{"ts":%d,"request":{"client_ip":"192.0.2.%d","host":"wiki.example.com","method":"GET","uri":"/p%d"},"status":%d}`, 1793743000+i*60, i+1, i, st))
	}
	os.WriteFile(file, []byte(strings.Join(logLines, "\n")+"\n"), 0o600)

	// Échec de certificat lu dans les journaux de Caddy.
	tr := acmelog.New()
	e.srv.cfg.CertFailures = tr
	fmt.Fprintln(tr.Wrap(io.Discard), `{"level":"error","logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"wiki.example.com","error":"HTTP 400 urn:ietf:params:acme:error:unauthorized"}`)

	// Données : listes, compte DNS, hôtes de chaque type, CrowdSec.
	office, _ := e.srv.cfg.Store.AddAccessList(ctx, store.AccessList{Name: "Bureau", Addresses: []string{"198.51.100.0/24"}})
	e.post("/certificates/dns", url.Values{"name": {"Mon OVH"}, "provider": {"ovh"}, "f_endpoint": {"ovh-eu"}, "f_application_key": {"ak"}, "f_application_secret": {"as"}, "f_consumer_key": {"ck"}})
	e.post("/security/crowdsec", url.Values{"url": {lapi.URL}, "key": {"cle-fictive"}, "appsec_url": {appsec.URL}, "appsec_failopen": {"1"}})
	e.caddy.csStatus = caddyadmin.CrowdSecStatus{Healthy: true, Streaming: true, Interval: "10s", Decisions: 2}
	e.post("/hosts", url.Values{"domain": {"wiki.example.com", "docs.example.com"}, "target": {"192.0.2.21:8080"}, "access": {itoa(office)}, "waf": {"1"}, "hsts": {"1"}, "compress": {"1"}, "force": {"1"},
		"loc_path": {"/api"}, "loc_access": {"0"}, "loc_target": {"192.0.2.6:8443"}, "loc_strip": {"1"}})
	e.post("/hosts", url.Values{"domain": {"blog.example.com"}, "target": {"192.0.2.22:3000"}, "dns": {"1"}, "force": {"1"}})
	e.post("/hosts", url.Values{"domain": {"off.example.com"}, "target": {"192.0.2.23:80"}, "force": {"1"}})
	e.post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"old.example.com"}, "target": {"https://new.example.org"}, "preserve": {"1"}, "code": {"301"}})
	e.post("/hosts", url.Values{"kind": {"404"}, "domain": {"gone.example.com"}})
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	for _, h := range hosts {
		if h.Domain == "off.example.com" {
			e.post("/hosts/"+itoa(h.ID)+"/toggle", nil)
		}
	}
	e.post("/stats/journal", url.Values{})
	return e
}

func TestEnglishPagesHaveNoFrench(t *testing.T) {
	e := englishFixture(t)
	ctx := context.Background()
	hosts, _ := e.srv.cfg.Store.ListHosts(ctx)
	ids := map[string]string{}
	for _, h := range hosts {
		ids[h.Domain] = itoa(h.ID)
	}
	en := []string{"Accept-Language", "en"}

	type req struct {
		method, path string
		form         url.Values
	}
	get := func(p string) req { return req{"GET", p, nil} }
	post := func(p string, f url.Values) req { return req{"POST", p, f} }
	reqs := []req{
		// Pages
		get("/"), get("/hosts"), get("/hosts?q=wiki"), get("/hosts?q=zzz"), get("/redirections"), get("/erreurs-404"),
		get("/hosts/new"), get("/hosts/new?kind=redirect"), get("/hosts/new?kind=404"), get("/hosts/new?target=http%3A%2F%2Fgoaccess%3A8080"),
		get("/hosts/" + ids["wiki.example.com"] + "/edit"), get("/hosts/" + ids["blog.example.com"] + "/edit"),
		get("/hosts/" + ids["old.example.com"] + "/edit"), get("/hosts/" + ids["gone.example.com"] + "/edit"),
		get("/security/protection"), get("/security/crowdsec"), get("/security/crowdsec/install"), get("/security/access"),
		get("/security/lists/new"), get("/security/lists/1/edit"), get("/security/proxies"),
		get("/certificates"), get("/certificates/dns"), get("/certificates/dns/new"), get("/certificates/dns/1/edit"),
		get("/stats"), get("/stats/install"), get("/settings"),
		// Fragments htmx
		get("/dashboard/online"), get("/hosts/" + ids["wiki.example.com"] + "/status"), get("/security/crowdsec/status"),
		get("/hosts/locations/row"), get("/hosts/domains/row"), get("/certificates/dns/fields?provider=ovh"), get("/certificates/dns/fields?provider=cloudflare"),
		post("/hosts/check/dns", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}}),
		post("/hosts/check/dns", url.Values{"domain": {"*.example.org"}}),
		post("/hosts/check/target", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}}),
		post("/hosts/check/target", url.Values{"kind": {"redirect"}, "domain": {"a.example.com"}, "target": {"https://b.example.org"}}),
		post("/hosts/check/target", url.Values{"domain": {"a.example.com"}, "target": {"not an address"}}),
		post("/hosts/check/preview", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}}),
		post("/hosts/check/preview", url.Values{}),
		// Messages de confirmation (paramètres de redirection)
		get("/hosts?added=wiki.example.com"), get("/hosts?changed=wiki.example.com"), get("/hosts?disabled=wiki.example.com"),
		get("/hosts?enabled=wiki.example.com"), get("/hosts?deleted=wiki.example.com"),
		get("/security/access?added=Bureau"), get("/security/access?changed=Bureau"), get("/security/access?deleted=Bureau"),
		get("/certificates/dns?added=Mon+OVH"), get("/certificates/dns?changed=Mon+OVH"), get("/certificates/dns?deleted=Mon+OVH"),
		get("/settings?saved=1"), get("/settings?password=1"), get("/security/proxies?saved=1"),
		get("/security/protection?csconnected=1"), get("/security/protection?csenabled=1"), get("/security/protection?csdisabled=1"), get("/security/protection?csremoved=1"),
		// Saisies invalides
		post("/settings/password", url.Values{"current": {"faux"}}),
		post("/settings/password", url.Values{"current": {goodPassword}, "password": {"court"}, "confirm": {"court"}}),
		post("/settings/password", url.Values{"current": {goodPassword}, "password": {goodPassword + "x"}, "confirm": {"autre"}}),
		post("/hosts", url.Values{}),
		post("/hosts", url.Values{"domain": {"wiki.example.com"}}),
		post("/hosts", url.Values{"domain": {"http://x"}, "target": {"192.0.2.1:80"}}),
		post("/hosts", url.Values{"domain": {"x.example.com"}, "target": {"ftp://192.0.2.1"}}),
		post("/hosts", url.Values{"domain": {"x.example.com"}, "target": {"192.0.2.1:80/chemin"}}),
		post("/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.99:80"}}),
		post("/hosts", url.Values{"domain": {"y.example.com", "y.example.com"}, "target": {"192.0.2.1:80"}}),
		post("/hosts", url.Values{"domain": {"y.example.com"}, "target": {"192.0.2.1:80"}, "access": {"99"}}),
		post("/hosts", url.Values{"domain": {"y.example.com"}, "target": {"192.0.2.1:80"}, "dns": {"99"}}),
		post("/hosts", url.Values{"domain": {"y.example.com"}, "target": {"192.0.2.1:80"}, "loc_path": {"api"}, "loc_target": {"192.0.2.2:80"}}),
		post("/hosts", url.Values{"domain": {"y.example.com"}, "target": {"192.0.2.1:80"}, "loc_path": {"/api"}, "loc_access": {"0"}}),
		post("/hosts", url.Values{"domain": {"y.example.com"}, "target": {"192.0.2.1:80"}, "loc_path": {"/a b"}, "loc_target": {"192.0.2.2:80"}}),
		post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"r.example.com"}, "target": {"https://r.example.com"}}),
		post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"r.example.com"}, "target": {"https://x.example.org/a"}, "preserve": {"1"}}),
		post("/hosts", url.Values{"kind": {"redirect"}, "domain": {"r.example.com"}, "target": {"x {y}"}}),
		post("/security/lists", url.Values{"name": {""}, "addresses": {"192.0.2.1"}}),
		post("/security/lists", url.Values{"name": {"Test"}, "addresses": {"not an address"}}),
		post("/security/lists", url.Values{"name": {"Bureau"}, "addresses": {"192.0.2.1"}}),
		post("/security/lists/1/delete", nil),
		post("/security/proxies", url.Values{"proxies": {"cloudflare.com"}}),
		post("/certificates/dns", url.Values{"name": {""}, "provider": {"ovh"}}),
		post("/certificates/dns", url.Values{"name": {"X"}, "provider": {"ovh"}, "f_endpoint": {"ovh-eu"}}),
		post("/certificates/dns", url.Values{"name": {"Mon OVH"}, "provider": {"ovh"}, "f_endpoint": {"ovh-eu"}, "f_application_key": {"a"}, "f_application_secret": {"b"}, "f_consumer_key": {"c"}}),
		post("/certificates/dns/1/delete", nil),
		post("/security/crowdsec", url.Values{"url": {""}, "key": {""}}),
		post("/security/crowdsec", url.Values{"url": {"crowdsec:8080"}, "key": {"x"}}),
		post("/security/crowdsec", url.Values{"url": {"http://127.0.0.1:1"}, "key": {"x"}}),
		post("/security/crowdsec", url.Values{"url": {"http://127.0.0.1:1"}, "key": {"mauvaise"}, "appsec_url": {"x"}}),
		post("/settings", url.Values{"crowdsec_ui_url": {"not an address"}}),
		post("/stats/journal", url.Values{"back": {"install"}}),
	}
	var problems []string
	for _, r := range reqs {
		resp, body := e.do(r.method, r.path, r.form, en...)
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") && body != "" {
			continue
		}
		if fr := frenchIn(body); len(fr) > 0 {
			problems = append(problems, fmt.Sprintf("%s %s (%d) : %q", r.method, r.path, resp.StatusCode, fr))
		}
	}
	// Pages sans compte connecté, et page d'erreur.
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, p := range []string{"/login", "/hosts/999/edit", "/nimporte-quoi"} {
		rq, _ := http.NewRequest("GET", e.ts.URL+p, nil)
		rq.Header.Set("Accept-Language", "en")
		if resp, err := anon.Do(rq); err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if fr := frenchIn(string(b)); len(fr) > 0 {
				problems = append(problems, fmt.Sprintf("anonyme GET %s : %q", p, fr))
			}
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("du français reste dans %d réponse(s) en anglais :\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
}

func TestLanguageSettingOverridesTheBrowser(t *testing.T) {
	e := newEnv(t)
	e.setup()
	en := []string{"Accept-Language", "en-US,en;q=0.9"}
	fr := []string{"Accept-Language", "fr-FR,fr;q=0.9"}

	// « Automatique » (défaut) : le navigateur décide ; sans en-tête, le français.
	if _, b := e.do("GET", "/hosts", nil); !strings.Contains(b, `<html lang="fr">`) || !strings.Contains(b, "Nouvel hôte") {
		t.Error("sans en-tête, la page doit être en français")
	}
	resp, b := e.do("GET", "/hosts", nil, en...)
	if !strings.Contains(b, `<html lang="en">`) || !strings.Contains(b, "New host") || strings.Contains(b, "Nouvel hôte") {
		t.Errorf("navigateur anglais : page non traduite : %.300s", b)
	}
	if resp.StatusCode != 200 || resp.ContentLength != int64(len(b)) {
		t.Errorf("statut %d, Content-Length %d pour %d octets", resp.StatusCode, resp.ContentLength, len(b))
	}
	if _, b := e.do("GET", "/hosts", nil, fr...); !strings.Contains(b, "Nouvel hôte") {
		t.Error("navigateur français : page traduite à tort")
	}
	// Le français est exactement la page d'origine : la traduction ne s'applique qu'à l'anglais.
	_, plain := e.do("GET", "/settings", nil)
	if _, withHeader := e.do("GET", "/settings", nil, fr...); plain != withHeader {
		t.Error("le français change selon l'en-tête du navigateur")
	}

	// Le réglage « English » impose l'anglais, même sans en-tête ; « Français » impose le français.
	e.post("/settings", url.Values{"ui_language": {"en"}})
	if _, b := e.do("GET", "/hosts", nil); !strings.Contains(b, "New host") {
		t.Error("réglage English sans effet")
	}
	if _, b := e.do("GET", "/settings", nil); !strings.Contains(b, `<option value="en" selected`) || !strings.Contains(b, "Language") {
		t.Errorf("réglage non réaffiché : %s", b)
	}
	e.post("/settings", url.Values{"ui_language": {"fr"}})
	if _, b := e.do("GET", "/hosts", nil, en...); !strings.Contains(b, "Nouvel hôte") {
		t.Error("réglage Français ignoré par un navigateur anglais")
	}
	// Une valeur inconnue est ignorée ; « auto » rend la main au navigateur.
	e.post("/settings", url.Values{"ui_language": {"klingon"}})
	if _, b := e.do("GET", "/hosts", nil, en...); !strings.Contains(b, "Nouvel hôte") {
		t.Error("valeur inconnue prise en compte")
	}
	e.post("/settings", url.Values{"ui_language": {"auto"}})
	if _, b := e.do("GET", "/hosts", nil, en...); !strings.Contains(b, "New host") {
		t.Error("« auto » ne suit pas le navigateur")
	}
}

func TestEnglishKeepsStatusCodesRedirectsAndStaticFiles(t *testing.T) {
	e := newEnv(t)
	e.setup()
	en := []string{"Accept-Language", "en"}
	// Statut d'erreur conservé.
	if resp, _ := e.do("POST", "/hosts", url.Values{}, en...); resp.StatusCode != 422 {
		t.Errorf("statut : %d", resp.StatusCode)
	}
	// Redirection conservée, sans corps.
	if resp, body := e.do("POST", "/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.21:8080"}, "force": {"1"}}, en...); resp.StatusCode != 303 || body != "" || !strings.HasPrefix(resp.Header.Get("Location"), "/hosts?added=") {
		t.Errorf("redirection : %d %q %q", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	// Erreur 404 en texte simple, traduite.
	if resp, body := e.do("GET", "/hosts/999/edit", nil, en...); resp.StatusCode != 404 || strings.Contains(body, "introuvable") {
		t.Errorf("404 : %d %q", resp.StatusCode, body)
	}
	// Les fichiers statiques ne passent pas par la traduction.
	resp, body := e.do("GET", "/static/htmx.min.js", nil, en...)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") || len(body) < 10000 {
		t.Errorf("fichier statique : %d %s %d octets", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	}
}

func TestEnglishSetupAndLoginFlows(t *testing.T) {
	e := newEnv(t)
	en := []string{"Accept-Language", "en"}
	var all []string
	collect := func(name string, resp *http.Response, body string) string {
		if fr := frenchIn(body); len(fr) > 0 {
			all = append(all, fmt.Sprintf("%s (%d) : %q", name, resp.StatusCode, fr))
		}
		return body
	}
	// Avant la création du compte : /login renvoie vers /setup.
	resp, body := e.do("GET", "/setup", nil, en...)
	if !strings.Contains(collect("GET /setup", resp, body), "Welcome to Gatewyn") {
		t.Error("page d'installation non traduite")
	}
	resp, body = e.do("POST", "/setup", url.Values{"username": {goodUsername}, "password": {goodPassword}, "confirm": {"autre chose"}}, en...)
	if !strings.Contains(collect("setup mismatch", resp, body), "do not match") {
		t.Errorf("mots de passe différents : %s", body)
	}
	resp, body = e.do("POST", "/setup", url.Values{"username": {goodUsername}, "password": {"court"}, "confirm": {"court"}}, en...)
	if !strings.Contains(collect("setup short", resp, body), "at least") {
		t.Errorf("mot de passe trop court : %s", body)
	}
	resp, body = e.do("POST", "/setup", url.Values{"username": {"a b"}, "password": {goodPassword}, "confirm": {goodPassword}}, en...)
	if !strings.Contains(collect("setup username", resp, body), "username can only contain") {
		t.Errorf("identifiant refusé : %s", body)
	}
	e.setup()

	// Connexion : mauvais mot de passe, puis trop d'essais.
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	login := func(pw string) (*http.Response, string) {
		rq, _ := http.NewRequest("POST", e.ts.URL+"/login", strings.NewReader(url.Values{"username": {goodUsername}, "password": {pw}}.Encode()))
		rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rq.Header.Set("Accept-Language", "en")
		resp, err := anon.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	resp, body = login("mauvais mot de passe")
	collect("login", resp, body)
	var last string
	for i := 0; i < 8; i++ {
		resp, last = login("encore faux")
		collect("login repeated", resp, last)
	}
	if !strings.Contains(last, "Too many attempts") {
		t.Errorf("limitation des essais non traduite : %.300s", last)
	}
	if len(all) > 0 {
		t.Errorf("du français reste :\n  %s", strings.Join(all, "\n  "))
	}
}

// Régression (français) : mettre en majuscule le premier octet d'un message qui commence par un
// caractère de plusieurs octets (« ou É) le corrompait (« �� cloudflare.com » n'est pas une adresse… »).
func TestCapitalizeKeepsMultibyteCharacters(t *testing.T) {
	for in, want := range map[string]string{"« x » est faux": "« x » est faux", "élan": "Élan", "abc": "Abc", "": "", "Éa": "Éa"} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, attendu %q", in, got, want)
		}
	}
	e := newEnv(t)
	e.setup()
	_, body := e.post("/security/proxies", url.Values{"proxies": {"cloudflare.com"}})
	if !strings.Contains(body, "« cloudflare.com » n&#39;est pas une adresse IP") || strings.Contains(body, "�") {
		t.Errorf("message d'erreur corrompu : %s", body)
	}
}
