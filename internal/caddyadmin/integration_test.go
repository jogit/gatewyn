package caddyadmin

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"github.com/jogit/gatewyn/internal/crowdsec"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/dnsprov"
)

// Test sur un Caddy réel (conteneur jetable). Ignoré sans ces variables :
//
//	GATEWYN_TEST_CADDY_ADMIN  ex. http://127.0.0.1:12019
//	GATEWYN_TEST_CADDY_HTTPS  ex. 127.0.0.1:12443 (port 443 du conteneur)
//	GATEWYN_TEST_UPSTREAM     ex. http://gw-up:8080 (service qui répond, joignable depuis Caddy)
//
// Le domaine de test est en .localhost : Caddy lui émet un certificat interne.
// Voir scripts/test-caddy.sh.
func TestRealCaddy(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	if admin == "" || httpsAddr == "" || upstream == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	const domain = "wiki.localhost"
	get := func() (int, string, error) {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
				},
			},
		}
		resp, err := client.Get("https://" + domain + "/")
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	waitFor := func(want func(code int, body string, err error) bool) (int, string, error) {
		var code int
		var body string
		var err error
		for i := 0; i < 20; i++ {
			code, body, err = get()
			if want(code, body, err) {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		return code, body, err
	}

	hosts := []caddyconf.Host{{Domain: domain, Target: upstream}}
	if err := c.Apply(ctx, hosts); err != nil {
		t.Fatal(err)
	}
	// Remplacer deux fois de suite doit fonctionner (POST crée ou remplace).
	if err := c.Apply(ctx, hosts); err != nil {
		t.Fatalf("deuxième publication : %v", err)
	}

	got, err := c.Hosts(ctx)
	if err != nil || !reflect.DeepEqual(got, hosts) {
		t.Fatalf("hôtes relus = %+v, err = %v ; attendu %+v", got, err, hosts)
	}

	code, body, err := waitFor(func(code int, _ string, err error) bool { return err == nil && code == 200 })
	if err != nil || code != 200 || !strings.Contains(body, "hello from upstream") {
		t.Fatalf("requête HTTPS réelle : code %d, corps %q, err %v", code, body, err)
	}

	// Retirer l'hôte : le service n'est plus servi, l'administration reste joignable.
	if err := c.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("administration perdue après publication : %v", err)
	}
	code, _, _ = waitFor(func(code int, _ string, err error) bool { return err != nil || code != 200 })
	if code == 200 {
		t.Error("le service répond encore après retrait de l'hôte")
	}
}

// TestRealCaddyRedirectAndNotFound vérifie sur un Caddy réel les types d'hôte
// « redirection » et « page introuvable » : code, en-tête Location, chemin conservé.
func TestRealCaddyRedirectAndNotFound(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	if admin == "" || httpsAddr == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	hosts := []caddyconf.Host{
		{Domain: "keep.localhost", Kind: caddyconf.KindRedirect, Target: "https://example.org", Code: 301, PreservePath: true},
		{Domain: "fixed.localhost", Kind: caddyconf.KindRedirect, Target: "https://example.org/landing", Code: 302},
		{Domain: "gone.localhost", Kind: caddyconf.KindNotFound},
	}
	if err := c.Apply(ctx, hosts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })

	get := func(domain, path string) (*http.Response, string, error) {
		client := &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
				},
			},
		}
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			resp, err = client.Get("https://" + domain + path)
			if err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b), nil
	}

	tests := []struct {
		domain, path string
		status       int
		location     string
	}{
		{"keep.localhost", "/a/b?c=d", 301, "https://example.org/a/b?c=d"},
		{"keep.localhost", "/", 301, "https://example.org/"},
		{"fixed.localhost", "/n-importe/quoi?x=1", 302, "https://example.org/landing"},
		{"gone.localhost", "/page", 404, ""},
	}
	for _, tt := range tests {
		resp, body, err := get(tt.domain, tt.path)
		if err != nil {
			t.Fatalf("%s%s : %v", tt.domain, tt.path, err)
		}
		if resp.StatusCode != tt.status || resp.Header.Get("Location") != tt.location {
			t.Errorf("%s%s → %d Location %q ; attendu %d %q", tt.domain, tt.path, resp.StatusCode, resp.Header.Get("Location"), tt.status, tt.location)
		}
		if tt.status == 404 && !strings.Contains(body, "404") {
			t.Errorf("corps de la page 404 : %q", body)
		}
	}
	// Les hôtes relus depuis Caddy gardent leur type (sinon la dérive passerait inaperçue).
	got, err := c.Hosts(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("hôtes relus : %+v, %v", got, err)
	}
}

// Liste d'accès : une adresse hors liste reçoit 403, une adresse dans la liste atteint le service.
func TestRealCaddyAccessList(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	if admin == "" || httpsAddr == "" || upstream == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	hosts := []caddyconf.Host{
		{Domain: "denied.localhost", Target: upstream, Access: []string{"192.0.2.0/24"}},
		{Domain: "allowed.localhost", Target: upstream, Access: []string{"0.0.0.0/0", "::/0"}},
		{Domain: "public.localhost", Target: upstream},
	}
	if err := c.Apply(ctx, hosts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })

	get := func(domain string) (int, string) {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
				},
			},
		}
		var lastErr error
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			resp, err := client.Get("https://" + domain + "/")
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				return resp.StatusCode, string(b)
			}
			lastErr = err
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s : %v", domain, lastErr)
		return 0, ""
	}
	for domain, want := range map[string]int{"denied.localhost": 403, "allowed.localhost": 200, "public.localhost": 200} {
		if status, body := get(domain); status != want {
			t.Errorf("%s → %d (%q) ; attendu %d", domain, status, body, want)
		}
	}
}

// Chaque fournisseur DNS du catalogue est accepté par le Caddy de l'image : mêmes
// noms de module et de champs que dans internal/dnsprov. « caddy validate »
// charge et prépare les modules sans rien démarrer ni contacter.
func TestRealCaddyAcceptsEveryDNSProvider(t *testing.T) {
	image := os.Getenv("GATEWYN_TEST_CADDY_IMAGE")
	if image == "" {
		t.Skip("GATEWYN_TEST_CADDY_IMAGE absente : test sur Caddy réel ignoré")
	}
	for _, p := range dnsprov.All() {
		values := map[string]string{}
		for _, f := range p.Fields {
			values[f.Key] = strings.Repeat("a", 40) // forme d'un jeton : Cloudflare la vérifie
			if f.Default != "" {
				values[f.Key] = f.Default
			}
		}
		policies, err := caddyconf.TLSJSON([]caddyconf.Host{{
			Domain: "*.example.com", Kind: caddyconf.KindNotFound,
			DNS: &caddyconf.DNSChallenge{Account: 1, Provider: dnsprov.CaddyConfig(p.ID, values)},
		}})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		cfg := `{"apps":{"tls":{"automation":` + string(policies) + `}}}`
		if err := os.WriteFile(filepath.Join(dir, "c.json"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("docker", "run", "--rm", "-v", dir+":/cfg:ro", image, "caddy", "validate", "--config", "/cfg/c.json").CombinedOutput()
		if err != nil {
			t.Errorf("%s refusé par Caddy : %v\n%s", p.ID, err, out)
		}
	}
}

// HTTP seulement : l'hôte répond en clair sur le port 80, sans HTTPS ni certificat, et
// les autres hôtes gardent leur redirection vers HTTPS. Auto-signé : HTTPS avec le
// certificat de l'autorité interne de Caddy.
func TestRealCaddyHTTPOnlyAndSelfSigned(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	httpAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTP")
	if admin == "" || httpsAddr == "" || httpAddr == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	hosts := []caddyconf.Host{
		{Domain: "secure.localhost", Kind: caddyconf.KindNotFound},
		{Domain: "plain.localhost", Kind: caddyconf.KindNotFound, HTTPOnly: true},
		{Domain: "self.localhost", Kind: caddyconf.KindNotFound, SelfSigned: true},
	}
	if err := c.Apply(ctx, hosts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })

	httpGet := func(domain string) *http.Response {
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpAddr)
			}}}
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ {
			if resp, err = client.Get("http://" + domain + "/"); err == nil {
				return resp
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s : %v", domain, err)
		return nil
	}
	if resp := httpGet("plain.localhost"); resp.StatusCode != 404 || resp.Header.Get("Location") != "" {
		t.Errorf("plain.localhost en HTTP → %d Location %q ; attendu 404 sans redirection", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := httpGet("secure.localhost"); resp.StatusCode != 308 || !strings.HasPrefix(resp.Header.Get("Location"), "https://secure.localhost") {
		t.Errorf("secure.localhost en HTTP → %d Location %q ; attendu la redirection vers HTTPS", resp.StatusCode, resp.Header.Get("Location"))
	}

	handshake := func(domain string) error {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", httpsAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		tc := tls.Client(conn, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		return tc.Handshake()
	}
	var err error
	for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
		if err = handshake("self.localhost"); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Errorf("auto-signé : %v", err)
	}
	if err := handshake("plain.localhost"); err == nil {
		t.Error("HTTPS réussi pour un hôte en HTTP seulement")
	}

	// Plus aucun hôte en HTTP seulement : le serveur HTTP est retiré, la redirection reste.
	if err := c.Apply(ctx, hosts[:1]); err != nil {
		t.Fatal(err)
	}
	if resp := httpGet("secure.localhost"); resp.StatusCode != 308 {
		t.Errorf("après retrait du serveur HTTP : %d", resp.StatusCode)
	}
}

// Un hôte à plusieurs noms répond sur chacun, et la relecture depuis Caddy les retrouve.
func TestRealCaddyAliases(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	if admin == "" || httpsAddr == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	if err := c.Apply(ctx, []caddyconf.Host{{Domain: "main.localhost", Aliases: []string{"alias.localhost"}, Kind: caddyconf.KindNotFound}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })
	for _, domain := range []string{"main.localhost", "alias.localhost"} {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			},
		}}
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			if resp, err = client.Get("https://" + domain + "/"); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s : %v", domain, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s → %d, attendu 404", domain, resp.StatusCode)
		}
	}
	got, err := c.Hosts(ctx)
	if err != nil || len(got) != 1 || got[0].Domain != "main.localhost" || len(got[0].Aliases) != 1 || got[0].Aliases[0] != "alias.localhost" {
		t.Errorf("relecture : %+v %v", got, err)
	}
}

// HSTS : l'en-tête est présent sur la réponse d'un hôte qui l'active, absent sinon.
func TestRealCaddyHSTS(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	if admin == "" || httpsAddr == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	if err := c.Apply(ctx, []caddyconf.Host{
		{Domain: "plain.localhost", Kind: caddyconf.KindNotFound},
		{Domain: "hsts.localhost", Kind: caddyconf.KindNotFound, HSTS: 1},
		{Domain: "sub.localhost", Kind: caddyconf.KindNotFound, HSTS: 2},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })
	for domain, want := range map[string]string{
		"plain.localhost": "",
		"hsts.localhost":  "max-age=31536000",
		"sub.localhost":   "max-age=31536000; includeSubDomains",
	} {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			},
		}}
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			if resp, err = client.Get("https://" + domain + "/"); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s : %v", domain, err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Strict-Transport-Security"); got != want || resp.StatusCode != 404 {
			t.Errorf("%s → %d, HSTS %q ; attendu 404 et %q", domain, resp.StatusCode, got, want)
		}
	}
}

// Chemins : /api part vers sa propre cible (ici injoignable, donc 502), le reste vers
// le service ; la relecture depuis Caddy rattache les chemins à l'hôte.
func TestRealCaddyLocations(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	if admin == "" || httpsAddr == "" || upstream == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	if err := c.Apply(ctx, []caddyconf.Host{{Domain: "paths.localhost", Target: upstream,
		Locations: []caddyconf.Location{{Path: "/api", Target: "http://127.0.0.1:1"}}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "paths.localhost", InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
		},
	}}
	for path, want := range map[string]int{"/": 200, "/autre": 200, "/api": 502, "/api/v1/x": 502, "/apix": 200} {
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			if resp, err = client.Get("https://paths.localhost" + path); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s : %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s → %d, attendu %d", path, resp.StatusCode, want)
		}
	}
	got, err := c.Hosts(ctx)
	if err != nil || len(got) != 1 || len(got[0].Locations) != 1 || got[0].Locations[0].Path != "/api" || got[0].Locations[0].Target != "http://127.0.0.1:1" {
		t.Errorf("relecture : %+v %v", got, err)
	}
}

// Accès par chemin : /admin est limité à une liste dont le client n'est pas membre (403),
// /open reste public malgré la liste de l'hôte (hérité : ici 403 aussi), le reste suit l'hôte.
func TestRealCaddyLocationAccess(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	if admin == "" || httpsAddr == "" || upstream == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	nobody := []string{"192.0.2.0/24"} // le client de test n'y est pas
	everyone := []string{"0.0.0.0/0", "::/0"}
	hosts := []caddyconf.Host{{Domain: "acl.localhost", Target: upstream, Access: nobody, Locations: []caddyconf.Location{
		{Path: "/inherit", Target: upstream},                // hérite de l'hôte : refusé
		{Path: "/open", Target: upstream, Public: true},     // public malgré l'hôte
		{Path: "/own", Target: upstream, Access: everyone},  // sa liste inclut le client
		{Path: "/closed", Target: upstream, Access: nobody}, // sa liste l'exclut
	}}, {Domain: "openhost.localhost", Target: upstream, Locations: []caddyconf.Location{
		{Path: "/admin", Target: upstream, Access: nobody}, // l'hôte est public, ce chemin non
	}}}
	if err := c.Apply(ctx, hosts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })

	status := func(domain, path string) int {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			},
		}}
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			if resp, err = client.Get("https://" + domain + path); err == nil {
				resp.Body.Close()
				return resp.StatusCode
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s%s : %v", domain, path, err)
		return 0
	}
	for _, tt := range []struct {
		domain, path string
		want         int
	}{
		{"acl.localhost", "/", 403}, {"acl.localhost", "/inherit", 403}, {"acl.localhost", "/inherit/x", 403},
		{"acl.localhost", "/open", 200}, {"acl.localhost", "/open/x", 200},
		{"acl.localhost", "/own", 200}, {"acl.localhost", "/closed", 403},
		{"openhost.localhost", "/", 200}, {"openhost.localhost", "/admin", 403}, {"openhost.localhost", "/admin/x", 403}, {"openhost.localhost", "/administrator", 200},
	} {
		if got := status(tt.domain, tt.path); got != tt.want {
			t.Errorf("%s%s → %d, attendu %d", tt.domain, tt.path, got, tt.want)
		}
	}
}

// CrowdSec : avec un vrai CrowdSec (API locale) et le bouncer de Caddy, une adresse
// bloquée reçoit 403, puis retrouve l'accès quand la décision disparaît. Gatewyn lit
// les décisions par l'API locale, et l'état du bouncer par l'API d'administration de Caddy.
// Voir scripts/test-crowdsec.sh.
func TestRealCrowdSec(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	lapiForCaddy := os.Getenv("GATEWYN_TEST_CROWDSEC_URL")
	lapiFromHost := os.Getenv("GATEWYN_TEST_CROWDSEC_HOSTURL")
	key := os.Getenv("GATEWYN_TEST_CROWDSEC_KEY")
	container := os.Getenv("GATEWYN_TEST_CROWDSEC_CONTAINER")
	if admin == "" || httpsAddr == "" || lapiForCaddy == "" || key == "" || container == "" {
		t.Skip("variables GATEWYN_TEST_CROWDSEC_* absentes : test sur CrowdSec réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	cscli := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("docker", append([]string{"exec", container, "cscli"}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("cscli %v : %v\n%s", args, err, out)
		}
	}
	hosts := []caddyconf.Host{{Domain: "cs.localhost", Kind: caddyconf.KindNotFound, CrowdSec: true}}
	if err := c.ApplyAll(ctx, hosts, caddyconf.Global{CrowdSec: &caddyconf.CrowdSec{URL: lapiForCaddy, Key: key}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.ApplyAll(ctx, nil, caddyconf.Global{}) })

	// Le bouncer est chargé et joint CrowdSec.
	var st CrowdSecStatus
	var err error
	for i := 0; i < 30; i++ {
		if st, err = c.CrowdSecStatus(ctx); err == nil && st.Healthy {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !st.Healthy || !st.Streaming || st.Interval != "10s" {
		t.Fatalf("état du bouncer : %+v %v", st, err)
	}

	status := func() int {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: "cs.localhost", InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			},
		}}
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			if resp, err := client.Get("https://cs.localhost/"); err == nil {
				resp.Body.Close()
				return resp.StatusCode
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatal("cs.localhost injoignable")
		return 0
	}
	waitFor := func(want int) int {
		var got int
		for i := 0; i < 40; i++ { // le flux de décisions est relu toutes les 10 s
			if got = status(); got == want {
				return got
			}
			time.Sleep(time.Second)
		}
		return got
	}
	if got := status(); got != 404 {
		t.Fatalf("avant blocage : %d, attendu 404 (la page introuvable de l'hôte)", got)
	}

	// L'adresse du client, vue par Caddy, est celle de la passerelle Docker : on bloque les plages privées.
	for _, r := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		cscli("decisions", "add", "--range", r, "--duration", "10m", "--reason", "test fictif")
	}
	if got := waitFor(403); got != 403 {
		t.Fatalf("après blocage : %d, attendu 403", got)
	}

	// Gatewyn lit les décisions par l'API locale (le compteur du bouncer ne compte pas les plages : il n'est pas utilisé).
	ds, err := crowdsec.Decisions(ctx, http.DefaultClient, lapiFromHost, key)
	if err != nil || len(ds) != 3 || ds[0].Remaining <= 0 {
		t.Errorf("décisions : %+v %v", ds, err)
	}
	if _, err := crowdsec.Decisions(ctx, http.DefaultClient, lapiFromHost, "mauvaise-cle"); !errors.Is(err, crowdsec.ErrBadKey) {
		t.Errorf("mauvaise clé : %v", err)
	}
	if st, err = c.CrowdSecStatus(ctx); err != nil || !st.Healthy {
		t.Errorf("état du bouncer après blocage : %+v %v", st, err)
	}

	// Décisions supprimées : l'accès revient.
	cscli("decisions", "delete", "--all")
	if got := waitFor(404); got != 404 {
		t.Errorf("après déblocage : %d, attendu 404", got)
	}
}

// tlsClient joint Caddy pour un nom donné, sans décompresser ni suivre les redirections :
// les en-têtes de la réponse sont ceux que Caddy a envoyés.
func tlsClient(domain, httpsAddr string) *http.Client {
	return &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			},
		}}
}

// get fait une requête, en réessayant tant que le certificat interne n'est pas émis.
func realGet(t *testing.T, domain, httpsAddr, path string, header http.Header) (*http.Response, string) {
	t.Helper()
	client := tlsClient(domain, httpsAddr)
	var lastErr error
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://"+domain+path, nil)
		for k, v := range header {
			req.Header[k] = v
		}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var body []byte
			if resp.Header.Get("Content-Encoding") == "gzip" {
				zr, zerr := gzip.NewReader(resp.Body)
				if zerr != nil {
					t.Fatalf("%s%s : corps gzip illisible : %v", domain, path, zerr)
				}
				body, _ = io.ReadAll(zr)
			} else {
				body, _ = io.ReadAll(resp.Body)
			}
			return resp, string(body)
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s%s : %v", domain, path, lastErr)
	return nil, ""
}

// Options d'un hôte : compression, en-têtes, chemin retiré ou gardé, cible h2c acceptée.
func TestRealCaddyHostOptions(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	echo := os.Getenv("GATEWYN_TEST_ECHO")
	if admin == "" || httpsAddr == "" || echo == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	if err := c.Apply(ctx, []caddyconf.Host{
		{Domain: "opt.localhost", Target: echo, Compress: true, NoBuffering: true, FrameOptions: "DENY", NoIndex: true,
			Locations: []caddyconf.Location{{Path: "/strip", Target: echo, StripPath: true}, {Path: "/keep", Target: echo}}},
		{Domain: "plain.localhost", Target: echo},
		{Domain: "grpc.localhost", Target: "h2c://gw-echo:8080"}, // Caddy doit accepter le transport h2c
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Apply(ctx, nil) })

	gz := http.Header{"Accept-Encoding": {"gzip"}}
	resp, body := realGet(t, "opt.localhost", httpsAddr, "/page", gz)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || !strings.HasPrefix(body, "/page ") {
		t.Errorf("/page : %d, Content-Encoding %q, corps %.20q", resp.StatusCode, resp.Header.Get("Content-Encoding"), body)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("X-Robots-Tag") != "noindex" {
		t.Errorf("en-têtes : X-Frame-Options %q, X-Robots-Tag %q", resp.Header.Get("X-Frame-Options"), resp.Header.Get("X-Robots-Tag"))
	}
	for path, want := range map[string]string{"/strip/x/y": "/x/y ", "/keep/z": "/keep/z "} {
		if _, body := realGet(t, "opt.localhost", httpsAddr, path, gz); !strings.HasPrefix(body, want) {
			t.Errorf("%s : le service reçoit %.20q, attendu un début %q", path, body, want)
		}
	}
	// Sans option : ni compression ni en-têtes ajoutés.
	resp, body = realGet(t, "plain.localhost", httpsAddr, "/page", gz)
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("X-Frame-Options") != "" || resp.Header.Get("X-Robots-Tag") != "" || !strings.HasPrefix(body, "/page ") {
		t.Errorf("hôte sans option : %v", resp.Header)
	}
}

// Proxies de confiance : derrière eux, l'adresse du visiteur vient de X-Forwarded-For, lu de droite à
// gauche ; sans eux, cet en-tête est ignoré, donc un visiteur ne peut pas se faire passer pour une
// adresse autorisée.
func TestRealCaddyTrustedProxies(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	if admin == "" || httpsAddr == "" || upstream == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	hosts := []caddyconf.Host{{Domain: "xff.localhost", Target: upstream, Access: []string{"203.0.113.0/24"}}}
	t.Cleanup(func() { _ = c.ApplyAll(ctx, nil, caddyconf.Global{}) })
	status := func(xff string) int {
		resp, _ := realGet(t, "xff.localhost", httpsAddr, "/", http.Header{"X-Forwarded-For": {xff}})
		return resp.StatusCode
	}

	// Sans proxy de confiance : l'en-tête est ignoré, le client (passerelle Docker) n'est pas dans la liste.
	if err := c.ApplyAll(ctx, hosts, caddyconf.Global{}); err != nil {
		t.Fatal(err)
	}
	if got := status("203.0.113.5"); got != 403 {
		t.Errorf("sans proxy de confiance, X-Forwarded-For falsifié → %d, attendu 403", got)
	}

	// Le client (passerelle Docker, plage privée) est un proxy de confiance.
	trusted := caddyconf.Global{TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}}
	if err := c.ApplyAll(ctx, hosts, trusted); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		xff  string
		want int
	}{
		{"203.0.113.5", 200},               // le visiteur annoncé par le proxy est dans la liste
		{"198.51.100.9", 403},              // il n'y est pas
		{"203.0.113.5, 198.51.100.9", 403}, // lecture de droite à gauche : une adresse ajoutée par le visiteur ne compte pas
		{"198.51.100.9, 203.0.113.5", 200}, // la dernière adresse, ajoutée par le proxy, est celle qui compte
	} {
		if got := status(tt.xff); got != tt.want {
			t.Errorf("proxy de confiance, X-Forwarded-For %q → %d, attendu %d", tt.xff, got, tt.want)
		}
	}
}

// WAF : avec AppSec activé dans CrowdSec, une requête qui sonde un fichier sensible (/.env) reçoit 403
// sur un hôte où le WAF est actif, et passe là où il est éteint ; une requête normale passe partout.
// Si AppSec tombe, le réglage « laisser passer » décide. Voir scripts/test-crowdsec.sh.
func TestRealCrowdSecAppSec(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	lapi := os.Getenv("GATEWYN_TEST_CROWDSEC_URL")
	appsec := os.Getenv("GATEWYN_TEST_APPSEC_URL")
	appsecFromHost := os.Getenv("GATEWYN_TEST_APPSEC_HOSTURL")
	key := os.Getenv("GATEWYN_TEST_CROWDSEC_KEY")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	if admin == "" || httpsAddr == "" || lapi == "" || appsec == "" || key == "" || upstream == "" {
		t.Skip("variables GATEWYN_TEST_APPSEC_* absentes : test sur CrowdSec réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	hosts := []caddyconf.Host{
		{Domain: "waf.localhost", Target: upstream, CrowdSec: true, WAF: true},
		{Domain: "nowaf.localhost", Target: upstream, CrowdSec: true},
	}
	t.Cleanup(func() { _ = c.ApplyAll(ctx, nil, caddyconf.Global{}) })

	// AppSec démarre un peu après l'API locale.
	var err error
	for i := 0; i < 60; i++ {
		if err = crowdsec.AppSecCheck(ctx, http.DefaultClient, appsecFromHost, key); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatalf("AppSec ne répond pas : %v", err)
	}
	if err := crowdsec.AppSecCheck(ctx, http.DefaultClient, appsecFromHost, "mauvaise-cle"); !errors.Is(err, crowdsec.ErrBadKey) {
		t.Errorf("mauvaise clé AppSec : %v", err)
	}

	apply := func(url string, failOpen bool) {
		t.Helper()
		g := caddyconf.Global{CrowdSec: &caddyconf.CrowdSec{URL: lapi, Key: key, AppSecURL: url, AppSecFailOpen: failOpen}}
		if err := c.ApplyAll(ctx, hosts, g); err != nil {
			t.Fatal(err)
		}
	}
	status := func(domain, path string) int {
		resp, _ := realGet(t, domain, httpsAddr, path, nil)
		return resp.StatusCode
	}
	// Caddy doit avoir chargé le bouncer avant de servir.
	apply(appsec, true)
	for i := 0; i < 30; i++ {
		if st, err := c.CrowdSecStatus(ctx); err == nil && st.Healthy {
			break
		}
		time.Sleep(time.Second)
	}

	for _, tt := range []struct {
		domain, path string
		want         int
	}{
		{"waf.localhost", "/index.html", 200}, // requête normale
		{"waf.localhost", "/.env", 403},       // sondage d'un fichier sensible : refusé par le WAF
		{"nowaf.localhost", "/.env", 200},     // WAF éteint pour cet hôte
		{"nowaf.localhost", "/index.html", 200},
	} {
		if got := status(tt.domain, tt.path); got != tt.want {
			t.Errorf("%s%s → %d, attendu %d", tt.domain, tt.path, got, tt.want)
		}
	}

	// AppSec injoignable : « laisser passer » laisse la requête passer, sinon elle est refusée.
	apply("http://gw-crowdsec:1", true)
	if got := status("waf.localhost", "/.env"); got != 200 {
		t.Errorf("AppSec tombé, laisser passer : %d, attendu 200", got)
	}
	apply("http://gw-crowdsec:1", false)
	if got := status("waf.localhost", "/index.html"); got == 200 {
		t.Errorf("AppSec tombé, refuser : %d, la requête ne devait pas passer", got)
	}
}

// TestRealCaddyAccessLog : le journal d'accès publié par Gatewyn est écrit en JSON
// dans le fichier demandé, puis Caddy cesse d'écrire une fois le journal retiré.
// Nécessite GATEWYN_TEST_CADDY_CONTAINER (nom du conteneur, voir scripts/test-caddy.sh).
func TestRealCaddyAccessLog(t *testing.T) {
	admin := os.Getenv("GATEWYN_TEST_CADDY_ADMIN")
	httpsAddr := os.Getenv("GATEWYN_TEST_CADDY_HTTPS")
	upstream := os.Getenv("GATEWYN_TEST_UPSTREAM")
	container := os.Getenv("GATEWYN_TEST_CADDY_CONTAINER")
	if admin == "" || httpsAddr == "" || upstream == "" || container == "" {
		t.Skip("variables GATEWYN_TEST_CADDY_* absentes : test sur Caddy réel ignoré")
	}
	ctx := context.Background()
	c := New(admin)
	t.Cleanup(func() { _ = c.ApplyAll(ctx, nil, caddyconf.Global{}) })

	const domain = "log.localhost"
	const file = "/tmp/gw-access-test.log"
	hosts := []caddyconf.Host{{Domain: domain, Target: upstream}}
	if err := c.ApplyAll(ctx, hosts, caddyconf.Global{AccessLog: &caddyconf.AccessLog{File: file, KeepDays: 30}}); err != nil {
		t.Fatal(err)
	}
	get := func() {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			},
		}}
		for i := 0; i < 20; i++ { // le certificat interne est émis à la première demande
			if resp, err := client.Get("https://" + domain + "/ping-journal"); err == nil {
				resp.Body.Close()
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	read := func() string {
		out, _ := exec.Command("docker", "exec", container, "cat", file).CombinedOutput()
		return string(out)
	}
	get()
	got := read()
	for _, w := range []string{`"logger":"http.log.access.gatewyn_access"`, `"uri":"/ping-journal"`, `"host":"log.localhost"`} {
		if !strings.Contains(got, w) {
			t.Fatalf("journal sans %s :\n%s", w, got)
		}
	}

	// Retiré : plus rien n'est écrit.
	if err := c.ApplyAll(ctx, hosts, caddyconf.Global{}); err != nil {
		t.Fatal(err)
	}
	before := len(read())
	get()
	time.Sleep(time.Second)
	if after := len(read()); after != before {
		t.Errorf("le journal grossit encore après son retrait (%d -> %d octets)", before, after)
	}
}
