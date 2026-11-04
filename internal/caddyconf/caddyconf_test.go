package caddyconf

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in      string
		dial    string
		tls     bool
		wantErr string
	}{
		{"http://192.0.2.21:8080", "192.0.2.21:8080", false, ""},
		{"http://wiki.internal", "wiki.internal:80", false, ""},
		{"https://192.0.2.30", "192.0.2.30:443", true, ""},
		{"https://app.internal:8443/", "app.internal:8443", true, ""},
		{"http://[2001:db8::1]:3000", "[2001:db8::1]:3000", false, ""},
		{" http://192.0.2.21:8080 ", "192.0.2.21:8080", false, ""},
		{"192.0.2.21:8080", "", false, "adresse invalide"},
		{"", "", false, "adresse invalide"},
		{"ftp://192.0.2.21", "", false, "non pris en charge"},
		{"http://192.0.2.21:8080/app", "", false, "chemin"},
		{"http://:8080", "", false, "hôte manquant"},
	}
	for _, tt := range tests {
		dial, tls, err := ParseTarget(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseTarget(%q) erreur = %v, attendu %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || dial != tt.dial || tls != tt.tls {
			t.Errorf("ParseTarget(%q) = %q, %v, %v ; attendu %q, %v", tt.in, dial, tls, err, tt.dial, tt.tls)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	ok := []string{"wiki.example.com", "a.b.example.com", "*.example.com", "xn--caf-dma.example.com", "my-app.example.com"}
	for _, d := range ok {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v, attendu valide", d, err)
		}
	}
	bad := []string{"", "localhost", "https://wiki.example.com", "wiki.example.com:8080", "wiki.example.com/path",
		"-bad.example.com", "bad-.example.com", "wiki..example.com", "wiki example.com", "WIKI.example.com ", "wiki_x.example.com"}
	for _, d := range bad {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) accepté, attendu une erreur", d)
		}
	}
}

// routeJSON extrait les routes du serveur Gatewyn dans la configuration produite.
func routes(t *testing.T, hosts []Host) []map[string]any {
	t.Helper()
	raw, err := JSON(hosts)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen []string         `json:"listen"`
					Routes []map[string]any `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	srv, ok := cfg.Apps.HTTP.Servers[ServerName]
	if !ok {
		t.Fatalf("serveur %q absent : %s", ServerName, raw)
	}
	if !reflect.DeepEqual(srv.Listen, []string{":443"}) {
		t.Errorf("listen = %v", srv.Listen)
	}
	return srv.Routes
}

func TestBuildOneHost(t *testing.T) {
	r := routes(t, []Host{{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"}})
	if len(r) != 1 {
		t.Fatalf("%d routes, attendu 1", len(r))
	}
	b, _ := json.Marshal(r[0])
	got := string(b)
	for _, want := range []string{`"host":["wiki.example.com"]`, `"handler":"reverse_proxy"`, `"dial":"192.0.2.21:8080"`, `"terminal":true`} {
		if !strings.Contains(got, want) {
			t.Errorf("route sans %s : %s", want, got)
		}
	}
	if strings.Contains(got, `"transport"`) {
		t.Errorf("transport TLS inattendu pour une cible http : %s", got)
	}
}

func TestBuildHTTPSTargetUsesTLSTransport(t *testing.T) {
	r := routes(t, []Host{{Domain: "nas.example.com", Target: "https://192.0.2.30:5001"}})
	b, _ := json.Marshal(r[0])
	if !strings.Contains(string(b), `"transport":{"protocol":"http","tls":{}}`) {
		t.Errorf("transport TLS absent : %s", b)
	}
}

func TestBuildDeterministicAndSorted(t *testing.T) {
	a := []Host{{Domain: "b.example.com", Target: "http://192.0.2.2"}, {Domain: "a.example.com", Target: "http://192.0.2.1"}}
	b := []Host{a[1], a[0]}
	ja, err := JSON(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, _ := JSON(b)
	if string(ja) != string(jb) {
		t.Errorf("la configuration dépend de l'ordre des hôtes")
	}
	r := routes(t, a)
	first, _ := json.Marshal(r[0])
	if !strings.Contains(string(first), "a.example.com") {
		t.Errorf("hôtes non triés : %s", first)
	}
}

func TestBuildNormalizesDomain(t *testing.T) {
	r := routes(t, []Host{{Domain: "  Wiki.Example.COM ", Target: "http://192.0.2.21"}})
	b, _ := json.Marshal(r[0])
	if !strings.Contains(string(b), `"host":["wiki.example.com"]`) {
		t.Errorf("domaine non normalisé : %s", b)
	}
}

func TestBuildSkipsDisabledButStillValidates(t *testing.T) {
	r := routes(t, []Host{{Domain: "off.example.com", Target: "http://192.0.2.9", Disabled: true}})
	if len(r) != 0 {
		t.Errorf("hôte désactivé publié : %v", r)
	}
	if _, err := Build([]Host{{Domain: "off.example.com", Target: "nimporte quoi", Disabled: true}}); err == nil {
		t.Error("cible invalide acceptée sur un hôte désactivé")
	}
}

func TestBuildEmpty(t *testing.T) {
	if r := routes(t, nil); len(r) != 0 {
		t.Errorf("routes = %v, attendu aucune", r)
	}
}

func TestBuildErrors(t *testing.T) {
	tests := []struct {
		name  string
		hosts []Host
		want  string
	}{
		{"doublon", []Host{{Domain: "a.example.com", Target: "http://192.0.2.1"}, {Domain: "A.example.com", Target: "http://192.0.2.2"}}, "en double"},
		{"domaine invalide", []Host{{Domain: "https://a.example.com", Target: "http://192.0.2.1"}}, "domaine invalide"},
		{"cible invalide", []Host{{Domain: "a.example.com", Target: "192.0.2.1"}}, "adresse invalide"},
	}
	for _, tt := range tests {
		_, err := Build(tt.hosts)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s : erreur = %v, attendu %q", tt.name, err, tt.want)
		}
	}
}

func TestBuildRedirect(t *testing.T) {
	r := routes(t, []Host{
		{Domain: "old.example.com", Kind: KindRedirect, Target: "https://new.example.org", Code: 301, PreservePath: true},
		{Domain: "short.example.com", Kind: KindRedirect, Target: "https://new.example.org/landing", Code: 302},
		{Domain: "default.example.com", Kind: KindRedirect, Target: "https://new.example.org"},
	})
	got := map[string]string{}
	for _, route := range r {
		b, _ := json.Marshal(route)
		for _, d := range []string{"old", "short", "default"} {
			if strings.Contains(string(b), d+".example.com") {
				got[d] = string(b)
			}
		}
	}
	for domain, wants := range map[string][]string{
		"old":     {`"handler":"static_response"`, `"status_code":301`, `"Location":["https://new.example.org{http.request.uri}"]`},
		"short":   {`"status_code":302`, `"Location":["https://new.example.org/landing"]`},
		"default": {`"status_code":301`, `"Location":["https://new.example.org"]`},
	} {
		for _, w := range wants {
			if !strings.Contains(got[domain], w) {
				t.Errorf("%s : route sans %s : %s", domain, w, got[domain])
			}
		}
	}
	if strings.Contains(got["old"], "reverse_proxy") {
		t.Error("une redirection ne doit pas contenir de reverse_proxy")
	}
}

func TestBuildNotFound(t *testing.T) {
	r := routes(t, []Host{{Domain: "gone.example.com", Kind: KindNotFound}})
	b, _ := json.Marshal(r[0])
	for _, w := range []string{`"handler":"static_response"`, `"status_code":404`, `"host":["gone.example.com"]`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("route 404 sans %s : %s", w, b)
		}
	}
}

func TestValidateRedirect(t *testing.T) {
	ok := []struct {
		domain, dest string
		code         int
		keep         bool
	}{
		{"a.example.com", "https://b.example.org", 301, true},
		{"a.example.com", "https://b.example.org/", 0, true},
		{"a.example.com", "http://b.example.org:8080", 302, true},
		{"a.example.com", "https://b.example.org/nouveau/chemin", 302, false},
		{"*.example.com", "https://autre.example.org", 301, true},
		{"a.example.com", "https://www.example.com", 301, true}, // autre nom : pas une boucle
	}
	for _, tt := range ok {
		if err := ValidateRedirect(tt.domain, tt.dest, tt.code, tt.keep); err != nil {
			t.Errorf("%+v refusé : %v", tt, err)
		}
	}
	bad := []struct {
		domain, dest string
		code         int
		keep         bool
		want         string
	}{
		{"a.example.com", "b.example.org", 301, true, "adresse invalide"},
		{"a.example.com", "ftp://b.example.org", 301, true, "adresse invalide"},
		{"a.example.com", "https://", 301, true, "adresse invalide"},
		{"a.example.com", "https://A.example.com/x", 301, false, "en boucle"},
		{"a.example.com", "https://a.example.com", 301, true, "en boucle"},
		{"a.example.com", "https://b.example.org/{http.request.host}", 301, false, "non autorisés"},
		{"a.example.com", "https://b.example.org/a b", 301, false, "non autorisés"},
		{"a.example.com", "https://user:pw@b.example.org", 301, true, "identifiant"},
		{"a.example.com", "https://b.example.org/page", 301, true, "garder le chemin"},
		{"a.example.com", "https://b.example.org/?x=1", 301, true, "garder le chemin"},
		{"a.example.com", "https://b.example.org", 307, true, "non pris en charge"},
	}
	for _, tt := range bad {
		if err := ValidateRedirect(tt.domain, tt.dest, tt.code, tt.keep); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%+v : erreur = %v, attendu %q", tt, err, tt.want)
		}
	}
}

func TestBuildValidatesPerKind(t *testing.T) {
	for _, h := range []Host{
		{Domain: "a.example.com", Kind: KindRedirect, Target: "pas une adresse"},
		{Domain: "a.example.com", Kind: "inconnu", Target: "http://192.0.2.1"},
		{Domain: "a.example.com", Kind: KindProxy, Target: "https://b.example.org"[:0]},
	} {
		if _, err := Build([]Host{h}); err == nil {
			t.Errorf("%+v accepté", h)
		}
	}
	// Une page 404 n'a pas de cible : elle est valide sans.
	if _, err := Build([]Host{{Domain: "gone.example.com", Kind: KindNotFound}}); err != nil {
		t.Errorf("404 refusé : %v", err)
	}
	// Un Kind vide reste un proxy (compatibilité avec les hôtes existants).
	r := routes(t, []Host{{Domain: "wiki.example.com", Target: "http://192.0.2.21"}})
	if b, _ := json.Marshal(r[0]); !strings.Contains(string(b), "reverse_proxy") {
		t.Errorf("Kind vide devenu autre chose : %s", b)
	}
}

func TestMixedKindsAreDeterministic(t *testing.T) {
	a := []Host{{Domain: "b.example.com", Kind: KindNotFound}, {Domain: "a.example.com", Kind: KindRedirect, Target: "https://x.example.org", PreservePath: true}, {Domain: "c.example.com", Target: "http://192.0.2.3"}}
	b := []Host{a[2], a[0], a[1]}
	ja, err := JSON(a)
	if err != nil {
		t.Fatal(err)
	}
	if jb, _ := JSON(b); string(ja) != string(jb) {
		t.Error("la configuration dépend de l'ordre des hôtes")
	}
}

func TestParseAddresses(t *testing.T) {
	got, err := ParseAddresses("192.0.2.9/24, 198.51.100.7\n2001:db8::1;10.0.0.0/8")
	if err != nil || strings.Join(got, " ") != "192.0.2.0/24 198.51.100.7 2001:db8::1 10.0.0.0/8" {
		t.Errorf("%v %v", got, err)
	}
	for _, bad := range []string{"", "  ", "example.com", "192.0.2.300", "192.0.2.0/33", "fe80::1%eth0"} {
		if _, err := ParseAddresses(bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestAccessAddsDenyRouteBeforeHostRoute(t *testing.T) {
	srv, err := BuildServer([]Host{
		{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080", Access: []string{"192.0.2.0/24", "198.51.100.7"}},
		{Domain: "open.example.com", Target: "http://192.0.2.22:8080"},
		{Domain: "old.example.com", Kind: KindNotFound, Access: []string{"192.0.2.0/24"}}, // ignoré hors service
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.Routes) != 4 {
		t.Fatalf("%d routes, attendu 4 (refus + service, service, 404)", len(srv.Routes))
	}
	raw, _ := json.Marshal(srv.Routes)
	var routes []struct {
		Match  []map[string]json.RawMessage `json:"match"`
		Handle []map[string]any             `json:"handle"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		t.Fatal(err)
	}
	deny := routes[2] // tri par domaine : old, open, wiki (refus), wiki
	if string(deny.Match[0]["not"]) != `[{"client_ip":{"ranges":["192.0.2.0/24","198.51.100.7"]}}]` || fmt.Sprint(deny.Handle[0]["status_code"]) != "403" {
		t.Errorf("route de refus : %s %v", deny.Match[0]["not"], deny.Handle[0])
	}
	if routes[0].Match[0]["not"] != nil || routes[1].Match[0]["not"] != nil || routes[2].Match[0]["not"] == nil || routes[3].Match[0]["not"] != nil {
		t.Errorf("la route de refus doit précéder celle de wiki.example.com : %s", raw)
	}
}

func TestTLSJSONGroupsHostsByDNSAccount(t *testing.T) {
	ovh := &DNSChallenge{Account: 2, Provider: map[string]any{"name": "ovh", "endpoint": "ovh-eu", "application_key": "ak"}}
	cf := &DNSChallenge{Account: 1, Provider: map[string]any{"name": "cloudflare", "api_token": "jeton-fictif"}}
	got, err := TLSJSON([]Host{
		{Domain: "b.example.com", Target: "http://192.0.2.1:80", DNS: ovh},
		{Domain: "*.example.org", Kind: KindNotFound, DNS: ovh},
		{Domain: "c.example.com", Target: "http://192.0.2.2:80", DNS: cf},
		{Domain: "http.example.com", Target: "http://192.0.2.3:80"},
		{Domain: "off.example.com", Target: "http://192.0.2.4:80", DNS: cf, Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"policies":[` +
		`{"subjects":["c.example.com"],"issuers":[{"challenges":{"dns":{"provider":{"api_token":"jeton-fictif","name":"cloudflare"}}},"module":"acme"}]},` +
		`{"subjects":["*.example.org","b.example.com"],"issuers":[{"challenges":{"dns":{"provider":{"application_key":"ak","endpoint":"ovh-eu","name":"ovh"}}},"module":"acme"}]}]}`
	if !sameJSON(t, got, []byte(want)) {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	// Sans compte DNS : aucune règle, Caddy garde son comportement par défaut.
	none, _ := TLSJSON([]Host{{Domain: "a.example.com", Target: "http://192.0.2.1:80"}})
	if string(none) != "{}" {
		t.Errorf("sans DNS : %s", none)
	}
}

func TestHTTPOnlyHostsGoToTheHTTPServerWithoutCertificate(t *testing.T) {
	dns := &DNSChallenge{Account: 1, Provider: map[string]any{"name": "ovh"}}
	hosts := []Host{
		{Domain: "b.example.com", Aliases: []string{"bb.example.com"}, Target: "http://192.0.2.1:80", HTTPOnly: true, DNS: dns, HSTS: 1},
		{Domain: "a.example.com", Target: "http://192.0.2.2:80"},
		{Domain: "off.example.com", Target: "http://192.0.2.3:80", HTTPOnly: true, Disabled: true},
	}
	https, err := BuildServer(hosts)
	if err != nil || len(https.Routes) != 1 || strings.Join(https.Listen, "") != ":443" {
		t.Fatalf("serveur HTTPS : %+v %v", https, err)
	}
	httpSrv, err := BuildHTTPServer(hosts)
	if err != nil || httpSrv == nil || len(httpSrv.Routes) != 1 || strings.Join(httpSrv.Listen, "") != ":80" {
		t.Fatalf("serveur HTTP : %+v %v", httpSrv, err)
	}
	raw, _ := json.Marshal(httpSrv)
	if !strings.Contains(string(raw), `"host":["b.example.com","bb.example.com"]`) || strings.Contains(string(raw), "Strict-Transport-Security") {
		t.Errorf("serveur HTTP : %s", raw)
	}
	// Pas de certificat, donc pas de règle de défi DNS.
	if got, _ := TLSJSON(hosts); string(got) != "{}" {
		t.Errorf("TLSJSON : %s", got)
	}
	// Sans hôte en HTTP seulement : pas de serveur HTTP.
	if srv, err := BuildHTTPServer(hosts[1:2]); srv != nil || err != nil {
		t.Errorf("serveur HTTP inattendu : %+v %v", srv, err)
	}
	// Un domaine reste unique même entre les deux serveurs.
	if _, err := BuildServer([]Host{hosts[0], {Domain: "bb.example.com", Target: "http://192.0.2.9:80"}}); err == nil {
		t.Error("domaine en double entre HTTP et HTTPS accepté")
	}
}

func TestSelfSignedHostsGetTheInternalIssuer(t *testing.T) {
	got, err := TLSJSON([]Host{
		{Domain: "z.example.com", Target: "http://192.0.2.1:80", SelfSigned: true},
		{Domain: "a.example.com", Aliases: []string{"b.example.com"}, Kind: KindNotFound, SelfSigned: true},
		{Domain: "c.example.com", Target: "http://192.0.2.3:80"},
		{Domain: "off.example.com", Target: "http://192.0.2.4:80", SelfSigned: true, Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"policies":[{"subjects":["a.example.com","b.example.com","z.example.com"],"issuers":[{"module":"internal"}]}]}`
	if string(got) != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

func TestAliasesShareTheHostRouteCertificateAndRules(t *testing.T) {
	ovh := &DNSChallenge{Account: 1, Provider: map[string]any{"name": "ovh"}}
	hosts := []Host{
		{Domain: "wiki.example.com", Aliases: []string{"Docs.Example.com", " wiki.example.org "}, Target: "http://192.0.2.1:80", DNS: ovh, Access: []string{"192.0.2.0/24"}},
		{Domain: "old.example.com", Aliases: []string{"older.example.com"}, Kind: KindNotFound},
	}
	srv, err := BuildServer(hosts)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(srv)
	for _, want := range []string{
		`"host":["wiki.example.com","docs.example.com","wiki.example.org"]`, // route du service et route de refus
		`"host":["old.example.com","older.example.com"]`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("serveur sans %s :\n%s", want, raw)
		}
	}
	if len(srv.Routes) != 3 { // refus + service, 404
		t.Errorf("%d routes", len(srv.Routes))
	}
	tls, _ := TLSJSON(hosts)
	if !strings.Contains(string(tls), `"subjects":["docs.example.com","wiki.example.com","wiki.example.org"]`) {
		t.Errorf("sujets du certificat : %s", tls)
	}
}

func TestAliasValidationAndDuplicates(t *testing.T) {
	for name, hosts := range map[string][]Host{
		"alias invalide":        {{Domain: "a.example.com", Aliases: []string{"pas un domaine"}, Target: "http://192.0.2.1:80"}},
		"alias = domaine":       {{Domain: "a.example.com", Aliases: []string{"A.example.com"}, Target: "http://192.0.2.1:80"}},
		"alias d'un autre hôte": {{Domain: "a.example.com", Target: "http://192.0.2.1:80"}, {Domain: "b.example.com", Aliases: []string{"a.example.com"}, Target: "http://192.0.2.2:80"}},
		"boucle sur un alias":   {{Domain: "a.example.com", Aliases: []string{"b.example.org"}, Kind: KindRedirect, Target: "https://b.example.org"}},
	} {
		if _, err := BuildServer(hosts); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestHSTSHeaderIsSetBeforeTheHostHandler(t *testing.T) {
	srv, err := BuildServer([]Host{
		{Domain: "a.example.com", Target: "http://192.0.2.1:80", HSTS: 1},
		{Domain: "b.example.com", Kind: KindNotFound, HSTS: 2},
		{Domain: "c.example.com", Target: "http://192.0.2.3:80"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var routes []struct {
		Handle []map[string]any `json:"handle"`
	}
	raw, _ := json.Marshal(srv.Routes)
	if err := json.Unmarshal(raw, &routes); err != nil {
		t.Fatal(err)
	}
	if len(routes[0].Handle) != 2 || routes[0].Handle[0]["handler"] != "headers" || routes[0].Handle[1]["handler"] != "reverse_proxy" {
		t.Fatalf("service avec HSTS : %v", routes[0].Handle)
	}
	if len(routes[2].Handle) != 1 {
		t.Errorf("service sans HSTS : %v", routes[2].Handle)
	}
	for i, want := range []string{`"Strict-Transport-Security":["max-age=31536000"]`, `"Strict-Transport-Security":["max-age=31536000; includeSubDomains"]`} {
		b, _ := json.Marshal(routes[i].Handle[0])
		if !strings.Contains(string(b), want) {
			t.Errorf("route %d : %s, attendu %s", i, b, want)
		}
	}
}

func TestLocationsAreRoutedBeforeTheHostRouteLongestPathFirst(t *testing.T) {
	srv, err := BuildServer([]Host{{
		Domain: "wiki.example.com", Target: "http://192.0.2.1:80", HSTS: 1, Access: []string{"192.0.2.0/24"},
		Locations: []Location{{Path: "/api", Target: "http://192.0.2.5:3000"}, {Path: "/api/v2", Target: "https://192.0.2.6:8443"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(srv.Routes)
	var routes []struct {
		Match  []map[string]json.RawMessage `json:"match"`
		Handle []map[string]any             `json:"handle"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		t.Fatal(err)
	}
	// Chaque chemin hérite de la liste de l'hôte : refus puis route pour /api/v2, idem /api, puis refus et route de l'hôte.
	if len(routes) != 6 {
		t.Fatalf("%d routes : %s", len(routes), raw)
	}
	for i, want := range []struct {
		path string
		deny bool
	}{{`["/api/v2","/api/v2/*"]`, true}, {`["/api/v2","/api/v2/*"]`, false}, {`["/api","/api/*"]`, true}, {`["/api","/api/*"]`, false}, {"", true}, {"", false}} {
		if got := string(routes[i].Match[0]["path"]); got != want.path {
			t.Errorf("route %d : chemin %q, attendu %q", i, got, want.path)
		}
		if (routes[i].Match[0]["not"] != nil) != want.deny {
			t.Errorf("route %d : refus = %v, attendu %v", i, routes[i].Match[0]["not"] != nil, want.deny)
		}
		if string(routes[i].Match[0]["host"]) != `["wiki.example.com"]` {
			t.Errorf("route %d sans le nom d'hôte", i)
		}
	}
	// Cible propre à chaque chemin, HSTS conservé.
	if !strings.Contains(string(raw), `"dial":"192.0.2.6:8443"`) || !strings.Contains(string(raw), `"dial":"192.0.2.5:3000"`) || strings.Count(string(raw), "Strict-Transport-Security") != 3 { // 2 chemins + hôte
		t.Errorf("cibles ou HSTS : %s", raw)
	}
}

func TestLocationValidation(t *testing.T) {
	for _, bad := range []string{"", "/", "api", "/api/", "/a b", "/a{b}", "/a*", "/a//b", "/a/../b", "/é"} {
		if ValidatePath(bad) == nil {
			t.Errorf("chemin %q accepté", bad)
		}
	}
	for _, ok := range []string{"/api", "/a/b", "/v1.2/x_y-z~"} {
		if err := ValidatePath(ok); err != nil {
			t.Errorf("chemin %q refusé : %v", ok, err)
		}
	}
	if err := ValidateLocations([]Location{{Path: "/api", Target: "http://a:1"}, {Path: "/api", Target: "http://b:2"}}); err == nil {
		t.Error("chemin en double accepté")
	}
	if err := ValidateLocations([]Location{{Path: "/api", Target: "pas une adresse"}}); err == nil {
		t.Error("cible invalide acceptée")
	}
}

func TestLocationAccessInheritsOverridesOrOpens(t *testing.T) {
	host := []string{"192.0.2.0/24"}
	srv, err := BuildServer([]Host{{
		Domain: "wiki.example.com", Target: "http://192.0.2.1:80", Access: host,
		Locations: []Location{
			{Path: "/inherit", Target: "http://192.0.2.5:80"},
			{Path: "/open", Target: "http://192.0.2.6:80", Public: true},
			{Path: "/own", Target: "http://192.0.2.7:80", Access: []string{"198.51.100.0/24"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(srv.Routes)
	var routes []struct {
		Match []map[string]json.RawMessage `json:"match"`
	}
	json.Unmarshal(raw, &routes)
	type route struct{ path, ranges string }
	var got []route
	for _, r := range routes {
		var rg string
		if n := r.Match[0]["not"]; n != nil {
			rg = string(n)
		}
		got = append(got, route{string(r.Match[0]["path"]), rg})
	}
	want := []route{
		{`["/inherit","/inherit/*"]`, `[{"client_ip":{"ranges":["192.0.2.0/24"]}}]`}, {`["/inherit","/inherit/*"]`, ""},
		{`["/open","/open/*"]`, ""}, // public : aucune route de refus
		{`["/own","/own/*"]`, `[{"client_ip":{"ranges":["198.51.100.0/24"]}}]`}, {`["/own","/own/*"]`, ""},
		{"", `[{"client_ip":{"ranges":["192.0.2.0/24"]}}]`}, {"", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("%d routes, attendu %d :\n%s", len(got), len(want), raw)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("route %d : %+v, attendu %+v", i, got[i], want[i])
		}
	}
	// Sans liste sur l'hôte, un chemin peut quand même avoir la sienne.
	srv, _ = BuildServer([]Host{{Domain: "a.example.com", Target: "http://192.0.2.1:80",
		Locations: []Location{{Path: "/admin", Target: "http://192.0.2.5:80", Access: host}}}})
	if len(srv.Routes) != 3 { // refus /admin, /admin, hôte (public)
		t.Errorf("%d routes", len(srv.Routes))
	}
}

func TestHostOptionsHeadersCompressionAndStreaming(t *testing.T) {
	srv, err := BuildServer([]Host{
		{Domain: "a.example.com", Target: "http://192.0.2.1:80", Compress: true, NoBuffering: true, FrameOptions: "DENY", NoIndex: true, HSTS: 1, CrowdSec: true},
		{Domain: "b.example.com", Kind: KindNotFound, Compress: true, FrameOptions: "SAMEORIGIN"}, // pas de compression hors service
		{Domain: "c.example.com", Target: "http://192.0.2.3:80", FrameOptions: "n'importe quoi"},  // valeur inconnue ignorée
	})
	if err != nil {
		t.Fatal(err)
	}
	var routes []struct {
		Handle []map[string]any `json:"handle"`
	}
	raw, _ := json.Marshal(srv.Routes)
	json.Unmarshal(raw, &routes)
	order := func(r int) []string {
		var out []string
		for _, h := range routes[r].Handle {
			out = append(out, h["handler"].(string))
		}
		return out
	}
	// Ordre : CrowdSec, en-têtes (un seul gestionnaire), compression, puis le service.
	if got := strings.Join(order(0), " "); got != "crowdsec headers encode reverse_proxy" {
		t.Errorf("service : %s", got)
	}
	if got := strings.Join(order(1), " "); got != "headers static_response" {
		t.Errorf("404 : %s", got)
	}
	if got := strings.Join(order(2), " "); got != "reverse_proxy" {
		t.Errorf("service sans option : %s", got)
	}
	for _, want := range []string{`"Strict-Transport-Security":["max-age=31536000"]`, `"X-Frame-Options":["DENY"]`, `"X-Robots-Tag":["noindex"]`, `"flush_interval":-1`, `"encodings":{"zstd":{},"gzip":{}}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("configuration sans %s", want)
		}
	}
	if strings.Contains(string(raw), "n'importe quoi") || strings.Count(string(raw), `"encode"`) != 1 {
		t.Errorf("valeur inconnue publiée ou compression en trop : %s", raw)
	}
}

func TestH2CTargetUsesHTTP2WithoutTLS(t *testing.T) {
	dial, tls, err := ParseTarget("h2c://192.0.2.5:50051")
	if err != nil || dial != "192.0.2.5:50051" || tls || !IsH2C("h2c://192.0.2.5:50051") || IsH2C("http://a:1") {
		t.Errorf("%q %v %v", dial, tls, err)
	}
	srv, err := BuildServer([]Host{{Domain: "grpc.example.com", Target: "h2c://192.0.2.5:50051"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(srv.Routes)
	if !strings.Contains(string(raw), `"versions":["h2c"]`) || strings.Contains(string(raw), `"tls"`) {
		t.Errorf("transport h2c : %s", raw)
	}
	if _, _, err := ParseTarget("ftp://a:1"); err == nil || !strings.Contains(err.Error(), "h2c") {
		t.Errorf("message de protocole : %v", err)
	}
}

func TestLocationStripPathAddsARewriteBeforeTheProxy(t *testing.T) {
	srv, _ := BuildServer([]Host{{Domain: "a.example.com", Target: "http://192.0.2.1:80", Locations: []Location{
		{Path: "/api", Target: "http://192.0.2.5:3000", StripPath: true},
		{Path: "/raw", Target: "http://192.0.2.6:3000"},
	}}})
	var routes []struct {
		Match  []map[string]json.RawMessage `json:"match"`
		Handle []map[string]any             `json:"handle"`
	}
	raw, _ := json.Marshal(srv.Routes)
	json.Unmarshal(raw, &routes)
	for _, r := range routes {
		path := string(r.Match[0]["path"])
		var kinds []string
		for _, h := range r.Handle {
			kinds = append(kinds, h["handler"].(string))
		}
		switch {
		case strings.HasPrefix(path, `["/api"`):
			if strings.Join(kinds, " ") != "rewrite reverse_proxy" || r.Handle[0]["strip_path_prefix"] != "/api" {
				t.Errorf("/api : %v %v", kinds, r.Handle[0])
			}
		case strings.HasPrefix(path, `["/raw"`):
			if strings.Join(kinds, " ") != "reverse_proxy" {
				t.Errorf("/raw : %v", kinds)
			}
		}
	}
}

func TestTrustedProxiesAreSetOnBothServersAndNothingByDefault(t *testing.T) {
	hosts := []Host{{Domain: "a.example.com", Target: "http://192.0.2.1:80"}, {Domain: "b.example.com", Target: "http://192.0.2.2:80", HTTPOnly: true}}
	g := Global{TrustedProxies: []string{"173.245.48.0/20", "192.0.2.7"}}
	for name, build := range map[string]func() (*Server, error){
		"HTTPS": func() (*Server, error) { return BuildServer(hosts, g) },
		"HTTP":  func() (*Server, error) { return BuildHTTPServer(hosts, g) },
	} {
		srv, err := build()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(srv)
		var parsed struct {
			TrustedProxies map[string]any `json:"trusted_proxies"`
			Strict         int            `json:"trusted_proxies_strict"`
		}
		json.Unmarshal(raw, &parsed)
		if !reflect.DeepEqual(parsed.TrustedProxies, map[string]any{"source": "static", "ranges": []any{"173.245.48.0/20", "192.0.2.7"}}) || parsed.Strict != 1 {
			t.Errorf("serveur %s : %s", name, raw)
		}
	}
	srv, _ := BuildServer(hosts)
	if raw, _ := json.Marshal(srv); strings.Contains(string(raw), "trusted_proxies") {
		t.Errorf("proxies de confiance sans réglage : %s", raw)
	}
}

func TestAppSecHandlerFollowsCrowdSecAndAppConfigCarriesAppSec(t *testing.T) {
	srv, err := BuildServer([]Host{
		{Domain: "a.example.com", Target: "http://192.0.2.1:80", CrowdSec: true, WAF: true},
		{Domain: "b.example.com", Target: "http://192.0.2.2:80", CrowdSec: true}, // CrowdSec sans WAF
		{Domain: "c.example.com", Target: "http://192.0.2.3:80", WAF: true},      // WAF sans CrowdSec : ignoré
		{Domain: "d.example.com", Kind: KindNotFound, CrowdSec: true, WAF: true}, // pas un service : pas de WAF
		{Domain: "e.example.com", Target: "http://192.0.2.5:80", CrowdSec: true, WAF: true, Compress: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var routes []struct {
		Handle []map[string]any `json:"handle"`
	}
	raw, _ := json.Marshal(srv.Routes)
	json.Unmarshal(raw, &routes)
	var got []string
	for _, r := range routes {
		var kinds []string
		for _, h := range r.Handle {
			kinds = append(kinds, h["handler"].(string))
		}
		got = append(got, strings.Join(kinds, " "))
	}
	want := []string{"crowdsec appsec reverse_proxy", "crowdsec reverse_proxy", "reverse_proxy", "crowdsec static_response", "crowdsec appsec encode reverse_proxy"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("route %d : %q, attendu %q", i, got[i], want[i])
		}
	}

	with, _ := CrowdSecJSON(CrowdSec{URL: "http://crowdsec:8080", Key: "cle", AppSecURL: "http://crowdsec:7422", AppSecFailOpen: true})
	without, _ := CrowdSecJSON(CrowdSec{URL: "http://crowdsec:8080", Key: "cle", AppSecFailOpen: true})
	closed, _ := CrowdSecJSON(CrowdSec{URL: "http://crowdsec:8080", Key: "cle", AppSecURL: "http://crowdsec:7422"})
	if !strings.Contains(string(with), `"appsec_url":"http://crowdsec:7422"`) || !strings.Contains(string(with), `"appsec_fail_open":true`) {
		t.Errorf("avec AppSec : %s", with)
	}
	if strings.Contains(string(without), "appsec") {
		t.Errorf("sans AppSec : %s", without)
	}
	if !strings.Contains(string(closed), `"appsec_fail_open":false`) {
		t.Errorf("refus si AppSec tombe : %s", closed)
	}
}

// Un chemin sans cible garde le service de l'hôte : seule sa règle d'accès change.
func TestLocationWithoutTargetUsesTheHostTarget(t *testing.T) {
	srv, err := BuildServer([]Host{{
		Domain: "bw.example.com", Target: "http://192.0.2.1:80",
		Locations: []Location{{Path: "/admin", Access: []string{"198.51.100.0/24"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(srv.Routes)
	if n := strings.Count(string(raw), `"dial":"192.0.2.1:80"`); n != 2 {
		t.Errorf("la cible de l'hôte doit servir /admin et le reste (%d fois) :\n%s", n, raw)
	}
	if !strings.Contains(string(raw), `["/admin","/admin/*"]`) || !strings.Contains(string(raw), `198.51.100.0/24`) {
		t.Errorf("règle d'accès de /admin absente :\n%s", raw)
	}
	if err := ValidateLocations([]Location{{Path: "/admin"}}); err != nil {
		t.Errorf("chemin sans cible refusé : %v", err)
	}
}

// sameJSON compare deux JSON sans tenir compte de l'ordre des clés.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}
