package caddyconf

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// goldenScenarios couvre toutes les branches de la génération : chaque entrée donne le JSON
// que Caddy reçoit. Le fichier testdata/golden.json le fige ; GATEWYN_UPDATE_GOLDEN=1 le réécrit.
func goldenScenarios(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	ovh := &DNSChallenge{Account: 1, Provider: map[string]any{"name": "ovh", "endpoint": "ovh-eu", "application_key": "ak-fictif", "application_secret": "as-fictif", "consumer_key": "ck-fictif"}}
	hostSets := map[string][]Host{
		"proxy simple":      {{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"}},
		"proxy https":       {{Domain: "nas.example.com", Target: "https://192.0.2.30"}},
		"proxy h2c":         {{Domain: "grpc.example.com", Target: "h2c://192.0.2.31:50051"}},
		"proxy options":     {{Domain: "app.example.com", Target: "http://192.0.2.22:3000", Compress: true, NoBuffering: true, FrameOptions: "SAMEORIGIN", NoIndex: true, HSTS: 2}},
		"proxy hsts simple": {{Domain: "app.example.com", Target: "http://192.0.2.22:3000", HSTS: 1, FrameOptions: "DENY"}},
		"proxy alias":       {{Domain: "wiki.example.com", Aliases: []string{"docs.example.com", "*.wiki.example.com"}, Target: "http://192.0.2.21:8080"}},
		"proxy acces":       {{Domain: "admin.example.com", Target: "http://192.0.2.23:80", Access: []string{"192.0.2.0/24", "198.51.100.7"}}},
		"proxy crowdsec":    {{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080", CrowdSec: true, Compress: true}},
		"proxy waf":         {{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080", CrowdSec: true, WAF: true, NoIndex: true}},
		"chemins": {{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080", Access: []string{"192.0.2.0/24"}, Locations: []Location{
			{Path: "/api", Target: "https://192.0.2.6:8443", StripPath: true},
			{Path: "/api/v2", Target: "http://192.0.2.7:9000"},
			{Path: "/public", Public: true},
			{Path: "/admin", Access: []string{"198.51.100.0/24"}},
			{Path: "/static"},
		}, CrowdSec: true, Compress: true, FrameOptions: "DENY"}},
		"redirection permanente": {{Domain: "old.example.com", Kind: KindRedirect, Target: "https://new.example.org", PreservePath: true}},
		"redirection temporaire": {{Domain: "old.example.com", Aliases: []string{"older.example.com"}, Kind: KindRedirect, Target: "https://new.example.org/", Code: 302, HSTS: 1, NoIndex: true}},
		"erreur 404":             {{Domain: "gone.example.com", Kind: KindNotFound, NoIndex: true, CrowdSec: true}},
		"desactive":              {{Domain: "off.example.com", Target: "http://192.0.2.9:80", Disabled: true}, {Domain: "on.example.com", Target: "http://192.0.2.10:80"}},
		"defi dns":               {{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080", DNS: ovh}, {Domain: "*.example.org", Kind: KindNotFound, DNS: ovh}, {Domain: "blog.example.com", Target: "http://192.0.2.22:80"}},
		"auto-signe":             {{Domain: "lan.example.com", Target: "http://192.0.2.22:8080", SelfSigned: true}, {Domain: "lan2.example.com", Aliases: []string{"lan3.example.com"}, Target: "http://192.0.2.23:8080", SelfSigned: true}},
		"http seulement":         {{Domain: "plain.example.com", Target: "http://192.0.2.23:8080", HTTPOnly: true, HSTS: 1}, {Domain: "secure.example.com", Target: "http://192.0.2.24:8080"}},
		"melange": {
			{Domain: "b.example.com", Target: "http://192.0.2.2:80"},
			{Domain: "a.example.com", Target: "http://192.0.2.1:80", DNS: ovh},
			{Domain: "r.example.com", Kind: KindRedirect, Target: "https://x.example.org", PreservePath: true},
			{Domain: "n.example.com", Kind: KindNotFound},
			{Domain: "h.example.com", Target: "http://192.0.2.3:80", HTTPOnly: true},
		},
		"vide": nil,
	}
	globals := map[string]Global{
		"sans reglage":    {},
		"proxies":         {TrustedProxies: []string{"173.245.48.0/20", "192.0.2.7"}},
		"journal":         {AccessLog: &AccessLog{File: "/data/logs/access.log", KeepDays: 30}},
		"tout":            {TrustedProxies: []string{"192.0.2.7"}, AccessLog: &AccessLog{File: "/tmp/a.log", KeepDays: 7}, CrowdSec: &CrowdSec{URL: "http://crowdsec:8080", Key: "cle-fictive"}},
		"crowdsec appsec": {CrowdSec: &CrowdSec{URL: "http://crowdsec:8080", Key: "cle-fictive", AppSecURL: "http://crowdsec:7422", AppSecFailOpen: true}},
	}

	out := map[string]json.RawMessage{}
	put := func(name string, b []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		if b == nil {
			out[name] = json.RawMessage("null")
			return
		}
		out[name] = b
	}
	for hn, hosts := range hostSets {
		b, err := ServerJSON(hosts)
		put("serveur HTTPS / "+hn, b, err)
		b, err = HTTPServerJSON(hosts)
		put("serveur HTTP / "+hn, b, err)
		b, err = TLSJSON(hosts)
		put("tls / "+hn, b, err)
		for gn, g := range globals {
			b, err = ServerJSON(hosts, g)
			put("serveur HTTPS / "+hn+" / "+gn, b, err)
			b, err = HTTPServerJSON(hosts, g)
			put("serveur HTTP / "+hn+" / "+gn, b, err)
		}
		b, err = JSON(hosts)
		put("configuration complète / "+hn, b, err)
	}
	for gn, g := range globals {
		if g.CrowdSec != nil {
			b, err := CrowdSecJSON(*g.CrowdSec)
			put("crowdsec / "+gn, b, err)
		}
		if g.AccessLog != nil {
			b, err := AccessLogJSON(*g.AccessLog)
			put("journal / "+gn, b, err)
		}
	}
	return out
}

// TestGolden vérifie que la configuration produite reste exactement celle qui a été
// contrôlée sur un Caddy réel : même JSON, à l'ordre des clés près.
func TestGolden(t *testing.T) {
	got := goldenScenarios(t)
	const path = "testdata/golden.json"
	if os.Getenv("GATEWYN_UPDATE_GOLDEN") == "1" {
		b, err := json.MarshalIndent(got, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skipf("référence réécrite : %d scénarios", len(got))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]json.RawMessage
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Errorf("%d scénarios attendus, %d produits", len(want), len(got))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("scénario %q absent", name)
			continue
		}
		var wa, ga any
		if err := json.Unmarshal(w, &wa); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(g, &ga); err != nil {
			t.Fatalf("%s : JSON invalide : %v", name, err)
		}
		if !reflect.DeepEqual(wa, ga) {
			t.Errorf("scénario %q différent\n attendu : %s\n produit : %s", name, w, g)
		}
	}
}
