package caddyadmin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jogit/gatewyn/internal/caddyconf"
)

func TestApplySendsServerOnly(t *testing.T) {
	var method, path, ctype, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete { // retrait du serveur HTTP, absent ici
			return
		}
		method, path, ctype = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()

	err := New(srv.URL+"/").Apply(context.Background(), []caddyconf.Host{{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || path != "/config/apps/http/servers/gatewyn" {
		t.Errorf("requête %s %s", method, path)
	}
	if ctype != "application/json" {
		t.Errorf("Content-Type = %q", ctype)
	}
	if !strings.Contains(body, `"dial":"192.0.2.21:8080"`) || strings.Contains(body, `"admin"`) {
		t.Errorf("corps inattendu : %s", body)
	}
}

func TestApplyReplacesWhenServerExists(t *testing.T) {
	var methods, paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error":"key already exists: gatewyn"}`)
		}
	}))
	defer srv.Close()
	if err := New(srv.URL).Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// Règles de certificat puis serveur, chacun en PUT puis PATCH (409), puis retrait du serveur
	// HTTP (aucun hôte en HTTP seulement), du journal d'accès et de CrowdSec (non demandés).
	if !reflect.DeepEqual(methods, []string{http.MethodPut, http.MethodPatch, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodDelete, http.MethodDelete}) {
		t.Errorf("méthodes = %v, attendu PUT puis PATCH pour chaque élément, puis DELETE ×3", methods)
	}
	if paths[0] != "/config/apps/tls/automation" || paths[2] != "/config/apps/http/servers/gatewyn" {
		t.Errorf("chemins = %v", paths)
	}
}

func TestApplyInvalidHostNeverCallsCaddy(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	err := New(srv.URL).Apply(context.Background(), []caddyconf.Host{{Domain: "pas un domaine", Target: "http://192.0.2.1"}})
	if err == nil || called {
		t.Errorf("err = %v, appel = %v ; attendu une erreur sans appel", err, called)
	}
}

func TestAPIErrorKeepsCaddyMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":"loading new config: unknown module"}`)
	}))
	defer srv.Close()
	err := New(srv.URL).Apply(context.Background(), nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 || apiErr.Message != "loading new config: unknown module" {
		t.Errorf("erreur = %#v", err)
	}
}

func TestUnreachableCaddy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	err := New(url).Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "impossible de joindre Caddy") {
		t.Errorf("erreur = %v", err)
	}
}

func TestHostsRoundTrip(t *testing.T) {
	hosts := []caddyconf.Host{
		{Domain: "nas.example.com", Target: "https://192.0.2.30:5001"},
		{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"},
	}
	body, err := caddyconf.ServerJSON(hosts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	got, err := New(srv.URL).Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, hosts) {
		t.Errorf("hôtes relus = %+v, attendu %+v", got, hosts)
	}
}

func TestHostsWhenServerAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "null") }))
	defer srv.Close()
	got, err := New(srv.URL).Hosts(context.Background())
	if err != nil || len(got) != 0 {
		t.Errorf("hôtes = %v, err = %v ; attendu liste vide", got, err)
	}
}

func TestHostsRoundTripAllKinds(t *testing.T) {
	hosts := []caddyconf.Host{
		{Domain: "gone.example.com", Kind: caddyconf.KindNotFound},
		{Domain: "keep.example.com", Kind: caddyconf.KindRedirect, Target: "https://example.org", Code: 301, PreservePath: true},
		{Domain: "nas.example.com", Target: "https://192.0.2.30:5001"},
		{Domain: "temp.example.com", Kind: caddyconf.KindRedirect, Target: "https://example.org/landing", Code: 302},
		{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"},
	}
	body, err := caddyconf.ServerJSON(hosts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	got, err := New(srv.URL).Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, hosts) {
		t.Errorf("hôtes relus = %+v\nattendu     %+v", got, hosts)
	}
}

func TestApplyPublishesTheHTTPServerForHTTPOnlyHosts(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
	}))
	defer srv.Close()
	err := New(srv.URL).Apply(context.Background(), []caddyconf.Host{
		{Domain: "secure.example.com", Target: "http://192.0.2.1:80"},
		{Domain: "plain.example.com", Target: "http://192.0.2.2:80", HTTPOnly: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /config/apps/tls/automation", "PUT /config/apps/http/servers/gatewyn", "PUT /config/apps/http/servers/gatewyn-http", "DELETE /config/logging/logs/gatewyn_access", "DELETE /config/apps/crowdsec"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("appels = %v, attendu %v", calls, want)
	}
}

func TestApplyAllPublishesTheCrowdSecAppFirstAndRemovesItLast(t *testing.T) {
	var calls []string
	var csBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/config/apps/crowdsec" && r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			csBody = string(b)
		}
	}))
	defer srv.Close()
	hosts := []caddyconf.Host{{Domain: "a.example.com", Target: "http://192.0.2.1:80", CrowdSec: true}}

	if err := New(srv.URL).ApplyAll(context.Background(), hosts, caddyconf.Global{CrowdSec: &caddyconf.CrowdSec{URL: "http://crowdsec:8080", Key: "cle-fictive"}}); err != nil {
		t.Fatal(err)
	}
	if calls[0] != "PUT /config/apps/crowdsec" || calls[len(calls)-1] == "DELETE /config/apps/crowdsec" {
		t.Errorf("avec CrowdSec : %v", calls)
	}
	if !strings.Contains(csBody, `"api_url":"http://crowdsec:8080"`) || !strings.Contains(csBody, `"api_key":"cle-fictive"`) || !strings.Contains(csBody, `"enable_streaming":true`) {
		t.Errorf("application CrowdSec : %s", csBody)
	}

	calls = nil
	if err := New(srv.URL).ApplyAll(context.Background(), hosts, caddyconf.Global{}); err != nil {
		t.Fatal(err)
	}
	// Retrait : les routes d'abord, l'application en dernier.
	if calls[len(calls)-1] != "DELETE /config/apps/crowdsec" || calls[0] == "PUT /config/apps/crowdsec" {
		t.Errorf("sans CrowdSec : %v", calls)
	}
}

func TestCrowdSecStatusReadsCaddyAdminEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { // comme le module de Caddy
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/crowdsec/health":
			io.WriteString(w, `{"ok":true}`)
		case "/crowdsec/info":
			io.WriteString(w, `{"streaming":{"enabled":true,"interval":"10s"},"number_of_active_decisions":14}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	st, err := New(srv.URL).CrowdSecStatus(context.Background())
	if err != nil || !st.Healthy || !st.Streaming || st.Interval != "10s" || st.Decisions != 14 {
		t.Errorf("%+v %v", st, err)
	}
	// Bouncer absent de Caddy : erreur.
	srv2 := httptest.NewServer(http.NotFoundHandler())
	defer srv2.Close()
	if _, err := New(srv2.URL).CrowdSecStatus(context.Background()); err == nil {
		t.Error("bouncer absent accepté")
	}
}

func TestApplyAllPublishesTheAccessLogBeforeTheServersAndRemovesItAfter(t *testing.T) {
	var calls []string
	bodies := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		bodies[r.URL.Path] = string(b)
	}))
	defer srv.Close()
	hosts := []caddyconf.Host{{Domain: "a.example.com", Target: "http://192.0.2.1:80"}}

	g := caddyconf.Global{AccessLog: &caddyconf.AccessLog{File: "/data/logs/access.log", KeepDays: 30}}
	if err := New(srv.URL).ApplyAll(context.Background(), hosts, g); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /config/logging/logs/gatewyn_access", "PUT /config/apps/tls/automation", "PUT /config/apps/http/servers/gatewyn", "DELETE /config/apps/http/servers/gatewyn-http", "DELETE /config/apps/crowdsec"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("avec journal : %v, attendu %v", calls, want)
	}
	for _, w := range []string{`"output":"file"`, `"filename":"/data/logs/access.log"`, `"roll_keep_days":30`, `"format":"json"`, `"http.log.access.gatewyn_access"`} {
		if !strings.Contains(bodies["/config/logging/logs/gatewyn_access"], w) {
			t.Errorf("journal sans %s : %s", w, bodies["/config/logging/logs/gatewyn_access"])
		}
	}
	if !strings.Contains(bodies["/config/apps/http/servers/gatewyn"], `"default_logger_name":"gatewyn_access"`) {
		t.Errorf("le serveur n'écrit pas dans le journal : %s", bodies["/config/apps/http/servers/gatewyn"])
	}

	// Sans journal : le serveur n'écrit plus, puis le journal est retiré.
	calls = nil
	if err := New(srv.URL).ApplyAll(context.Background(), hosts, caddyconf.Global{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodies["/config/apps/http/servers/gatewyn"], "default_logger_name") {
		t.Error("le serveur écrit encore dans le journal")
	}
	if calls[len(calls)-2] != "DELETE /config/logging/logs/gatewyn_access" {
		t.Errorf("sans journal : %v", calls)
	}
}
