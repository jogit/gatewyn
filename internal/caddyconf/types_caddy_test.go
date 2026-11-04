package caddyconf

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/caddy/v2/modules/logging"
)

// Les structures de model.go ne dépendent pas de Caddy pour garder le programme léger. Ces tests
// gardent la même garantie qu'avant : chaque configuration produite est relue dans les vrais types
// de Caddy, en refusant tout champ inconnu, donc une faute de frappe ou un champ renommé échoue ici.

// strict décode raw dans v et refuse les champs inconnus.
func strict(t *testing.T, name string, raw []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Errorf("%s : refusé par les types de Caddy : %v\n%s", name, err, raw)
	}
}

// module décode un module identifié par une clé (« handler », « protocol », « module »…) : la clé
// sert à Caddy à choisir le type, elle n'est pas un champ du type lui-même.
func module(t *testing.T, name string, raw json.RawMessage, key string, v any) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Errorf("%s : %v", name, err)
		return ""
	}
	var id string
	json.Unmarshal(m[key], &id)
	delete(m, key)
	rest, _ := json.Marshal(m)
	strict(t, name+" ("+id+")", rest, v)
	return id
}

func checkMatchers(t *testing.T, name string, sets []map[string]json.RawMessage) {
	t.Helper()
	for _, set := range sets {
		for k, raw := range set {
			switch k {
			case "host":
				var v caddyhttp.MatchHost
				strict(t, name+" host", raw, &v)
			case "path":
				var v caddyhttp.MatchPath
				strict(t, name+" path", raw, &v)
			case "client_ip":
				var v caddyhttp.MatchClientIP
				strict(t, name+" client_ip", raw, &v)
			case "not":
				var inner []map[string]json.RawMessage
				strict(t, name+" not", raw, &inner)
				checkMatchers(t, name+" not", inner)
			default:
				t.Errorf("%s : critère %q inconnu", name, k)
			}
		}
	}
}

func checkHandler(t *testing.T, name string, raw json.RawMessage) {
	t.Helper()
	var head struct {
		Handler string `json:"handler"`
	}
	json.Unmarshal(raw, &head)
	switch head.Handler {
	case "static_response":
		var v caddyhttp.StaticResponse
		module(t, name, raw, "handler", &v)
	case "headers":
		var v headers.Handler
		module(t, name, raw, "handler", &v)
	case "rewrite":
		var v rewrite.Rewrite
		module(t, name, raw, "handler", &v)
	case "encode":
		var v encode.Encode
		module(t, name, raw, "handler", &v)
	case "reverse_proxy":
		var v reverseproxy.Handler
		module(t, name, raw, "handler", &v)
		if v.TransportRaw != nil {
			var tr reverseproxy.HTTPTransport
			module(t, name+" transport", v.TransportRaw, "protocol", &tr)
		}
	case "crowdsec", "appsec":
		// Modules du bouncer CrowdSec (hors de Caddy) : pas de type à contrôler ici ; le test
		// sur un Caddy réel (scripts/test-crowdsec.sh) les charge.
		if string(bytes.TrimSpace(raw)) != `{"handler":"`+head.Handler+`"}` {
			t.Errorf("%s : gestionnaire %s inattendu : %s", name, head.Handler, raw)
		}
	default:
		t.Errorf("%s : gestionnaire %q inconnu", name, head.Handler)
	}
}

func checkServer(t *testing.T, name string, raw []byte) {
	t.Helper()
	var srv caddyhttp.Server
	strict(t, name, raw, &srv)
	for i, r := range srv.Routes {
		rn := name + " route " + string(rune('0'+i%10))
		sets := make([]map[string]json.RawMessage, len(r.MatcherSetsRaw))
		for j, set := range r.MatcherSetsRaw {
			sets[j] = set
		}
		checkMatchers(t, rn, sets)
		for _, h := range r.HandlersRaw {
			checkHandler(t, rn, h)
		}
	}
	if srv.TrustedProxiesRaw != nil {
		var tp map[string]any
		json.Unmarshal(srv.TrustedProxiesRaw, &tp)
		if tp["source"] != "static" {
			t.Errorf("%s : proxies de confiance : %s", name, srv.TrustedProxiesRaw)
		}
	}
}

// TestOutputIsAcceptedByCaddyTypes relit les 270 scénarios de référence dans les types de Caddy.
func TestOutputIsAcceptedByCaddyTypes(t *testing.T) {
	var servers, tlsCount, logs, configs int
	for name, raw := range goldenScenarios(t) {
		switch {
		case strings.HasPrefix(name, "serveur "):
			if string(raw) == "null" {
				continue // aucun hôte en HTTP seulement
			}
			checkServer(t, name, raw)
			servers++
		case strings.HasPrefix(name, "tls "):
			var cfg caddytls.AutomationConfig
			strict(t, name, raw, &cfg)
			for _, p := range cfg.Policies {
				for _, is := range p.IssuersRaw {
					var head struct {
						Module string `json:"module"`
					}
					json.Unmarshal(is, &head)
					switch head.Module {
					case "internal":
						var v caddytls.InternalIssuer
						module(t, name, is, "module", &v)
					case "acme":
						var v caddytls.ACMEIssuer
						module(t, name, is, "module", &v)
					default:
						t.Errorf("%s : émetteur %q inconnu", name, head.Module)
					}
				}
			}
			tlsCount++
		case strings.HasPrefix(name, "journal "):
			var l caddy.CustomLog
			strict(t, name, raw, &l)
			var w logging.FileWriter
			module(t, name+" writer", l.WriterRaw, "output", &w)
			var e logging.JSONEncoder
			module(t, name+" encoder", l.EncoderRaw, "format", &e)
			if w.Roll == nil || !*w.Roll || w.RollKeepDays < 1 {
				t.Errorf("%s : rotation absente : %+v", name, w)
			}
			logs++
		case strings.HasPrefix(name, "configuration complète"):
			var cfg caddy.Config
			strict(t, name, raw, &cfg)
			var http caddyhttp.App
			strict(t, name+" http", cfg.AppsRaw["http"], &http)
			for sn, srv := range http.Servers {
				b, _ := json.Marshal(srv)
				checkServer(t, name+" "+sn, b)
			}
			configs++
		}
	}
	if servers < 100 || tlsCount < 15 || logs != 2 || configs < 15 {
		t.Errorf("couverture trop faible : %d serveurs, %d tls, %d journaux, %d configurations", servers, tlsCount, logs, configs)
	}
}
