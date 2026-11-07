package checks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct {
	addrs map[string][]string
	err   error
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.addrs[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestDNS(t *testing.T) {
	r := fakeResolver{addrs: map[string][]string{
		"ok.example.com":    {"203.0.113.5"},
		"dup.example.com":   {"203.0.113.5", "203.0.113.5", "203.0.113.5"},
		"wrong.example.com": {"198.51.100.7"},
		"extra.example.com": {"203.0.113.5", "2001:db8::9"},
		"v6.example.com":    {"2001:0db8:0000:0000:0000:0000:0000:0001"},
	}}
	ctx := context.Background()
	mine := []string{"203.0.113.5", "2001:db8::1"}
	tests := []struct {
		name   string
		domain string
		ips    []string
		res    Resolver
		code   string
		status Status
		must   []string
	}{
		{"correct", "ok.example.com", mine, r, "dns_ok", OK, []string{"pointe vers 203.0.113.5"}},
		{"mauvaise IP", "wrong.example.com", mine, r, "dns_wrong_ip", Error, []string{"ne pointe pas vers votre IP", "198.51.100.7", "203.0.113.5"}},
		{"inexistant", "nope.example.com", mine, r, "dns_not_found", Error, []string{"n'existe pas dans le DNS", "enregistrement A", "203.0.113.5"}},
		{"IP en plus", "extra.example.com", mine, r, "dns_extra_ip", Warn, []string{"2001:db8::9"}},
		{"IPv6 écrite autrement", "v6.example.com", mine, r, "dns_ok", OK, nil},
		{"IP publique inconnue", "ok.example.com", nil, r, "dns_unknown_ip", Info, []string{"pointe vers 203.0.113.5."}},
		{"adresse répétée par le résolveur", "dup.example.com", nil, r, "dns_unknown_ip", Info, []string{"pointe vers 203.0.113.5."}},
		{"joker", "*.example.com", mine, r, "dns_wildcard", Info, []string{"joker"}},
		{"résolveur en panne", "ok.example.com", mine, fakeResolver{err: errors.New("server misbehaving")}, "dns_unavailable", Warn, []string{"Réessayez"}},
	}
	for _, tt := range tests {
		got := DNS(ctx, tt.res, tt.domain, tt.ips)
		if got.Code != tt.code || got.Status != tt.status {
			t.Errorf("%s : %s/%s (%q), attendu %s/%s", tt.name, got.Status, got.Code, got.Message, tt.status, tt.code)
		}
		for _, m := range tt.must {
			if !strings.Contains(got.Message, m) {
				t.Errorf("%s : message sans %q : %s", tt.name, m, got.Message)
			}
		}
	}
}

func TestTargetOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	defer srv.Close()
	got := Target(context.Background(), srv.URL, false)
	if got.Code != "target_ok" || got.Status != OK || !strings.Contains(got.Message, "200") {
		t.Errorf("%+v", got)
	}
}

func TestTargetRedirectAndClientErrorCountAsReachable(t *testing.T) {
	for _, code := range []int{http.StatusFound, http.StatusUnauthorized, http.StatusNotFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://elsewhere.example.com/")
			w.WriteHeader(code)
		}))
		got := Target(context.Background(), srv.URL, false)
		srv.Close()
		if got.Status != OK {
			t.Errorf("code %d : %+v", code, got)
		}
	}
}

func TestTarget5xxIsWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	got := Target(context.Background(), srv.URL, false)
	if got.Status != Warn || got.Code != "target_5xx" {
		t.Errorf("%+v", got)
	}
}

func TestTargetClosedPort(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close() // port fermé
	got := Target(context.Background(), "http://"+addr, false)
	// Selon le système (WSL2 coupe au lieu de refuser), le message diffère ; les deux sont des erreurs claires.
	if got.Status != Error || (got.Code != "target_refused" && got.Code != "target_reset") {
		t.Errorf("%+v", got)
	}
}

func TestExplainTargetError(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{errors.New("dial tcp 127.0.0.1:9: connect: connection refused"), "target_refused"},
		{errors.New("read tcp 1.2.3.4:5->6.7.8.9:80: read: connection reset by peer"), "target_reset"},
		{errors.New(`Get "https://x": EOF`), "target_reset"},
		{errors.New("http: server gave HTTP response to HTTPS client"), "target_protocol"},
		{errors.New("tls: first record does not look like a TLS handshake"), "target_protocol"},
		{errors.New("dial tcp 192.0.2.9:80: connect: no route to host"), "target_unreachable"},
		{&net.DNSError{Err: "no such host", Name: "wiki.internal", IsNotFound: true}, "target_dns"},
		{errors.New("quelque chose d'autre"), "target_failed"},
	}
	for _, tt := range tests {
		if got := explainTargetError("192.0.2.9:80", tt.err); got.Code != tt.code || got.Status != Error {
			t.Errorf("%v → %s, attendu %s", tt.err, got.Code, tt.code)
		}
	}
}

func TestTargetTimeout(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0") // accepte la connexion (backlog) sans jamais répondre
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got := Target(ctx, "http://"+l.Addr().String(), false)
	if got.Code != "target_timeout" || !strings.Contains(got.Message, "ne répond pas") {
		t.Errorf("%+v", got)
	}
}

func TestTargetSelfSignedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	got := Target(context.Background(), srv.URL, false)
	if got.Code != "target_cert" || got.Status != Warn || !strings.Contains(got.Message, "http://") {
		t.Errorf("%+v", got)
	}
	if got := Target(context.Background(), srv.URL, true); got.Code != "target_ok" || got.Status != OK {
		t.Errorf("sans vérification du certificat : %+v", got)
	}
}

func TestTargetInvalid(t *testing.T) {
	for _, in := range []string{"192.0.2.1:80", "", "ftp://192.0.2.1"} {
		got := Target(context.Background(), in, false)
		if got.Code != "target_invalid" || got.Status != Error {
			t.Errorf("%q : %+v", in, got)
		}
	}
}

func TestExplainACME(t *testing.T) {
	tests := []struct {
		raw  string
		code string
	}{
		{`acme: error: 429 :: POST :: urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued`, "acme_rate_limit"},
		{`Detail: DNS problem: NXDOMAIN looking up A for wiki.example.com`, "acme_dns"},
		{`Fetching http://wiki.example.com/.well-known/acme-challenge/x: Timeout during connect (likely firewall problem)`, "acme_unreachable"},
		{`Connection refused`, "acme_refused"},
		{`urn:ietf:params:acme:error:unauthorized :: Invalid response from http://wiki.example.com/...`, "acme_wrong_server"},
		{`CAA record for example.com prevents issuance`, "acme_caa"},
		{`solving challenges: dns-01: TXT record propagation timed out`, "acme_dns_challenge"},
		{`registering account [] with server: provisioning client: performing request: Get "https://acme-v02.api.letsencrypt.org/directory": dial tcp: lookup acme-v02.api.letsencrypt.org on 127.0.0.11:53: server misbehaving`, "acme_no_outbound"},
		{`Get "https://acme-v02.api.letsencrypt.org/directory": dial tcp 192.0.2.10:443: i/o timeout`, "acme_no_outbound"},
		{`something completely different`, "acme_unknown"},
		{``, "acme_unknown"},
	}
	for _, tt := range tests {
		got := ExplainACME(tt.raw)
		if got.Code != tt.code || got.Status != Error {
			t.Errorf("%q → %s, attendu %s", tt.raw, got.Code, tt.code)
		}
		if strings.Contains(got.Message, "urn:ietf") || strings.Contains(got.Message, "acme:error") {
			t.Errorf("code ACME brut dans le message : %s", got.Message)
		}
	}
}

func TestTargetH2COnlyTestsTheConnection(t *testing.T) {
	// Un service gRPC refuse HTTP/1.1 : on ne teste que la connexion TCP.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // ne parle pas HTTP du tout
		}
	}()
	res := Target(context.Background(), "h2c://"+ln.Addr().String(), false)
	if res.Status != OK || !strings.Contains(res.Message, "HTTP/2 n'est pas testé") {
		t.Errorf("service qui écoute : %+v", res)
	}
	ln.Close()
	// Port 1 : personne n'écoute (le port libéré par ln peut être repris par un autre test).
	if res := Target(context.Background(), "h2c://127.0.0.1:1", false); res.Status != Error {
		t.Errorf("port fermé : %+v", res)
	}
}

func TestCapitalizeKeepsMultibyteCharacters(t *testing.T) {
	for in, want := range map[string]string{"« x » est faux": "« x » est faux", "élan": "Élan", "abc": "Abc", "": ""} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, attendu %q", in, got, want)
		}
	}
}
