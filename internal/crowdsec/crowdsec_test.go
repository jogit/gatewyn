package crowdsec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func lapi(t *testing.T, key, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Api-Key") != key {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(body))
	}))
}

func TestDecisions(t *testing.T) {
	srv := lapi(t, "cle-fictive", `[{"duration":"3h59m58.5s","id":1,"origin":"crowdsec","scenario":"crowdsecurity/http-probing","scope":"Ip","type":"ban","value":"192.0.2.99"},
	{"duration":"1h59m58s","id":2,"origin":"cscli","scenario":"plage fictive","scope":"Range","type":"ban","value":"198.51.100.0/24"}]`)
	defer srv.Close()
	got, err := Decisions(context.Background(), srv.Client(), srv.URL+"/", "cle-fictive")
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Value != "192.0.2.99" || got[0].Scope != "Ip" || got[0].Origin != "crowdsec" || got[0].Remaining != 3*time.Hour+59*time.Minute+58500*time.Millisecond {
		t.Errorf("première décision : %+v", got[0])
	}
}

func TestDecisionsNoneBadKeyAndUnreachable(t *testing.T) {
	srv := lapi(t, "cle", `null`)
	defer srv.Close()
	if got, err := Decisions(context.Background(), srv.Client(), srv.URL, "cle"); err != nil || len(got) != 0 {
		t.Errorf("aucune décision : %+v %v", got, err)
	}
	if _, err := Decisions(context.Background(), srv.Client(), srv.URL, "mauvaise"); !errors.Is(err, ErrBadKey) {
		t.Errorf("mauvaise clé : %v", err)
	}
	srv.Close()
	if _, err := Decisions(context.Background(), srv.Client(), srv.URL, "cle"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("injoignable : %v", err)
	}
	if _, err := Decisions(context.Background(), http.DefaultClient, "://pas une adresse", "cle"); err == nil {
		t.Error("adresse invalide acceptée")
	}
}

func TestAppSecCheck(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		switch r.Header.Get("X-Crowdsec-Appsec-Api-Key") {
		case "cle":
			w.Write([]byte(`{"action":"allow","http_status":200}`))
		case "cle-ban": // une règle peut refuser la requête anodine : AppSec fonctionne quand même
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if err := AppSecCheck(ctx, srv.Client(), srv.URL+"/", "cle"); err != nil {
		t.Errorf("clé valide : %v", err)
	}
	for _, h := range []string{"X-Crowdsec-Appsec-Ip", "X-Crowdsec-Appsec-Uri", "X-Crowdsec-Appsec-Host", "X-Crowdsec-Appsec-Verb", "X-Crowdsec-Appsec-Api-Key"} {
		if got.Get(h) == "" {
			t.Errorf("en-tête %s absent", h)
		}
	}
	if err := AppSecCheck(ctx, srv.Client(), srv.URL, "cle-ban"); err != nil {
		t.Errorf("réponse 403 : %v", err)
	}
	if err := AppSecCheck(ctx, srv.Client(), srv.URL, "mauvaise"); !errors.Is(err, ErrBadKey) {
		t.Errorf("mauvaise clé : %v", err)
	}
	srv.Close()
	if err := AppSecCheck(ctx, srv.Client(), srv.URL, "cle"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("injoignable : %v", err)
	}
}

const sampleMetrics = `# HELP cs_appsec_reqs_total Total events processed by the Application Security Engine.
# TYPE cs_appsec_reqs_total counter
cs_appsec_reqs_total{appsec_engine="0.0.0.0:7422/",source="10.0.0.2"} 28
cs_appsec_reqs_total{appsec_engine="0.0.0.0:7422/",source="10.0.0.3"} 2
# TYPE cs_appsec_block_total counter
cs_appsec_block_total{appsec_engine="0.0.0.0:7422/",source="10.0.0.2"} 17
cs_appsec_rule_hits{appsec_engine="0.0.0.0:7422/",rule_name="crowdsecurity/vpatch-env-access",source="10.0.0.2",type="inband"} 15
cs_appsec_rule_hits{appsec_engine="0.0.0.0:7422/",rule_name="crowdsecurity/vpatch-env-access",source="10.0.0.2",type="outofband"} 15
cs_appsec_rule_hits{appsec_engine="0.0.0.0:7422/",rule_name="crowdsecurity/vpatch-CVE-2024-1234",source="10.0.0.2",type="inband"} 2
cs_appsec_rule_hits{appsec_engine="0.0.0.0:7422/",rule_name="crowdsecurity/vpatch-git-config",source="10.0.0.2",type="inband"} 2
cs_appsec_inband_parsing_time_seconds_count{appsec_engine="0.0.0.0:7422/",source="10.0.0.2"} 28
cs_active_decisions 4
`

func TestStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sampleMetrics)) }))
	defer srv.Close()
	st, err := Stats(context.Background(), srv.Client(), srv.URL+"/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if st.Processed != 30 || st.Blocked != 17 {
		t.Errorf("compteurs : %+v", st)
	}
	// Les règles en bande et hors bande s'additionnent ; tri du plus au moins déclenché.
	want := []RuleHit{{"crowdsecurity/vpatch-env-access", 30}, {"crowdsecurity/vpatch-CVE-2024-1234", 2}, {"crowdsecurity/vpatch-git-config", 2}}
	if len(st.Rules) != 3 || st.Rules[0] != want[0] || st.Rules[1] != want[1] || st.Rules[2] != want[2] {
		t.Errorf("règles : %+v", st.Rules)
	}
	srv.Close()
	if _, err := Stats(context.Background(), srv.Client(), srv.URL+"/metrics"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("injoignable : %v", err)
	}
	srv2 := httptest.NewServer(http.NotFoundHandler())
	defer srv2.Close()
	if _, err := Stats(context.Background(), srv2.Client(), srv2.URL); err == nil {
		t.Error("réponse 404 acceptée")
	}
}

func TestRuleLabel(t *testing.T) {
	for rule, want := range map[string][2]string{
		"crowdsecurity/vpatch-env-access":    {"Accès à un fichier .env", "crowdsecurity/vpatch-env-access"},
		"crowdsecurity/vpatch-CVE-2024-1234": {"Faille connue (CVE-2024-1234)", "crowdsecurity/vpatch-CVE-2024-1234"},
		"crowdsecurity/une-regle-inconnue":   {"crowdsecurity/une-regle-inconnue", ""},
	} {
		if l, raw := RuleLabel(rule); l != want[0] || raw != want[1] {
			t.Errorf("%s → %q %q", rule, l, raw)
		}
	}
}

func TestAppSecUpSendsNoRequest(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	if err := AppSecUp(context.Background(), srv.URL); err != nil {
		t.Errorf("serveur qui écoute : %v", err)
	}
	if requests != 0 {
		t.Errorf("%d requête(s) envoyée(s) : AppSec la compterait", requests)
	}
	srv.Close()
	// Port 1 : personne n'écoute (un port libéré par un test peut être repris par un autre, d'où des échecs aléatoires).
	if err := AppSecUp(context.Background(), "http://127.0.0.1:1"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("injoignable : %v", err)
	}
	if err := AppSecUp(context.Background(), "://x"); err == nil {
		t.Error("adresse invalide acceptée")
	}
}
