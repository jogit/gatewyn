package web

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// TestDumpEnglish écrit le texte visible des pages en anglais (relecture à la main) quand
// GATEWYN_DUMP_EN pointe vers un fichier. Ignoré sinon.
func TestDumpEnglish(t *testing.T) {
	out := os.Getenv("GATEWYN_DUMP_EN")
	if out == "" {
		t.Skip("GATEWYN_DUMP_EN absent")
	}
	e := englishFixture(t)
	hosts, _ := e.srv.cfg.Store.ListHosts(t.Context())
	id := map[string]string{}
	for _, h := range hosts {
		id[h.Domain] = itoa(h.ID)
	}
	var b strings.Builder
	for _, p := range []string{"/", "/hosts", "/redirections", "/erreurs-404", "/hosts/new", "/hosts/" + id["wiki.example.com"] + "/edit", "/hosts/new?kind=redirect",
		"/security/protection", "/security/crowdsec", "/security/crowdsec/install", "/security/access", "/security/lists/new", "/security/proxies",
		"/certificates", "/certificates/dns", "/certificates/dns/new", "/stats", "/stats/install", "/settings", "/dashboard/online", "/security/crowdsec/status"} {
		_, body := e.do("GET", p, nil, "Accept-Language", "en")
		b.WriteString("\n##### " + p + "\n")
		doc, _ := html.Parse(strings.NewReader(body))
		var walk func(n *html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "pre" || n.Data == "svg") {
				return
			}
			if n.Type == html.TextNode {
				if s := strings.Join(strings.Fields(n.Data), " "); s != "" {
					b.WriteString(s + "\n")
				}
			}
			if n.Type == html.ElementNode {
				for _, a := range n.Attr {
					if a.Key == "placeholder" || a.Key == "title" || a.Key == "aria-label" || a.Key == "hx-confirm" {
						b.WriteString("  [" + a.Key + "] " + a.Val + "\n")
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
	}
	// Réponses aux saisies invalides : seulement les messages d'alerte.
	b.WriteString("\n##### SAISIES INVALIDES\n")
	for _, r := range []struct {
		path string
		form url.Values
	}{
		{"/hosts", url.Values{}}, {"/hosts", url.Values{"domain": {"x.example.com"}}}, {"/hosts", url.Values{"domain": {"http://x"}, "target": {"192.0.2.1:80"}}},
		{"/hosts", url.Values{"domain": {"x.example.com"}, "target": {"ftp://192.0.2.1"}}}, {"/hosts", url.Values{"domain": {"wiki.example.com"}, "target": {"192.0.2.99:80"}}},
		{"/hosts", url.Values{"domain": {"y.example.com"}, "target": {"192.0.2.1:80"}, "loc_path": {"api"}, "loc_target": {"192.0.2.2:80"}}},
		{"/hosts", url.Values{"kind": {"redirect"}, "domain": {"r.example.com"}, "target": {"https://r.example.com"}}},
		{"/hosts", url.Values{"domain": {"z.example.com"}, "target": {"192.0.2.1:1"}}},
		{"/security/lists", url.Values{"name": {""}, "addresses": {"192.0.2.1"}}}, {"/security/lists", url.Values{"name": {"T"}, "addresses": {"abc"}}},
		{"/security/proxies", url.Values{"proxies": {"cloudflare.com"}}}, {"/certificates/dns", url.Values{"name": {"X"}, "provider": {"ovh"}}},
		{"/security/crowdsec", url.Values{"url": {""}, "key": {""}}}, {"/security/crowdsec", url.Values{"url": {"http://127.0.0.1:1"}, "key": {"x"}}},
		{"/settings", url.Values{"crowdsec_ui_url": {"abc"}}}, {"/hosts/check/dns", url.Values{"domain": {"inexistant.example.invalid"}}},
		{"/hosts/check/target", url.Values{"domain": {"a.example.com"}, "target": {"192.0.2.1:1"}}}, {"/hosts/check/dns", url.Values{"domain": {"wiki.example.com"}}},
	} {
		_, body := e.do("POST", r.path, r.form, "Accept-Language", "en")
		doc, _ := html.Parse(strings.NewReader(body))
		var walk func(n *html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				for _, a := range n.Attr {
					if (a.Key == "role" && a.Val == "alert") || (a.Key == "class" && strings.Contains(a.Val, "note")) {
						b.WriteString(r.path + " → " + strings.Join(strings.Fields(textOf(n)), " ") + "\n")
						return
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
	}
	os.WriteFile(out, []byte(b.String()), 0o644)
}

func textOf(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.WriteString(textOf(c) + " ")
	}
	return b.String()
}
