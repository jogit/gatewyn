// Package caddyconf traduit les hôtes Gatewyn en configuration Caddy (JSON de l'API
// d'administration), avec des structures locales vérifiées en test contre les types de Caddy.
package caddyconf

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// ServerName est le nom du serveur HTTP géré par Gatewyn dans la configuration Caddy.
const ServerName = "gatewyn"

// Types d'hôte. Un Kind vide vaut KindProxy.
const (
	KindProxy    = "proxy"    // publie un service (reverse proxy)
	KindRedirect = "redirect" // redirige vers une autre adresse
	KindNotFound = "404"      // répond « page introuvable »
)

// Host décrit un nom de domaine publié par Gatewyn.
type Host struct {
	Domain   string   // nom public, ex. wiki.example.com
	Aliases  []string // autres noms servis par le même hôte, avec le même certificat
	Kind     string   // KindProxy (défaut), KindRedirect ou KindNotFound
	Target   string   // proxy : adresse du service (http://192.0.2.21:8080) ; redirection : destination (https://example.org)
	Disabled bool     // l'hôte reste enregistré mais n'est pas publié

	// Redirection seulement.
	Code         int  // 301 (permanente, défaut) ou 302 (temporaire)
	PreservePath bool // garde le chemin et les paramètres de la requête

	// Service seulement : adresses IP ou plages autorisées ; vide = public.
	Access []string

	// Certificat par le défi DNS ; nil = défi HTTP automatique de Caddy.
	DNS *DNSChallenge

	// Publié en HTTP seulement (port 80) : pas de HTTPS, pas de certificat.
	HTTPOnly bool

	// Certificat auto-signé par l'autorité interne de Caddy.
	SelfSigned bool

	// En-tête HSTS : 0 = aucun, 1 = HSTS, 2 = HSTS avec les sous-domaines.
	HSTS int

	// Service seulement : chemins envoyés vers une autre cible que Target.
	Locations []Location

	// Les requêtes passent par le bouncer CrowdSec avant d'être servies.
	CrowdSec bool

	// Service : le certificat HTTPS du service (et de ses chemins) n'est pas vérifié.
	TLSSkipVerify bool

	// Service : les requêtes passent aussi par le WAF de CrowdSec (AppSec). Sans effet
	// si CrowdSec n'est pas actif.
	WAF bool

	// Service : compression des réponses (zstd, gzip) et streaming sans tampon.
	Compress, NoBuffering bool

	// En-têtes de réponse : X-Frame-Options (« », « SAMEORIGIN » ou « DENY ») et X-Robots-Tag: noindex.
	FrameOptions string
	NoIndex      bool

	strip string // route d'un chemin : préfixe retiré avant de transmettre
}

// Global rassemble les réglages qui ne dépendent pas d'un hôte.
type Global struct {
	CrowdSec *CrowdSec // nil : pas de bouncer
	// Proxies de confiance (adresses ou plages) : derrière eux, l'adresse du visiteur
	// est lue dans X-Forwarded-For, pour les listes d'accès et CrowdSec.
	TrustedProxies []string
	// AccessLog : journal d'accès JSON, par exemple pour GoAccess. nil : aucun journal.
	AccessLog *AccessLog
}

// AccessLog décrit le fichier de journal d'accès. Il contient l'adresse de chaque
// visiteur : Caddy supprime lui-même les fichiers plus vieux que KeepDays.
type AccessLog struct {
	File     string // chemin du fichier, ex. /data/logs/access.log
	KeepDays int    // durée de conservation, en jours (au moins 1)
}

// AccessLogName est le nom du journal de Gatewyn dans la configuration de Caddy.
const AccessLogName = "gatewyn_access"

// AccessLogJSON renvoie le journal « gatewyn_access » de Caddy : les accès HTTP,
// en JSON, dans un fichier avec rotation.
func AccessLogJSON(a AccessLog) ([]byte, error) {
	return json.Marshal(logConfig{
		Writer: fileWriter{
			Output: "file", Filename: a.File, Roll: true,
			RollSizeMB: 100, RollKeep: 1000, // c'est la durée, pas le nombre de fichiers, qui limite
			RollKeepDays: a.KeepDays,
		},
		Encoder: logEncoder{Format: "json"},
		Include: []string{"http.log.access." + AccessLogName},
	})
}

// DefaultLogJSON renvoie le journal principal de Caddy (stderr) réglé pour ne pas recevoir
// les accès HTTP. Sans cela, chaque requête, avec l'adresse du visiteur, serait aussi écrite
// dans les journaux du conteneur : Caddy envoie au journal principal tout ce qu'aucun
// journal n'exclut, et seul le Caddyfile ajoute cette exclusion de lui-même.
func DefaultLogJSON() ([]byte, error) {
	return json.Marshal(struct {
		Exclude []string `json:"exclude"`
	}{Exclude: []string{"http.log.access." + AccessLogName}})
}

// CrowdSec configure le bouncer CrowdSec de Caddy (module caddy-crowdsec-bouncer).
type CrowdSec struct {
	URL string // API locale de CrowdSec, ex. http://crowdsec:8080
	Key string // clé du bouncer (cscli bouncers add)

	// WAF : composant AppSec de CrowdSec (ex. http://crowdsec:7422), vide s'il n'est pas utilisé.
	AppSecURL string
	// AppSecFailOpen : une requête passe si AppSec est injoignable (sinon elle est refusée).
	AppSecFailOpen bool
}

// CrowdSecJSON renvoie la configuration de l'application « crowdsec » de Caddy :
// les décisions sont lues en flux et gardées en mémoire, mises à jour toutes les 10 s.
func CrowdSecJSON(cs CrowdSec) ([]byte, error) {
	m := map[string]any{
		"api_url":          cs.URL,
		"api_key":          cs.Key,
		"ticker_interval":  "10s",
		"enable_streaming": true,
	}
	if cs.AppSecURL != "" {
		m["appsec_url"] = cs.AppSecURL
		m["appsec_fail_open"] = cs.AppSecFailOpen
	}
	return json.Marshal(m)
}

// Location envoie un chemin (et tout ce qui est dessous) vers une autre cible.
type Location struct {
	Path   string // « /api » : correspond à /api et /api/...
	Target string // comme Host.Target ; vide : la cible de l'hôte

	// Accès du chemin : par défaut celui de l'hôte (Host.Access). Public l'ouvre à
	// tous ; Access le limite à ces adresses.
	Access []string
	Public bool

	StripPath bool // retire le chemin avant de transmettre : /api/x devient /x
}

// access renvoie les adresses autorisées sur ce chemin (vide = public).
func (l Location) access(host []string) []string {
	switch {
	case l.Public:
		return nil
	case len(l.Access) > 0:
		return l.Access
	}
	return host
}

// HSTSValue est la valeur de l'en-tête Strict-Transport-Security (un an).
func (h Host) HSTSValue() string {
	switch h.HSTS {
	case 1:
		return "max-age=31536000"
	case 2:
		return "max-age=31536000; includeSubDomains"
	}
	return ""
}

// DNSChallenge désigne le compte DNS d'un hôte. Les hôtes d'un même compte
// partagent une règle d'obtention de certificat.
type DNSChallenge struct {
	Account  int64
	Provider map[string]any // JSON du module Caddy, ex. {"name": "ovh", "endpoint": "ovh-eu", ...}
}

// Domains renvoie tous les noms de l'hôte : le domaine, puis ses alias.
func (h Host) Domains() []string { return append([]string{h.Domain}, h.Aliases...) }

// KindOf renvoie le type effectif de l'hôte.
func (h Host) KindOf() string {
	if h.Kind == "" {
		return KindProxy
	}
	return h.Kind
}

// prepare normalise et valide les hôtes, et renvoie ceux qui sont publiés.
func prepare(hosts []Host) ([]Host, error) {
	active := make([]Host, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		h.Domain = strings.ToLower(strings.TrimSpace(h.Domain))
		h.Aliases = append([]string(nil), h.Aliases...)
		for i := range h.Aliases {
			h.Aliases[i] = strings.ToLower(strings.TrimSpace(h.Aliases[i]))
		}
		for _, d := range h.Domains() {
			if err := ValidateDomain(d); err != nil {
				return nil, fmt.Errorf("hôte %q : %w", h.Domain, err)
			}
			if seen[d] {
				return nil, fmt.Errorf("hôte %q : domaine %q en double", h.Domain, d)
			}
			seen[d] = true
		}
		if err := h.Validate(); err != nil {
			return nil, fmt.Errorf("hôte %q : %w", h.Domain, err)
		}
		if !h.Disabled {
			active = append(active, h)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Domain < active[j].Domain })
	return active, nil
}

// BuildServer produit le serveur HTTPS de Caddy (port 443) pour les hôtes donnés,
// sauf ceux publiés en HTTP seulement. Gatewyn ne remplace que ses serveurs (voir
// caddyadmin), jamais le reste de la configuration de Caddy, pour ne pas perdre
// les réglages d'administration. Le résultat ne dépend pas de l'ordre des hôtes.
//
// Les réglages globaux (proxies de confiance) sont facultatifs : BuildServer(hosts)
// suffit quand il n'y en a pas.
func BuildServer(hosts []Host, g ...Global) (*Server, error) {
	return buildServer(hosts, false, firstGlobal(g))
}

func firstGlobal(g []Global) Global {
	if len(g) > 0 {
		return g[0]
	}
	return Global{}
}

// BuildHTTPServer produit le serveur HTTP (port 80) des hôtes publiés en HTTP
// seulement. Renvoie nil s'il n'y en a aucun. Caddy n'applique aucun HTTPS à un
// serveur qui n'écoute que sur le port HTTP, et garde la redirection vers HTTPS
// des autres hôtes.
func BuildHTTPServer(hosts []Host, g ...Global) (*Server, error) {
	srv, err := buildServer(hosts, true, firstGlobal(g))
	if err != nil || len(srv.Routes) == 0 {
		return nil, err
	}
	srv.Listen = []string{":80"}
	return srv, nil
}

func buildServer(hosts []Host, httpOnly bool, g Global) (*Server, error) {
	all, err := prepare(hosts)
	if err != nil {
		return nil, err
	}
	var active []Host
	for _, h := range all {
		if h.HTTPOnly == httpOnly {
			active = append(active, h)
		}
	}

	routes := make([]Route, 0, len(active))
	for _, h := range active {
		route, err := buildRoute(h)
		if err != nil {
			return nil, err
		}
		if h.KindOf() == KindProxy {
			routes = append(routes, buildLocationRoutes(h)...)
			if len(h.Access) > 0 {
				routes = append(routes, buildDenyRoute(h.Domains(), "", h.Access))
			}
		}
		routes = append(routes, route)
	}
	srv := &Server{Listen: []string{":443"}, Routes: routes}
	if g.AccessLog != nil {
		srv.Logs = &serverLogs{DefaultLoggerName: AccessLogName}
	}
	if len(g.TrustedProxies) > 0 {
		// Derrière un proxy de confiance, l'adresse du visiteur vient de X-Forwarded-For,
		// lu de droite à gauche (strict) pour qu'une adresse ajoutée par le visiteur ne compte pas.
		srv.TrustedProxies = &trustedProxies{Source: "static", Ranges: g.TrustedProxies}
		srv.TrustedProxiesStrict = 1
	}
	return srv, nil
}

// ServerJSON sérialise le serveur pour l'API d'administration de Caddy.
func ServerJSON(hosts []Host, g ...Global) ([]byte, error) {
	srv, err := BuildServer(hosts, g...)
	if err != nil {
		return nil, err
	}
	return json.Marshal(srv)
}

// Validate vérifie la partie propre au type de l'hôte (cible, destination, code).
func (h Host) Validate() error {
	switch h.KindOf() {
	case KindProxy:
		if _, _, err := ParseTarget(h.Target); err != nil {
			return err
		}
		return ValidateLocations(h.Locations)
	case KindRedirect:
		for _, d := range h.Domains() {
			if err := ValidateRedirect(d, h.Target, h.Code, h.PreservePath); err != nil {
				return err
			}
		}
		return nil
	case KindNotFound:
		return nil
	}
	return fmt.Errorf("type d'hôte inconnu : %q", h.Kind)
}

func buildRoute(h Host) (Route, error) {
	var handler any
	switch h.KindOf() {
	case KindRedirect:
		code := h.Code
		if code == 0 {
			code = 301
		}
		location := h.Target
		if h.PreservePath {
			// {http.request.uri} : chemin et paramètres de la requête d'origine.
			location = strings.TrimRight(h.Target, "/") + "{http.request.uri}"
		}
		handler = staticResponse{Handler: "static_response", StatusCode: code, Headers: http.Header{"Location": {location}}}
	case KindNotFound:
		handler = staticResponse{Handler: "static_response", StatusCode: 404, Body: "404 Not Found"}
	default:
		dial, tls, _ := ParseTarget(h.Target)
		rp := reverseProxy{Handler: "reverse_proxy", Upstreams: []upstream{{Dial: dial}}}
		if h.NoBuffering {
			rp.FlushInterval = -1 // les réponses partent au fur et à mesure (vidéo, flux en direct)
		}
		switch {
		case tls:
			// Caddy remplace le Host par l'adresse de la cible HTTPS : on garde celui du visiteur,
			// comme pour une cible HTTP (sinon Crafty, entre autres, refuse les WebSockets : origine différente).
			rp.Headers = &rpHeaders{}
			rp.Headers.Request.Set = http.Header{"Host": {"{http.request.hostport}"}}
			rp.Transport = &transport{Protocol: "http", TLS: &transportTLS{InsecureSkipVerify: h.TLSSkipVerify}}
		case IsH2C(h.Target):
			rp.Transport = &transport{Protocol: "http", Versions: []string{"h2c"}}
		}
		handler = rp
	}
	// Ordre : CrowdSec, en-têtes, compression, retrait du chemin, puis le gestionnaire de l'hôte.
	var handlers []any
	if h.CrowdSec { // en premier : une adresse bloquée n'atteint rien d'autre
		handlers = append(handlers, simpleHandler{Handler: "crowdsec"})
		if h.WAF && h.KindOf() == KindProxy { // puis le WAF, qui inspecte la requête elle-même
			handlers = append(handlers, simpleHandler{Handler: "appsec"})
		}
	}
	if set := h.ResponseHeaders(); len(set) > 0 {
		handlers = append(handlers, headersHandler{Handler: "headers", Response: respHeaders{Set: set}})
	}
	if h.KindOf() == KindProxy && h.Compress {
		handlers = append(handlers, encodeRaw)
	}
	if h.strip != "" {
		handlers = append(handlers, rewriteHandler{Handler: "rewrite", StripPathPrefix: h.strip})
	}
	handlers = append(handlers, handler)
	return Route{Match: []matchers{{Host: h.Domains()}}, Handle: handlers, Terminal: true}, nil
}

// ResponseHeaders renvoie les en-têtes que Gatewyn ajoute aux réponses de l'hôte.
func (h Host) ResponseHeaders() http.Header {
	set := http.Header{}
	if v := h.HSTSValue(); v != "" && !h.HTTPOnly { // sans effet en HTTP
		set.Set("Strict-Transport-Security", v)
	}
	if h.FrameOptions == "SAMEORIGIN" || h.FrameOptions == "DENY" {
		set.Set("X-Frame-Options", h.FrameOptions)
	}
	if h.NoIndex {
		set.Set("X-Robots-Tag", "noindex")
	}
	return set
}

// buildLocationRoutes : une route par chemin, avant celle de l'hôte, le chemin le
// plus long d'abord pour que /api/v2 passe avant /api.
func buildLocationRoutes(h Host) []Route {
	locs := append([]Location(nil), h.Locations...)
	sort.Slice(locs, func(i, j int) bool {
		return len(locs[i].Path) > len(locs[j].Path) || (len(locs[i].Path) == len(locs[j].Path) && locs[i].Path < locs[j].Path)
	})
	var out []Route
	for _, l := range locs {
		lh := h
		if l.Target != "" {
			lh.Target = l.Target
		}
		if l.StripPath {
			lh.strip = l.Path
		}
		route, _ := buildRoute(lh) // l'hôte est déjà validé
		route.Match = []matchers{{Host: h.Domains(), Path: []string{l.Path, l.Path + "/*"}}}
		if ranges := l.access(h.Access); len(ranges) > 0 {
			out = append(out, buildDenyRoute(h.Domains(), l.Path, ranges))
		}
		out = append(out, route)
	}
	return out
}

// buildDenyRoute répond 403 aux adresses qui ne sont pas dans la liste d'accès ;
// elle précède la route qu'elle protège (celle de l'hôte, ou d'un chemin).
func buildDenyRoute(domains []string, path string, ranges []string) Route {
	m := matchers{
		Host: domains,
		// client_ip : l'adresse du visiteur, derrière un proxy de confiance aussi.
		Not: []notMatcher{{ClientIP: &clientIP{Ranges: ranges}}},
	}
	if path != "" {
		m.Path = []string{path, path + "/*"}
	}
	return Route{
		Match:    []matchers{m},
		Handle:   []any{staticResponse{Handler: "static_response", StatusCode: 403, Body: "403 Forbidden"}},
		Terminal: true,
	}
}

// ValidateRedirect vérifie la destination d'une redirection : une adresse http(s)
// complète, sans caractère que Caddy interpréterait, qui ne renvoie pas vers le
// domaine lui-même (boucle), et sans chemin quand le chemin d'origine est conservé.
func ValidateRedirect(domain, dest string, code int, preservePath bool) error {
	dest = strings.TrimSpace(dest)
	if code != 0 && code != 301 && code != 302 {
		return fmt.Errorf("code de redirection %d non pris en charge (301 ou 302)", code)
	}
	if strings.ContainsAny(dest, "{}\\ \t\r\n") {
		return fmt.Errorf("destination %q : caractères non autorisés (espace, accolades)", dest)
	}
	u, err := url.Parse(dest)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("destination %q : adresse invalide, attendu https://exemple.org", dest)
	}
	if u.User != nil {
		return fmt.Errorf("destination %q : l'identifiant dans l'adresse n'est pas accepté", dest)
	}
	if strings.EqualFold(u.Hostname(), strings.TrimPrefix(domain, "*.")) && domain != "" {
		return fmt.Errorf("la destination renvoie vers %s lui-même : la redirection tournerait en boucle", u.Hostname())
	}
	if preservePath && (u.Path != "" && u.Path != "/" || u.RawQuery != "") {
		return fmt.Errorf("pour garder le chemin de la requête, la destination ne doit pas contenir de chemin (%s) : retirez-le, ou décochez « garder le chemin »", u.Path)
	}
	return nil
}

// IsH2C dit si la cible parle HTTP/2 sans chiffrement (h2c://hôte:port), pour gRPC.
func IsH2C(target string) bool { return strings.HasPrefix(strings.TrimSpace(target), "h2c://") }

// ParseTarget lit l'adresse d'un service et renvoie l'adresse de connexion
// (hôte:port) et si la connexion à la cible est chiffrée.
func ParseTarget(target string) (dial string, tls bool, err error) {
	target = strings.TrimSpace(target)
	u, perr := url.Parse(target)
	if perr != nil || u.Host == "" {
		return "", false, fmt.Errorf("cible %q : adresse invalide, attendu http://hôte:port", target)
	}
	switch u.Scheme {
	case "http", "h2c": // h2c : HTTP/2 sans chiffrement, par exemple gRPC
	case "https":
		tls = true
	default:
		return "", false, fmt.Errorf("cible %q : protocole %q non pris en charge (http, https ou h2c)", target, u.Scheme)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		return "", false, fmt.Errorf("cible %q : un chemin n'est pas accepté, indiquez seulement l'hôte et le port", target)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return "", false, fmt.Errorf("cible %q : hôte manquant", target)
	}
	if port == "" {
		port = "80"
		if tls {
			port = "443"
		}
	}
	return net.JoinHostPort(host, port), tls, nil
}

// ValidateDomain vérifie qu'un nom public est un nom d'hôte simple
// (sans schéma, chemin ni port ; un joker initial *.example.com est accepté).
func ValidateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("domaine manquant")
	}
	if strings.ContainsAny(d, "/:@ ") {
		return fmt.Errorf("domaine invalide : indiquez seulement le nom, sans http://, port ni chemin")
	}
	name := strings.TrimPrefix(d, "*.")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return fmt.Errorf("domaine invalide : attendu un nom complet comme wiki.example.com")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domaine invalide : partie %q incorrecte", label)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("domaine invalide : caractère %q non autorisé", r)
			}
		}
	}
	return nil
}

// ParseAddresses lit une liste d'adresses IP ou de plages (CIDR) séparées par
// des espaces, virgules ou retours à la ligne, et les renvoie normalisées.
func ParseAddresses(text string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked().String())
		} else if a, err := netip.ParseAddr(f); err == nil && a.Zone() == "" {
			out = append(out, a.String())
		} else {
			return nil, fmt.Errorf("« %s » n'est pas une adresse IP ni une plage (exemples : 192.0.2.7, 192.0.2.0/24)", f)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("indiquez au moins une adresse")
	}
	return out, nil
}

// HTTPServerJSON sérialise le serveur HTTP ; nil s'il n'y a aucun hôte en HTTP seulement.
func HTTPServerJSON(hosts []Host, g ...Global) ([]byte, error) {
	srv, err := BuildHTTPServer(hosts, g...)
	if err != nil || srv == nil {
		return nil, err
	}
	return json.Marshal(srv)
}

// TLSJSON renvoie la configuration d'obtention des certificats : une règle par
// compte DNS, qui s'applique aux domaines de ses hôtes. Les autres domaines
// gardent le comportement automatique de Caddy (défi HTTP).
func TLSJSON(hosts []Host) ([]byte, error) {
	byAccount := map[int64][]string{}
	provider := map[int64]map[string]any{}
	for _, h := range hosts {
		if h.Disabled || h.HTTPOnly || h.SelfSigned || h.DNS == nil {
			continue
		}
		for _, d := range h.Domains() {
			byAccount[h.DNS.Account] = append(byAccount[h.DNS.Account], strings.ToLower(strings.TrimSpace(d)))
		}
		provider[h.DNS.Account] = h.DNS.Provider
	}
	accounts := make([]int64, 0, len(byAccount))
	for id := range byAccount {
		accounts = append(accounts, id)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i] < accounts[j] })

	var cfg tlsAutomation
	var selfSigned []string
	for _, h := range hosts {
		if h.SelfSigned && !h.Disabled && !h.HTTPOnly {
			for _, d := range h.Domains() {
				selfSigned = append(selfSigned, strings.ToLower(strings.TrimSpace(d)))
			}
		}
	}
	if len(selfSigned) > 0 {
		sort.Strings(selfSigned)
		cfg.Policies = append(cfg.Policies, tlsPolicy{Subjects: selfSigned, Issuers: []any{internalIssuer{Module: "internal"}}})
	}
	for _, id := range accounts {
		subjects := byAccount[id]
		sort.Strings(subjects)
		cfg.Policies = append(cfg.Policies, tlsPolicy{
			Subjects: subjects,
			Issuers:  []any{acmeIssuer{Module: "acme", Challenges: acmeChallenges{DNS: dnsChallenge{Provider: provider[id]}}}},
		})
	}
	return json.Marshal(cfg)
}

// ValidateLocations vérifie les chemins (valides, sans doublon) et leurs cibles.
func ValidateLocations(ls []Location) error {
	seen := map[string]bool{}
	for _, l := range ls {
		if err := ValidatePath(l.Path); err != nil {
			return err
		}
		if seen[l.Path] {
			return fmt.Errorf("le chemin %s est indiqué deux fois", l.Path)
		}
		seen[l.Path] = true
		if l.Target == "" {
			continue // même cible que l'hôte
		}
		if _, _, err := ParseTarget(l.Target); err != nil {
			return fmt.Errorf("chemin %s : %w", l.Path, err)
		}
	}
	return nil
}

// ValidatePath vérifie le chemin d'un emplacement : « /api », « /a/b », sans
// caractère que Caddy interpréterait (joker, accolades, espace).
func ValidatePath(p string) error {
	if len(p) < 2 || p[0] != '/' || strings.HasSuffix(p, "/") {
		return fmt.Errorf("le chemin %q doit commencer par « / », ne pas finir par « / » et contenir un nom, par exemple /api", p)
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/-._~", r)) {
			return fmt.Errorf("le chemin %q contient un caractère non accepté (%q) : lettres, chiffres et - . _ ~ / seulement", p, r)
		}
	}
	if strings.Contains(p, "//") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return fmt.Errorf("le chemin %q est invalide", p)
	}
	return nil
}
