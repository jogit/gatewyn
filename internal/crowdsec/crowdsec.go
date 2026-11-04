// Package crowdsec lit les décisions de l'API locale (LAPI) de CrowdSec, en lecture
// seule, avec la clé d'un bouncer. Gatewyn n'y écrit jamais.
package crowdsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Erreurs distinguées pour des messages clairs.
var (
	ErrBadKey      = errors.New("CrowdSec a refusé la clé du bouncer")
	ErrUnreachable = errors.New("CrowdSec est injoignable")
)

// Decision est une adresse (ou une plage) bloquée.
type Decision struct {
	ID        int64
	Value     string // adresse IP ou plage
	Scope     string // « Ip » ou « Range »
	Type      string // « ban », « captcha »…
	Scenario  string // motif, ex. crowdsecurity/http-probing
	Origin    string // ex. crowdsec, cscli, CAPI
	Remaining time.Duration
}

// Decisions renvoie les décisions actives de la LAPI à l'adresse url.
func Decisions(ctx context.Context, client *http.Client, url, key string) ([]Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/v1/decisions", nil)
	if err != nil {
		return nil, fmt.Errorf("adresse de CrowdSec invalide : %w", err)
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("User-Agent", "gatewyn")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrUnreachable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, ErrUnreachable
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, ErrBadKey
	default:
		return nil, fmt.Errorf("CrowdSec a répondu %d", resp.StatusCode)
	}
	// Aucune décision : la LAPI répond « null ».
	var raw []struct {
		ID       int64  `json:"id"`
		Value    string `json:"value"`
		Scope    string `json:"scope"`
		Type     string `json:"type"`
		Scenario string `json:"scenario"`
		Origin   string `json:"origin"`
		Duration string `json:"duration"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errors.New("réponse de CrowdSec illisible")
	}
	out := make([]Decision, 0, len(raw))
	for _, d := range raw {
		left, _ := time.ParseDuration(d.Duration)
		out = append(out, Decision{ID: d.ID, Value: d.Value, Scope: d.Scope, Type: d.Type, Scenario: d.Scenario, Origin: d.Origin, Remaining: left})
	}
	return out, nil
}

// AppSecUp vérifie seulement qu'AppSec accepte les connexions. Contrairement à AppSecCheck,
// elle n'envoie aucune requête : AppSec ne la compte donc pas dans ses statistiques.
func AppSecUp(ctx context.Context, url string) error {
	u, err := neturl.Parse(url)
	if err != nil || u.Host == "" {
		return fmt.Errorf("adresse d'AppSec invalide")
	}
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", host)
	if err != nil {
		return ErrUnreachable
	}
	return conn.Close()
}

// AppSecCheck vérifie que le composant AppSec (WAF) répond et accepte la clé du bouncer,
// avec une requête anodine. Il répond « allow » (200) ou « ban » (403) selon ses règles :
// les deux prouvent qu'il fonctionne ; 401 signifie que la clé est refusée.
func AppSecCheck(ctx context.Context, client *http.Client, url, key string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/", nil)
	if err != nil {
		return fmt.Errorf("adresse d'AppSec invalide : %w", err)
	}
	for k, v := range map[string]string{
		"X-Crowdsec-Appsec-Ip":         "127.0.0.1",
		"X-Crowdsec-Appsec-Uri":        "/",
		"X-Crowdsec-Appsec-Host":       "gatewyn.local",
		"X-Crowdsec-Appsec-Verb":       "GET",
		"X-Crowdsec-Appsec-User-Agent": "gatewyn",
		"X-Crowdsec-Appsec-Api-Key":    key,
	} {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ErrUnreachable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		return nil
	case http.StatusUnauthorized:
		return ErrBadKey
	}
	return fmt.Errorf("AppSec a répondu %d", resp.StatusCode)
}

// RuleHit est le nombre de fois où une règle du WAF s'est déclenchée.
type RuleHit struct {
	Rule string
	Hits int64
}

// WAFStats résume l'activité d'AppSec depuis le démarrage de CrowdSec (les compteurs
// repartent de zéro à chaque redémarrage).
type WAFStats struct {
	Processed, Blocked int64
	Rules              []RuleHit // du plus déclenché au moins déclenché
}

var promLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+([0-9.eE+-]+)\s*$`)
var promRule = regexp.MustCompile(`rule_name="([^"]*)"`)

// Stats lit les métriques AppSec de CrowdSec (format Prometheus, lecture seule, sans
// identifiant) à l'adresse url, par exemple http://crowdsec:6060/metrics.
func Stats(ctx context.Context, client *http.Client, url string) (WAFStats, error) {
	var st WAFStats
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return st, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return st, ErrUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("les métriques de CrowdSec ont répondu %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return st, ErrUnreachable
	}
	hits := map[string]int64{}
	for _, line := range strings.Split(string(body), "\n") {
		m := promLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v, err := strconv.ParseFloat(m[4], 64)
		if err != nil {
			continue
		}
		switch m[1] {
		case "cs_appsec_reqs_total":
			st.Processed += int64(v)
		case "cs_appsec_block_total":
			st.Blocked += int64(v)
		case "cs_appsec_rule_hits":
			if r := promRule.FindStringSubmatch(m[3]); r != nil {
				hits[r[1]] += int64(v) // en bande et hors bande : on additionne
			}
		}
	}
	for rule, n := range hits {
		st.Rules = append(st.Rules, RuleHit{rule, n})
	}
	sort.Slice(st.Rules, func(i, j int) bool {
		return st.Rules[i].Hits > st.Rules[j].Hits || (st.Rules[i].Hits == st.Rules[j].Hits && st.Rules[i].Rule < st.Rules[j].Rule)
	})
	return st, nil
}

var cveRule = regexp.MustCompile(`vpatch-(CVE-\d{4}-\d+)`)

// RuleLabel donne un nom lisible à une règle du WAF, et l'identifiant brut s'il n'en a pas.
func RuleLabel(rule string) (label, raw string) {
	known := map[string]string{
		"crowdsecurity/vpatch-env-access":  "Accès à un fichier .env",
		"crowdsecurity/vpatch-git-config":  "Accès à .git/config",
		"crowdsecurity/vpatch-ds-store":    "Accès à un fichier .DS_Store",
		"crowdsecurity/vpatch-backup-file": "Accès à une sauvegarde",
	}
	if l, ok := known[rule]; ok {
		return l, rule
	}
	if m := cveRule.FindStringSubmatch(rule); m != nil {
		return "Faille connue (" + m[1] + ")", rule
	}
	return rule, ""
}
