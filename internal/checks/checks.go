// Package checks vérifie, avant et après la création d'un hôte, ce qui fait
// échouer une première publication : le DNS du domaine et la réponse de la
// cible. Chaque résultat porte un message en clair et une action à faire,
// jamais un code d'erreur brut.
package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jogit/gatewyn/internal/caddyconf"
)

// Status est la gravité d'un résultat.
type Status string

const (
	OK    Status = "ok"
	Info  Status = "info"
	Warn  Status = "warn"
	Error Status = "error"
)

// Result est le résultat d'une vérification. Code est stable (traduction).
type Result struct {
	Status  Status
	Code    string
	Message string
}

// Resolver est satisfait par *net.Resolver et par un faux dans les tests.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DNS vérifie que le domaine pointe vers l'une des adresses publiques
// données. Sans adresse publique connue, il vérifie seulement que le domaine
// existe et le dit.
func DNS(ctx context.Context, r Resolver, domain string, publicIPs []string) Result {
	if strings.HasPrefix(domain, "*.") {
		return Result{Info, "dns_wildcard", "Domaine joker : le DNS ne peut pas être vérifié à l'avance. Le certificat d'un joker demande un défi DNS (avancé)."}
	}
	addrs, err := r.LookupHost(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			if len(publicIPs) > 0 {
				return Result{Error, "dns_not_found", fmt.Sprintf("Le domaine %s n'existe pas dans le DNS. Créez chez votre registraire un enregistrement A vers %s.", domain, strings.Join(publicIPs, " ou "))}
			}
			return Result{Error, "dns_not_found", fmt.Sprintf("Le domaine %s n'existe pas dans le DNS. Créez chez votre registraire un enregistrement A.", domain)}
		}
		return Result{Warn, "dns_unavailable", fmt.Sprintf("Impossible de vérifier le DNS de %s pour l'instant (%s). Réessayez dans un moment.", domain, shortErr(err))}
	}
	sort.Strings(addrs)
	addrs = slices.Compact(addrs) // le résolveur peut répéter la même adresse
	if len(publicIPs) == 0 {
		return Result{Info, "dns_unknown_ip", fmt.Sprintf("%s pointe vers %s.", domain, strings.Join(addrs, ", "))}
	}
	want := map[string]bool{}
	for _, ip := range publicIPs {
		want[normalizeIP(ip)] = true
	}
	var match, other []string
	for _, a := range addrs {
		if want[normalizeIP(a)] {
			match = append(match, a)
		} else {
			other = append(other, a)
		}
	}
	switch {
	case len(match) == 0:
		return Result{Error, "dns_wrong_ip", fmt.Sprintf("Le domaine %s ne pointe pas vers votre IP : il pointe vers %s, votre adresse publique est %s. Modifiez l'enregistrement A chez votre registraire.",
			domain, strings.Join(addrs, ", "), strings.Join(publicIPs, " ou "))}
	case len(other) > 0:
		return Result{Warn, "dns_extra_ip", fmt.Sprintf("%s pointe vers votre IP, mais aussi vers %s. Le certificat peut échouer si Let's Encrypt interroge l'autre adresse.",
			domain, strings.Join(other, ", "))}
	}
	return Result{OK, "dns_ok", fmt.Sprintf("%s pointe vers %s, votre adresse publique.", domain, strings.Join(match, ", "))}
}

// Target vérifie que le service répond. Une réponse HTTP, quel que soit son
// code, prouve que le service est joignable ; seuls les échecs de connexion
// sont des erreurs.
func Target(ctx context.Context, target string) Result {
	dial, useTLS, err := caddyconf.ParseTarget(target)
	if err != nil {
		return Result{Error, "target_invalid", capitalize(err.Error()) + "."}
	}
	if caddyconf.IsH2C(target) {
		// Un service gRPC (HTTP/2 sans chiffrement) refuse une requête HTTP/1.1 : on teste seulement la connexion.
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", dial)
		if err != nil {
			return explainTargetError(dial, err)
		}
		conn.Close()
		return Result{OK, "target_ok", fmt.Sprintf("La cible accepte les connexions (%s). Le protocole HTTP/2 n'est pas testé.", dial)}
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Pas de suivi de redirection : on veut la réponse de la cible elle-même.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if useTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{}}
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+dial+"/", nil)
	if err != nil {
		return Result{Error, "target_invalid", "Adresse de cible invalide."}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return explainTargetError(dial, err)
	}
	defer resp.Body.Close()
	ms := time.Since(start).Milliseconds()
	msg := fmt.Sprintf("La cible répond (%d, %d ms).", resp.StatusCode, ms)
	if resp.StatusCode >= 500 {
		return Result{Warn, "target_5xx", fmt.Sprintf("La cible répond mais avec une erreur (%d). Vérifiez que le service est bien démarré.", resp.StatusCode)}
	}
	return Result{OK, "target_ok", msg}
}

func explainTargetError(dial string, err error) Result {
	err = lowered{err}
	var dnsErr *net.DNSError
	var unknownAuth x509.UnknownAuthorityError
	var certInvalid x509.CertificateInvalidError
	var hostErr x509.HostnameError
	switch {
	case errors.As(err, &dnsErr):
		return Result{Error, "target_dns", fmt.Sprintf("Le nom de la cible (%s) est introuvable. Vérifiez l'orthographe, ou utilisez son adresse IP.", hostOf(dial))}
	case errors.As(err, &unknownAuth), errors.As(err, &certInvalid), errors.As(err, &hostErr):
		return Result{Warn, "target_cert", fmt.Sprintf("La cible %s répond en HTTPS avec un certificat que Caddy ne reconnaît pas (courant sur un NAS ou un routeur). Choisissez http:// si le service l'accepte.", dial)}
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return Result{Error, "target_timeout", fmt.Sprintf("La cible %s ne répond pas (délai dépassé). Vérifiez l'adresse, le port et le pare-feu.", dial)}
	case strings.Contains(err.Error(), "server gave http response to https client"),
		strings.Contains(err.Error(), "first record does not look like a tls handshake"):
		return Result{Error, "target_protocol", fmt.Sprintf("La cible %s répond en HTTP simple et non en HTTPS. Utilisez une adresse en http://.", dial)}
	case strings.Contains(err.Error(), "connection reset"), errors.Is(err, io.EOF), strings.HasSuffix(err.Error(), "eof"):
		return Result{Error, "target_reset", fmt.Sprintf("La cible %s a coupé la connexion sans répondre. Le port est peut-être incorrect, ou le service attend du HTTPS : essayez https://.", dial)}
	case strings.Contains(err.Error(), "connection refused"):
		return Result{Error, "target_refused", fmt.Sprintf("Connexion refusée par %s. Le service n'écoute pas sur ce port : vérifiez qu'il est démarré et que le port est le bon.", dial)}
	case strings.Contains(err.Error(), "no route to host"), strings.Contains(err.Error(), "network is unreachable"):
		return Result{Error, "target_unreachable", fmt.Sprintf("La machine %s est injoignable depuis ici. Vérifiez l'adresse et que Gatewyn est sur le même réseau.", dial)}
	}
	return Result{Error, "target_failed", fmt.Sprintf("Impossible de joindre %s (%s).", dial, shortErr(err))}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func hostOf(dial string) string {
	h, _, err := net.SplitHostPort(dial)
	if err != nil {
		return dial
	}
	return h
}

func normalizeIP(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(s)
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func capitalize(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// lowered rend le texte d'une erreur en minuscules pour les comparaisons,
// tout en gardant l'erreur d'origine accessible à errors.As et errors.Is.
type lowered struct{ error }

func (l lowered) Error() string { return strings.ToLower(l.error.Error()) }
func (l lowered) Unwrap() error { return l.error }
