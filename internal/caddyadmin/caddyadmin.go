// Package caddyadmin pilote Caddy par son API d'administration.
//
// Gatewyn ne remplace jamais toute la configuration (POST /load) : cela
// réinitialiserait aussi les réglages d'administration et couperait l'accès.
// Il crée ou remplace seulement son serveur, à /config/apps/http/servers/gatewyn,
// son serveur HTTP (hôtes sans HTTPS, à ...-http) et les règles d'obtention des
// certificats, à /config/apps/tls/automation.
// En cas de configuration invalide, Caddy refuse et garde l'état précédent
// (vérifié sur un Caddy réel).
package caddyadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jogit/gatewyn/internal/caddyconf"
)

const crowdsecPath = "/config/apps/crowdsec"

// accessLogPath : le journal d'accès de Gatewyn, à côté des journaux propres à Caddy.
const accessLogPath = "/config/logging/logs/" + caddyconf.AccessLogName

// defaultLogPath : le journal principal de Caddy (stderr), qui ne doit pas recevoir les accès.
const defaultLogPath = "/config/logging/logs/default"

const (
	serverPath     = "/config/apps/http/servers/" + caddyconf.ServerName
	httpServerPath = "/config/apps/http/servers/" + caddyconf.ServerName + "-http"
	tlsPath        = "/config/apps/tls/automation"
)

// Client parle à l'API d'administration d'un Caddy.
type Client struct {
	BaseURL string // ex. http://caddy:2019
	HTTP    *http.Client
}

// New crée un client avec un délai d'attente raisonnable.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// APIError est une réponse d'erreur de Caddy.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("caddy a refusé la configuration (HTTP %d) : %s", e.Status, e.Message)
}

// Apply publie les hôtes sans réglage global (ni CrowdSec ni proxies de confiance).
func (c *Client) Apply(ctx context.Context, hosts []caddyconf.Host) error {
	return c.ApplyAll(ctx, hosts, caddyconf.Global{})
}

// ApplyAll publie les hôtes : crée ou remplace les serveurs Gatewyn dans Caddy, et
// le bouncer CrowdSec si g.CrowdSec n'est pas nil (sinon il est retiré). Les hôtes qui
// demandent CrowdSec (Host.CrowdSec) ne sont protégés que si g.CrowdSec est donné.
func (c *Client) ApplyAll(ctx context.Context, hosts []caddyconf.Host, g caddyconf.Global) error {
	cs := g.CrowdSec
	body, err := caddyconf.ServerJSON(hosts, g)
	if err != nil {
		return err
	}
	tls, err := caddyconf.TLSJSON(hosts)
	if err != nil {
		return err
	}
	httpBody, err := caddyconf.HTTPServerJSON(hosts, g)
	if err != nil {
		return err
	}
	// L'application CrowdSec d'abord : les routes qui s'en servent en dépendent.
	if cs != nil {
		csBody, err := caddyconf.CrowdSecJSON(*cs)
		if err != nil {
			return err
		}
		if err := c.put(ctx, crowdsecPath, csBody); err != nil {
			return err
		}
	}
	// Le journal d'accès avant les serveurs qui y écrivent.
	if g.AccessLog != nil {
		logBody, err := caddyconf.AccessLogJSON(*g.AccessLog)
		if err != nil {
			return err
		}
		if err := c.put(ctx, accessLogPath, logBody); err != nil {
			return err
		}
		defBody, err := caddyconf.DefaultLogJSON()
		if err != nil {
			return err
		}
		if err := c.put(ctx, defaultLogPath, defBody); err != nil {
			return err
		}
	}
	// Les règles de certificat ensuite : le serveur peut en dépendre.
	if err := c.put(ctx, tlsPath, tls); err != nil {
		return err
	}
	if err := c.put(ctx, serverPath, body); err != nil {
		return err
	}
	if httpBody == nil { // plus d'hôte en HTTP seulement : on retire le serveur s'il existe
		if err := c.remove(ctx, httpServerPath); err != nil {
			return err
		}
	} else if err := c.put(ctx, httpServerPath, httpBody); err != nil {
		return err
	}
	if g.AccessLog == nil { // retiré après les serveurs qui y écrivaient
		if err := c.remove(ctx, accessLogPath); err != nil {
			return err
		}
		if err := c.remove(ctx, defaultLogPath); err != nil {
			return err
		}
	}
	if cs == nil { // retiré en dernier : plus aucune route ne s'en sert
		return c.remove(ctx, crowdsecPath)
	}
	return nil
}

// remove supprime la configuration à path ; l'absence n'est pas une erreur.
func (c *Client) remove(ctx context.Context, path string) error {
	_, err := c.do(ctx, http.MethodDelete, path, nil)
	var apiErr *APIError
	if err != nil && !errors.As(err, &apiErr) {
		return err
	}
	return nil
}

// CrowdSecStatus est l'état du bouncer CrowdSec dans Caddy.
type CrowdSecStatus struct {
	Healthy   bool   // Caddy joint l'API locale de CrowdSec
	Streaming bool   // les décisions sont gardées en mémoire (mode flux)
	Interval  string // intervalle de mise à jour en mode flux, ex. « 10s »
	Decisions int    // décisions actives connues du bouncer
}

// CrowdSecStatus interroge l'API d'administration du module (/crowdsec/health et /info).
// Une erreur signifie que le bouncer n'est pas chargé dans Caddy.
func (c *Client) CrowdSecStatus(ctx context.Context) (CrowdSecStatus, error) {
	var st CrowdSecStatus
	// Le module n'accepte que POST sur ces points d'état ; ils ne modifient rien.
	raw, err := c.do(ctx, http.MethodPost, "/crowdsec/health", nil)
	if err != nil {
		return st, err
	}
	var h struct {
		Ok bool `json:"ok"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return st, err
	}
	st.Healthy = h.Ok
	raw, err = c.do(ctx, http.MethodPost, "/crowdsec/info", nil)
	if err != nil {
		return st, err
	}
	var info struct {
		Streaming struct {
			Enabled  bool   `json:"enabled"`
			Interval string `json:"interval"`
		} `json:"streaming"`
		Decisions int `json:"number_of_active_decisions"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return st, err
	}
	st.Streaming, st.Interval, st.Decisions = info.Streaming.Enabled, info.Streaming.Interval, info.Decisions
	return st, nil
}

// put crée ou remplace la configuration à path. PUT crée l'élément (et les
// niveaux manquants d'un Caddy neuf) ; s'il existe déjà, Caddy répond 409 et
// PATCH le remplace. POST échoue sur un Caddy neuf (« invalid traversal path »).
func (c *Client) put(ctx context.Context, path string, body []byte) error {
	_, err := c.do(ctx, http.MethodPut, path, body)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
		_, err = c.do(ctx, http.MethodPatch, path, body)
	}
	return err
}

// Hosts relit les hôtes actuellement publiés dans Caddy. Renvoie une liste
// vide si le serveur Gatewyn n'existe pas encore.
func (c *Client) Hosts(ctx context.Context) ([]caddyconf.Host, error) {
	raw, err := c.do(ctx, http.MethodGet, serverPath, nil)
	if err != nil {
		return nil, err
	}
	return parseHosts(raw)
}

// Ping vérifie que l'API d'administration répond.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/config/", nil)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("impossible de joindre Caddy à %s : %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return nil, &APIError{Status: resp.StatusCode, Message: msg}
	}
	return data, nil
}

// parseHosts lit le JSON du serveur Gatewyn tel que Caddy le renvoie.
func parseHosts(raw []byte) ([]caddyconf.Host, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return []caddyconf.Host{}, nil
	}
	var srv struct {
		Routes []struct {
			Match []struct {
				Host []string `json:"host"`
				Path []string `json:"path"`
			} `json:"match"`
			Handle []struct {
				Handler    string          `json:"handler"`
				StatusCode json.Number     `json:"status_code"`
				Headers    json.RawMessage // static_response : en-têtes de réponse (reverse_proxy : autre forme, ignorée)
				Upstreams  []struct {
					Dial string `json:"dial"`
				} `json:"upstreams"`
				Transport *struct {
					TLS *json.RawMessage `json:"tls"`
				} `json:"transport"`
			} `json:"handle"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &srv); err != nil {
		return nil, fmt.Errorf("réponse de Caddy illisible : %w", err)
	}
	const keepPath = "{http.request.uri}"
	hosts := []caddyconf.Host{}
	locations := map[string][]caddyconf.Location{}
	for _, r := range srv.Routes {
		var domain string
		var aliases []string
		for _, m := range r.Match {
			if len(m.Host) > 0 {
				domain, aliases = m.Host[0], nil
				if len(m.Host) > 1 {
					aliases = m.Host[1:]
				}
			}
		}
		if domain == "" {
			continue
		}
		var path string
		for _, m := range r.Match {
			if len(m.Path) > 0 {
				path = m.Path[0]
			}
		}
		for _, h := range r.Handle {
			switch {
			case h.Handler == "reverse_proxy" && len(h.Upstreams) > 0:
				scheme := "http"
				if h.Transport != nil && h.Transport.TLS != nil {
					scheme = "https"
				}
				if path != "" { // emplacement : rattaché à l'hôte plus bas
					locations[domain] = append(locations[domain], caddyconf.Location{Path: path, Target: scheme + "://" + h.Upstreams[0].Dial})
					continue
				}
				hosts = append(hosts, caddyconf.Host{Domain: domain, Aliases: aliases, Target: scheme + "://" + h.Upstreams[0].Dial})
			case h.Handler == "static_response" && len(location(h.Headers)) > 0:
				code, _ := h.StatusCode.Int64()
				loc := location(h.Headers)[0]
				keep := strings.HasSuffix(loc, keepPath)
				hosts = append(hosts, caddyconf.Host{Domain: domain, Aliases: aliases, Kind: caddyconf.KindRedirect,
					Target: strings.TrimSuffix(loc, keepPath), Code: int(code), PreservePath: keep})
			case h.Handler == "static_response" && h.StatusCode.String() == "404":
				hosts = append(hosts, caddyconf.Host{Domain: domain, Aliases: aliases, Kind: caddyconf.KindNotFound})
			}
		}
	}
	for i := range hosts {
		hosts[i].Locations = locations[hosts[i].Domain]
	}
	return hosts, nil
}

// location lit l'en-tête Location d'une réponse statique (les en-têtes d'un reverse_proxy n'ont pas cette forme).
func location(raw json.RawMessage) []string {
	var m map[string][]string
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m["Location"]
}
