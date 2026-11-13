package web

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/certs"
	"github.com/jogit/gatewyn/internal/checks"
	"github.com/jogit/gatewyn/internal/crowdsec"
	"github.com/jogit/gatewyn/internal/store"
)

type eventView struct{ Class, Text, When string }

// events traduit les dernières lignes du journal d'audit liées aux hôtes.
func events(entries []store.AuditEntry, now time.Time) []eventView {
	var out []eventView
	for _, e := range entries {
		domain, _, _ := strings.Cut(e.Detail, " ")
		var text, class string
		switch e.Action {
		case "host.create":
			text, class = fmt.Sprintf("Hôte %s créé", domain), "ok"
		case "host.update":
			text, class = fmt.Sprintf("Hôte %s modifié", domain), "ok"
		case "host.enable":
			text, class = fmt.Sprintf("Hôte %s activé", domain), "ok"
		case "host.disable":
			text, class = fmt.Sprintf("Hôte %s désactivé", domain), "warn"
		case "host.delete":
			text, class = fmt.Sprintf("Hôte %s supprimé", domain), "warn"
		default:
			continue
		}
		out = append(out, eventView{class, text, ago(now, e.At)})
	}
	return out
}

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("il y a %d h", int(d.Hours()))
	}
	return fmt.Sprintf("le %s", t.Local().Format("02/01 15:04"))
}

// watchItem est une ligne de « À surveiller ».
type watchItem struct {
	Class, Label, Domain, Text, Href string
}

// csTile est l'état de la case Protection, connu après un appel à CrowdSec.
type csTile struct {
	State     string // ok, err, off
	Decisions int
}

// dashOnline est ce que renvoie /dashboard/online : la case Services, et par échange hors bande
// la case Protection et la liste « À surveiller ».
type dashOnline struct {
	Online, Total, Failed int
	CS                    *csTile // nil : CrowdSec non installé
	Watch                 []watchItem
}

// maxAlerts : nombre d'alertes montrées d'emblée ; les autres se déplient.
const maxAlerts = 4

func (d dashOnline) First() []watchItem {
	return d.Watch[:min(len(d.Watch), maxAlerts)]
}

func (d dashOnline) Rest() []watchItem {
	if len(d.Watch) <= maxAlerts {
		return nil
	}
	return d.Watch[maxAlerts:]
}

// MoreLabel : le texte du bouton qui déplie les alertes en plus.
func (d dashOnline) MoreLabel() string {
	return plural(len(d.Watch)-maxAlerts, "%d autre alerte", "%d autres alertes")
}

// fillStrip remplit la bande d'état de la liste des hôtes : certificats, trafic, protection.
// Les cases qui demandent un appel réseau (services en ligne, CrowdSec) sont chargées après coup.
func (s *Server) fillStrip(ctx context.Context, p *page, hosts []store.Host) {
	// Certificats : nombre et prochaine échéance, lus sur le disque.
	if p.CertsReadable = s.cfg.CertDir != ""; p.CertsReadable {
		list, _ := certs.List(s.cfg.CertDir)
		now := s.cfg.Now()
		p.CertCount = len(list)
		// L'échéance et la couleur ne concernent que les certificats des hôtes publiés : un
		// vieux certificat resté sur le disque après la suppression d'un hôte n'est pas un problème.
		var next time.Time
		for _, hc := range s.hostCerts(hosts) {
			if next.IsZero() || hc.cert.Expires.Before(next) {
				next = hc.cert.Expires
			}
		}
		if !next.IsZero() {
			p.CertNext, p.CertClass = daysLeft(now, next), expiryClass(now, next)
		}
	}
	// Trafic : résumé du journal d'accès, s'il est activé.
	s.fillAccessLog(ctx, p)
	if p.AccessLogOn {
		_, p.StatsSum = readRequests(s.cfg.AccessLogFile, 0, 5000)
	}
	if c, err := s.loadCrowdSec(ctx); err == nil {
		p.CSConfigured = c.URL != ""
	}
}

// dashboardOnline vérifie la cible de chaque service actif et résume le résultat. Dans la même requête
// (pour n'attendre qu'une fois), il interroge CrowdSec et dresse la liste « À surveiller ».
func (s *Server) dashboardOnline(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.cfg.Store.ListHosts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	d := dashOnline{}
	for _, h := range hosts {
		if kindFromForm(h.Kind) != caddyconf.KindProxy || h.Disabled {
			continue
		}
		d.Total++
		wg.Add(1)
		go func(id int64, domain, target string, skip bool) {
			defer wg.Done()
			res := s.cfg.CheckTarget(ctx, target, skip)
			mu.Lock()
			defer mu.Unlock()
			if res.Status != checks.Error {
				d.Online++
				return
			}
			d.Watch = append(d.Watch, watchItem{Class: "err", Label: "Injoignable", Domain: domain, Text: res.Message, Href: hostEditPath(id)})
		}(h.ID, h.Domain, h.Target, h.TLSSkipVerify)
	}
	wg.Add(1)
	go func() { // CrowdSec
		defer wg.Done()
		c, err := s.loadCrowdSec(ctx)
		if err != nil || c.URL == "" {
			return
		}
		tile := &csTile{State: "off"}
		if c.Enabled {
			if dec, err := crowdsec.Decisions(ctx, s.csClient(), c.URL, c.Key); err != nil {
				tile.State = "err"
			} else {
				tile.State, tile.Decisions = "ok", len(dec)
			}
		}
		mu.Lock()
		d.CS = tile
		mu.Unlock()
	}()
	wg.Wait()
	d.Failed = d.Total - d.Online
	// Les hôtes en erreur d'abord, dans un ordre stable.
	sort.Slice(d.Watch, func(i, j int) bool { return d.Watch[i].Domain < d.Watch[j].Domain }) // ordre stable
	for _, h := range hosts {
		if msg := s.certProblem(h); msg != "" {
			d.Watch = append(d.Watch, watchItem{Class: "err", Label: "Certificat", Domain: h.Domain, Text: msg, Href: hostEditPath(h.ID)})
		}
	}
	d.Watch = append(d.Watch, s.expiringCerts(hosts)...)
	s.renderFragment(w, "hosts", "online", d)
}

func hostEditPath(id int64) string { return fmt.Sprintf("/hosts/%d/edit", id) }

type hostCert struct {
	host store.Host
	cert certs.Cert
}

// hostCerts associe chaque hôte actif en HTTPS au certificat qui le sert, s'il existe.
func (s *Server) hostCerts(hosts []store.Host) []hostCert {
	byName := s.certsByName()
	var out []hostCert
	for _, h := range hosts {
		if h.Disabled || h.HTTPOnly || h.SelfSigned {
			continue
		}
		if c, ok := certFor(byName, h.Domain); ok {
			out = append(out, hostCert{h, c})
		}
	}
	return out
}

// expiringCerts signale les certificats des hôtes publiés qui expirent sous 14 jours, ou qui ont expiré.
func (s *Server) expiringCerts(hosts []store.Host) []watchItem {
	now := s.cfg.Now()
	var out []watchItem
	for _, hc := range s.hostCerts(hosts) {
		class := expiryClass(now, hc.cert.Expires)
		if class == "ok" {
			continue
		}
		text := fmt.Sprintf("Le certificat expire dans %s.", daysLeft(now, hc.cert.Expires))
		label := "Expire bientôt"
		if class == "err" {
			text, label = "Le certificat a expiré.", "Expiré"
		}
		out = append(out, watchItem{Class: class, Label: label, Domain: hc.host.Domain, Text: text, Href: hostEditPath(hc.host.ID)})
	}
	return out
}
