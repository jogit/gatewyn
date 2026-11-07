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
	Class, Label, Text, Href string
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

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entries, err := s.cfg.Store.RecentAudit(ctx, 50)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	hosts, err := s.cfg.Store.ListHosts(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.authedPage(r, "Vue d'ensemble", "dashboard")
	p.Events = events(entries, s.cfg.Now())
	if len(p.Events) > 8 {
		p.Events = p.Events[:8]
	}
	p.HasHosts = len(hosts) > 0

	// Certificats : nombre et prochaine échéance, lus sur le disque.
	if p.CertsReadable = s.cfg.CertDir != ""; p.CertsReadable {
		list, _ := certs.List(s.cfg.CertDir)
		now := s.cfg.Now()
		p.CertCount = len(list)
		var next time.Time
		for _, c := range list {
			if next.IsZero() || c.Expires.Before(next) {
				next = c.Expires
			}
		}
		if !next.IsZero() {
			p.CertNext, p.CertClass = daysLeft(now, next), expiryClass(now, next)
		}
	}
	// Trafic : résumé du journal d'accès, s'il est activé.
	s.fillAccessLog(ctx, &p)
	if p.AccessLogOn {
		_, p.StatsSum = readRequests(s.cfg.AccessLogFile, 0, 5000)
	}
	if c, err := s.loadCrowdSec(ctx); err == nil {
		p.CSConfigured = c.URL != ""
	}
	s.render(w, "dashboard", p)
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
		go func(domain, target string, skip bool) {
			defer wg.Done()
			res := s.cfg.CheckTarget(ctx, target, skip)
			mu.Lock()
			defer mu.Unlock()
			if res.Status != checks.Error {
				d.Online++
				return
			}
			d.Watch = append(d.Watch, watchItem{Class: "err", Label: "Injoignable", Text: domain + " : " + res.Message, Href: "/hosts"})
		}(h.Domain, h.Target, h.TLSSkipVerify)
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
	sort.Slice(d.Watch, func(i, j int) bool { return d.Watch[i].Text < d.Watch[j].Text }) // ordre stable
	for _, h := range hosts {
		if msg := s.certProblem(h); msg != "" {
			d.Watch = append(d.Watch, watchItem{Class: "err", Label: "Certificat", Text: h.Domain + " : " + msg, Href: "/hosts"})
		}
	}
	d.Watch = append(d.Watch, s.expiringCerts()...)
	s.renderFragment(w, "dashboard", "online", d)
}

// expiringCerts signale les certificats qui expirent sous 14 jours, ou qui ont expiré.
func (s *Server) expiringCerts() []watchItem {
	if s.cfg.CertDir == "" {
		return nil
	}
	list, _ := certs.List(s.cfg.CertDir)
	now := s.cfg.Now()
	var out []watchItem
	for _, c := range list {
		class := expiryClass(now, c.Expires)
		if class == "ok" {
			continue
		}
		text := fmt.Sprintf("Le certificat de %s expire dans %s.", c.Domain, daysLeft(now, c.Expires))
		label := "Expire bientôt"
		if class == "err" {
			text, label = fmt.Sprintf("Le certificat de %s a expiré.", c.Domain), "Expiré"
		}
		out = append(out, watchItem{Class: class, Label: label, Text: text, Href: "/certificates"})
	}
	return out
}
