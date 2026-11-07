package web

import (
	"context"
	"fmt"

	"github.com/jogit/gatewyn/internal/store"
)

// hostStrip : la bande d'état de la page d'un hôte (certificat, trafic, protection).
type hostStrip struct {
	Domain                   string
	CertTitle, CertSub       string
	CertClass                string
	TrafficTitle, TrafficSub string
	ProtTitle, ProtSub       string
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf(one, n)
	}
	return fmt.Sprintf(many, n)
}

// hostStrip prépare la bande d'état d'un hôte existant, avec ce que Gatewyn sait déjà sans appel réseau.
func (s *Server) hostStrip(ctx context.Context, h store.Host) hostStrip {
	st := hostStrip{Domain: h.Domain}
	now := s.cfg.Now()
	switch c, ok := s.certsByName()[h.Domain]; {
	case h.Disabled:
		st.CertTitle, st.CertSub = "—", "Hôte désactivé"
	case h.HTTPOnly:
		st.CertTitle, st.CertSub = "Aucun certificat", "HTTP seulement"
	case ok:
		left, class := daysLeft(now, c.Expires), expiryClass(now, c.Expires)
		st.CertTitle = "Valide"
		switch class {
		case "warn":
			st.CertTitle, st.CertClass = "Expire bientôt", "warn"
		case "err":
			st.CertTitle, st.CertClass, left = "Expiré", "err", ""
		}
		st.CertSub = fmt.Sprintf("%s · expire dans %s", c.Issuer, left)
		if class == "err" {
			st.CertSub = c.Issuer
		}
	default:
		st.CertTitle, st.CertSub = "En attente", "Un certificat apparaît après la première visite du domaine."
	}
	var log page
	s.fillAccessLog(ctx, &log)
	switch {
	case !log.AccessLogOn:
		st.TrafficTitle, st.TrafficSub = "—", "journal d'accès désactivé"
	default:
		_, sum := readRequests(s.cfg.AccessLogFile, 0, 5000)
		st.TrafficTitle, st.TrafficSub = "0 requête", "rien dans le journal"
		for _, ht := range sum.Hosts {
			if ht.Host == h.Domain {
				st.TrafficTitle = plural(ht.Requests, "%d requête", "%d requêtes")
				st.TrafficSub = plural(ht.Errs, "%d erreur", "%d erreurs")
			}
		}
	}
	if cs, _ := s.activeCrowdSec(ctx); cs != nil {
		st.ProtTitle, st.ProtSub = "CrowdSec", "blocage des adresses signalées"
		if h.WAF {
			st.ProtTitle, st.ProtSub = "CrowdSec + WAF", "adresses signalées et attaques connues"
		}
	} else {
		st.ProtTitle, st.ProtSub = "Aucune", "CrowdSec n'est pas connecté"
	}
	return st
}

// hostRecent renvoie les dernières requêtes reçues par un domaine, dans la fin du journal d'accès.
func (s *Server) hostRecent(ctx context.Context, domain string, n int) []reqView {
	var p page
	s.fillAccessLog(ctx, &p)
	if !p.AccessLogOn {
		return nil
	}
	all, _ := readRequests(s.cfg.AccessLogFile, 5000, 5000)
	var out []reqView
	for _, r := range all {
		if r.Host == domain {
			out = append(out, r)
			if len(out) == n {
				break
			}
		}
	}
	return out
}
