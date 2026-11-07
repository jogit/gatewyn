package web

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/jogit/gatewyn/internal/crowdsec"
)

// maxDecisionsShown : au-delà, la liste est tronquée (CrowdSec en connaît parfois des dizaines de milliers).
const maxDecisionsShown = 200

type decisionView struct{ Value, Scenario, Origin, Remaining string }

// remainingFR écrit la durée restante d'une décision : « 3 j 02 h », « 3 h 41 », « 12 min ».
func remainingFR(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d j %02d h", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%d h %02d", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d min", max(int(d.Minutes()), 1))
}

// decisionsPage liste les adresses que CrowdSec fait bloquer. Lecture seule : Gatewyn ne bannit
// ni ne débannit rien, l'interface de CrowdSec sert à cela.
func (s *Server) decisionsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.loadCrowdSec(ctx)
	if err != nil || c.URL == "" {
		http.Redirect(w, r, "/security/protection", http.StatusSeeOther)
		return
	}
	p := s.authedPage(r, "Adresses bloquées", "security-crowdsec")
	p.CS.WebUIURL = s.crowdSecWebUIURL(ctx, c.URL, pageHost(r))
	if !c.Enabled {
		p.Error = "CrowdSec est désactivé : Caddy ne bloque plus ces adresses."
	}
	dec, err := crowdsec.Decisions(ctx, s.csClient(), c.URL, c.Key)
	if err != nil {
		p.Error = explainCrowdSecError(err, c.URL)
	}
	sort.SliceStable(dec, func(i, j int) bool { return dec[i].Remaining > dec[j].Remaining })
	p.DecisionsTotal = len(dec)
	for i, d := range dec {
		if i == maxDecisionsShown {
			break
		}
		p.Decisions = append(p.Decisions, decisionView{d.Value, d.Scenario, d.Origin, remainingFR(d.Remaining)})
	}
	s.render(w, "decisions", p)
}
