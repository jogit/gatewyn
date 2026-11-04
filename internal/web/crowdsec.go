package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/crowdsec"
)

const (
	settingCSURL = "crowdsec.url"
	settingCSKey = "crowdsec.key" // chiffrée
	settingCSOn  = "crowdsec.enabled"

	settingCSAppSec         = "crowdsec.appsec_url"      // WAF : adresse d'AppSec, vide si inutilisé
	settingCSAppSecFailOpen = "crowdsec.appsec_failopen" // « 0 » : refuser les requêtes si AppSec est injoignable
)

const defaultAppSecURL = "http://crowdsec:7422"

const defaultCrowdSecURL = "http://crowdsec:8080"

// csConfig est la connexion à CrowdSec telle qu'enregistrée.
type csConfig struct {
	URL, Key       string
	Enabled        bool
	AppSecURL      string
	AppSecFailOpen bool
}

func (s *Server) loadCrowdSec(ctx context.Context) (csConfig, error) {
	var c csConfig
	var err error
	if c.URL, err = s.cfg.Store.Setting(ctx, settingCSURL); err != nil {
		return c, err
	}
	on, err := s.cfg.Store.Setting(ctx, settingCSOn)
	if err != nil {
		return c, err
	}
	c.Enabled = on == "1"
	if c.AppSecURL, err = s.cfg.Store.Setting(ctx, settingCSAppSec); err != nil {
		return c, err
	}
	failOpen, err := s.cfg.Store.Setting(ctx, settingCSAppSecFailOpen)
	if err != nil {
		return c, err
	}
	c.AppSecFailOpen = failOpen != "0" // par défaut, une panne d'AppSec ne coupe pas les sites
	sealed, err := s.cfg.Store.Setting(ctx, settingCSKey)
	if err != nil || sealed == "" {
		return c, err
	}
	if s.cfg.Secrets == nil {
		return c, errors.New("le chiffrement des identifiants n'est pas disponible")
	}
	if c.Key, err = s.cfg.Secrets.Unseal(sealed); err != nil {
		return c, fmt.Errorf("clé CrowdSec : %w", err)
	}
	return c, nil
}

func (s *Server) saveCrowdSec(ctx context.Context, c csConfig) error {
	sealed := ""
	if c.Key != "" {
		if s.cfg.Secrets == nil {
			return errors.New("le chiffrement des identifiants n'est pas disponible")
		}
		var err error
		if sealed, err = s.cfg.Secrets.Seal(c.Key); err != nil {
			return err
		}
	}
	on := "0"
	if c.Enabled {
		on = "1"
	}
	failOpen := "0"
	if c.AppSecFailOpen {
		failOpen = "1"
	}
	for k, v := range map[string]string{settingCSURL: c.URL, settingCSKey: sealed, settingCSOn: on, settingCSAppSec: c.AppSecURL, settingCSAppSecFailOpen: failOpen} {
		if err := s.cfg.Store.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

// activeCrowdSec renvoie la configuration à publier dans Caddy, ou nil si CrowdSec
// n'est pas connecté ou désactivé.
func (s *Server) activeCrowdSec(ctx context.Context) (*caddyconf.CrowdSec, error) {
	c, err := s.loadCrowdSec(ctx)
	if err != nil || !c.Enabled || c.URL == "" || c.Key == "" {
		return nil, err
	}
	return &caddyconf.CrowdSec{URL: c.URL, Key: c.Key, AppSecURL: c.AppSecURL, AppSecFailOpen: c.AppSecFailOpen}, nil
}

type csView struct {
	Configured, Enabled bool
	AppSec              bool
	URL                 string
	WebUIURL            string // interface locale fournie par le compose Gatewyn
	Sites               []protectedSite
	// Detected : pas encore connecté, mais le compose a déjà déployé CrowdSec (sa clé de bouncer est là).
	Detected bool
}

// protectedSite : un service publié et ce qui le protège.
type protectedSite struct {
	ID     int64
	Domain string
	WAF    bool
}

func (s *Server) crowdSecView(ctx context.Context, host string) csView {
	c, err := s.loadCrowdSec(ctx)
	if err != nil {
		s.cfg.Logger.Error("CrowdSec", "error", err)
	}
	v := csView{Configured: c.URL != "" && c.Key != "", Enabled: c.Enabled, AppSec: c.AppSecURL != "", URL: c.URL}
	v.WebUIURL = s.crowdSecWebUIURL(ctx, c.URL, host)
	v.Detected = !v.Configured && s.autoKey() != ""
	if v.Configured && v.Enabled {
		hosts, err := s.cfg.Store.ListHosts(ctx)
		if err != nil {
			s.cfg.Logger.Error("CrowdSec hosts", "error", err)
		}
		for _, h := range hosts {
			if h.Kind == caddyconf.KindProxy && !h.Disabled {
				v.Sites = append(v.Sites, protectedSite{h.ID, h.Domain, h.WAF && v.AppSec})
			}
		}
	}
	return v
}

// --- connexion ---

// crowdSecInstallPage guide une première installation sans toucher à Docker.
// Gatewyn fournit les fichiers et commandes, puis vérifie la connexion à l'étape suivante.
func (s *Server) crowdSecInstallPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Installer CrowdSec", "security-crowdsec")
	p.Heading = "Installer CrowdSec"
	s.render(w, "crowdsecinstall", p)
}

// autoKey renvoie la clé du bouncer que CrowdSec a déposée pour Gatewyn (compose Gatewyn), ou "".
func (s *Server) autoKey() string {
	if s.cfg.CrowdSecKeyFile == "" {
		return ""
	}
	b, err := os.ReadFile(s.cfg.CrowdSecKeyFile)
	if err != nil || len(b) > 4096 {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *Server) crowdSecForm(r *http.Request) page {
	p := s.authedPage(r, "Connecter CrowdSec", "security-crowdsec")
	p.Heading, p.Submit, p.ListPath = "Connecter CrowdSec", "Connecter", "/security/protection"
	p.Guided = r.URL.Query().Get("appsec") == "1"
	p.Name = defaultCrowdSecURL // adresse proposée
	p.AppSecFailOpen = true
	if c, _ := s.loadCrowdSec(r.Context()); c.URL != "" {
		p.Name, p.Editing = c.URL, true
		p.Heading, p.Submit = "Connexion à CrowdSec", "Enregistrer"
		p.AppSecURL, p.AppSecFailOpen = c.AppSecURL, c.AppSecFailOpen
	} else {
		p.KeyAuto = s.autoKey() != ""
	}
	// Le compose Gatewyn active AppSec sur cette adresse. On la propose aussi aux
	// installations déjà connectées avant l'ajout d'AppSec, sans modifier leur
	// configuration tant que l'utilisateur n'a pas validé le formulaire.
	if p.AppSecURL == "" && (p.Guided || p.Name == defaultCrowdSecURL) {
		p.AppSecURL = defaultAppSecURL
	}
	return p
}

func (s *Server) crowdSecFormPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "crowdsecform", s.crowdSecForm(r))
}

// explainCrowdSecError traduit une erreur de la LAPI en phrase claire.
func explainCrowdSecError(err error, url string) string {
	switch {
	case errors.Is(err, crowdsec.ErrBadKey):
		return "CrowdSec a refusé la clé. Créez-en une avec « cscli bouncers add gatewyn » et copiez-la ici."
	case errors.Is(err, crowdsec.ErrUnreachable):
		return fmt.Sprintf("Gatewyn n'arrive pas à joindre CrowdSec à l'adresse %s. Vérifiez l'adresse, et que CrowdSec et Gatewyn sont sur le même réseau Docker.", url)
	}
	return capitalize(err.Error()) + "."
}

// loadWAFStats lit les compteurs du WAF ; leur absence n'est pas une panne (le port des métriques
// n'est pas toujours joignable).
func (s *Server) loadWAFStats(ctx context.Context, v *csStatusView, lapi string) {
	url := s.metricsURL(lapi)
	if url == "" {
		return
	}
	st, err := crowdsec.Stats(ctx, s.csClient(), url)
	if err != nil {
		v.WAFStatsNo = "Les compteurs du WAF ne sont pas joignables (métriques de CrowdSec, port 6060)."
		return
	}
	v.WAFStats, v.Processed, v.Blocked = true, st.Processed, st.Blocked
	for _, r := range st.Rules {
		label, raw := crowdsec.RuleLabel(r.Rule)
		v.WAFRules = append(v.WAFRules, wafRuleView{label, raw, r.Hits})
	}
}

// explainAppSecError traduit une erreur d'AppSec en phrase claire.
func explainAppSecError(err error, url string) string {
	switch {
	case errors.Is(err, crowdsec.ErrBadKey):
		return "AppSec a refusé la clé du bouncer."
	case errors.Is(err, crowdsec.ErrUnreachable):
		return fmt.Sprintf("Gatewyn n'arrive pas à joindre AppSec à l'adresse %s. Vérifiez que le composant AppSec est activé dans CrowdSec (port 7422 par défaut), ou laissez ce champ vide pour ne pas utiliser le WAF.", url)
	}
	return capitalize(err.Error()) + "."
}

func (s *Server) saveCrowdSecForm(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	ctx := r.Context()
	p := s.crowdSecForm(r)
	url := strings.TrimSpace(r.PostFormValue("url"))
	key := strings.TrimSpace(r.PostFormValue("key"))
	appsec := strings.TrimSpace(r.PostFormValue("appsec_url"))
	failOpen := r.PostFormValue("appsec_failopen") == "1"
	p.Name, p.AppSecURL, p.AppSecFailOpen = url, appsec, failOpen
	reject := func(code int, msg string) {
		p.Error = msg
		w.WriteHeader(code)
		s.render(w, "crowdsecform", p)
	}
	old, err := s.loadCrowdSec(ctx)
	if err != nil {
		reject(http.StatusInternalServerError, err.Error())
		return
	}
	if key == "" {
		key = old.Key // une clé laissée vide reste inchangée
	}
	if key == "" {
		key = s.autoKey() // première connexion : la clé que CrowdSec a créée pour Gatewyn
	}
	if url == "" || key == "" {
		reject(http.StatusUnprocessableEntity, "Indiquez l'adresse de CrowdSec et la clé du bouncer.")
		return
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		reject(http.StatusUnprocessableEntity, fmt.Sprintf("L'adresse doit commencer par http:// ou https://, par exemple %s.", defaultCrowdSecURL))
		return
	}
	// On n'enregistre que si CrowdSec répond avec cette clé.
	if _, err := crowdsec.Decisions(ctx, s.csClient(), url, key); err != nil {
		reject(http.StatusUnprocessableEntity, explainCrowdSecError(err, url))
		return
	}
	if appsec != "" {
		if !strings.HasPrefix(appsec, "http://") && !strings.HasPrefix(appsec, "https://") {
			reject(http.StatusUnprocessableEntity, fmt.Sprintf("L'adresse d'AppSec doit commencer par http:// ou https://, par exemple %s.", defaultAppSecURL))
			return
		}
		if err := crowdsec.AppSecCheck(ctx, s.csClient(), appsec, key); err != nil {
			reject(http.StatusUnprocessableEntity, explainAppSecError(err, appsec))
			return
		}
	}
	if err := s.saveCrowdSec(ctx, csConfig{URL: url, Key: key, Enabled: true, AppSecURL: appsec, AppSecFailOpen: failOpen}); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sync(ctx); err != nil { // Caddy refuse : retour à la connexion d'avant
		_ = s.saveCrowdSec(ctx, old)
		_ = s.sync(ctx)
		reject(http.StatusBadGateway, explainSyncError(err))
		return
	}
	s.audit(ctx, "crowdsec.connect", url)
	http.Redirect(w, r, "/security/protection?csconnected=1", http.StatusSeeOther)
}

func (s *Server) setCrowdSecEnabled(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		old, err := s.loadCrowdSec(ctx)
		if err != nil || old.URL == "" || old.Key == "" {
			s.htmxError(w, "CrowdSec n'est pas connecté.")
			return
		}
		next := old
		next.Enabled = on
		if err := s.saveCrowdSec(ctx, next); err != nil {
			s.fail(w, r, err)
			return
		}
		if err := s.sync(ctx); err != nil {
			_ = s.saveCrowdSec(ctx, old)
			_ = s.sync(ctx)
			s.htmxError(w, explainSyncError(err))
			return
		}
		action, flag := "crowdsec.disable", "csdisabled"
		if on {
			action, flag = "crowdsec.enable", "csenabled"
		}
		s.audit(ctx, action, old.URL)
		w.Header().Set("HX-Redirect", "/security/protection?"+flag+"=1")
		w.WriteHeader(http.StatusOK)
	}
}

// removeCrowdSec retire entièrement la connexion enregistrée et le bouncer de Caddy.
// Il ne touche pas au moteur CrowdSec externe ni à ses données.
func (s *Server) removeCrowdSec(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	old, err := s.loadCrowdSec(ctx)
	if err != nil || old.URL == "" || old.Key == "" {
		s.htmxError(w, "CrowdSec n'est pas connecté.")
		return
	}
	if err := s.saveCrowdSec(ctx, csConfig{AppSecFailOpen: true}); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sync(ctx); err != nil {
		_ = s.saveCrowdSec(ctx, old)
		_ = s.sync(ctx)
		s.htmxError(w, explainSyncError(err))
		return
	}
	s.audit(ctx, "crowdsec.remove", old.URL)
	w.Header().Set("HX-Redirect", "/security/protection?csremoved=1")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) csClient() *http.Client {
	if s.cfg.CrowdSecClient != nil {
		return s.cfg.CrowdSecClient
	}
	return http.DefaultClient
}

// --- état de la protection (fragment chargé par la page Sécurité) ---

type wafRuleView struct {
	Label, Raw string
	Hits       int64
}

// metricsURL : les métriques de CrowdSec sont sur le port 6060 de la même machine que son API locale.
func (s *Server) metricsURL(lapi string) string {
	if s.cfg.CrowdSecMetricsURL != "" {
		return s.cfg.CrowdSecMetricsURL
	}
	u, err := neturl.Parse(lapi)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return "http://" + net.JoinHostPort(u.Hostname(), "6060") + "/metrics"
}

type csStatusView struct {
	EngineOK  bool
	EngineMsg string
	CaddyOK   bool
	CaddyMsg  string
	Total     int

	AppSecOn  bool // le WAF est configuré
	AppSecOK  bool
	AppSecMsg string

	WAFStats   bool // les compteurs du WAF sont lisibles
	Processed  int64
	Blocked    int64
	WAFRules   []wafRuleView
	WAFStatsNo string // pourquoi les compteurs manquent
}

func (s *Server) crowdSecStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	c, err := s.loadCrowdSec(ctx)
	if err != nil || !c.Enabled {
		fmt.Fprint(w, `<p class="muted">CrowdSec n'est pas actif.</p>`)
		return
	}
	v := csStatusView{}
	decisions, err := crowdsec.Decisions(ctx, s.csClient(), c.URL, c.Key)
	if err != nil {
		v.EngineMsg = explainCrowdSecError(err, c.URL)
	} else {
		v.EngineOK = true
		v.Total = len(decisions)
	}
	if c.AppSecURL != "" {
		v.AppSecOn = true
		// Connexion seulement : une vraie requête serait comptée par AppSec dans ses statistiques.
		if err := crowdsec.AppSecUp(ctx, c.AppSecURL); err != nil {
			v.AppSecMsg = explainAppSecError(err, c.AppSecURL)
		} else {
			v.AppSecOK = true
			s.loadWAFStats(ctx, &v, c.URL)
			if c.AppSecFailOpen {
				v.AppSecMsg = "Activé par hôte (groupe Protection) · les requêtes passent si AppSec tombe"
			} else {
				v.AppSecMsg = "Activé par hôte (groupe Protection) · les requêtes sont refusées si AppSec tombe"
			}
		}
	}
	if st, err := s.cfg.Caddy.CrowdSecStatus(ctx); err != nil {
		v.CaddyMsg = "Le bouncer n'est pas chargé dans Caddy."
	} else if !st.Healthy {
		v.CaddyMsg = "Caddy n'arrive pas à joindre CrowdSec."
	} else {
		v.CaddyOK = true
		if st.Streaming {
			v.CaddyMsg = fmt.Sprintf("Mode flux · liste mise à jour toutes les %s", secondsFR(st.Interval))
		} else {
			v.CaddyMsg = "Interrogation à chaque requête"
		}
	}
	s.renderFragment(w, "security", "csstatus", v)
}

// secondsFR : « 10s » devient « 10 s » ; une autre forme est gardée telle quelle.
func secondsFR(interval string) string {
	if strings.HasSuffix(interval, "s") && !strings.ContainsAny(interval, "mh") {
		return strings.TrimSuffix(interval, "s") + " s"
	}
	return interval
}
