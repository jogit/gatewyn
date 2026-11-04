package web

import (
	"context"
	"net"
	"net/http"
	neturl "net/url"
	"slices"
	"strconv"
	"strings"
)

const settingCSWebUI = "crowdsec.web_ui_url"

// crowdSecWebUIURL renvoie le lien choisi dans les réglages. Une valeur « - »
// distingue un bouton volontairement masqué de l'absence de réglage.
func (s *Server) crowdSecWebUIURL(ctx context.Context, crowdSecURL, host string) string {
	v, err := s.cfg.Store.Setting(ctx, settingCSWebUI)
	if err != nil {
		s.cfg.Logger.Error("CrowdSec link", "error", err)
		return ""
	}
	if v == "-" {
		return ""
	}
	if v == "" && crowdSecURL == defaultCrowdSecURL {
		return "http://" + host + ":8090"
	}
	return v
}

// pageHost : le nom ou l'adresse par lequel le navigateur a ouvert Gatewyn. Les applications
// du compose (interface CrowdSec, rapport GoAccess) sont publiées sur la même machine,
// sur d'autres ports : leur lien par défaut en dérive, au lieu de 127.0.0.1.
func pageHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") { // IPv6 sans crochets
		h = "[" + h + "]"
	}
	return h
}

// defaultWebURL : lien par défaut d'une application du compose publiée sur le port donné.
func defaultWebURL(r *http.Request, port int) string {
	return "http://" + pageHost(r) + ":" + strconv.Itoa(port)
}

// validWebURL : adresse HTTP ou HTTPS complète.
func validWebURL(v string) bool {
	u, err := neturl.Parse(v)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Réglages", "settings")
	p.CrowdSecUIURL = s.crowdSecWebUIURL(r.Context(), defaultCrowdSecURL, pageHost(r))
	p.GoAccessReport, p.GoAccessTarget = s.goAccessReportURL(r.Context(), pageHost(r)), s.cfg.GoAccessURL
	p.UILanguage = s.languageSetting(r.Context())
	s.fillAccessLog(r.Context(), &p)
	if r.URL.Query().Get("saved") != "" {
		p.Flash = "Les réglages sont enregistrés."
	}
	s.render(w, "settings", p)
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	p := s.authedPage(r, "Réglages", "settings")
	p.CrowdSecUIURL = strings.TrimSpace(r.PostFormValue("crowdsec_ui_url"))
	p.UILanguage = s.languageSetting(r.Context())
	if v := r.PostFormValue("ui_language"); v == "auto" || v == "fr" || v == "en" {
		p.UILanguage = v // enregistré avec les autres réglages, si tout est valide
	}
	p.GoAccessReport, p.GoAccessTarget = strings.TrimSpace(r.PostFormValue("goaccess_report_url")), s.cfg.GoAccessURL
	s.fillAccessLog(r.Context(), &p)
	if p.AccessLogAvail {
		p.AccessLogOn = r.PostFormValue("accesslog") == "1"
		if d, err := strconv.Atoi(r.PostFormValue("accesslog_days")); err == nil && slices.Contains(accessLogChoices, d) {
			p.AccessLogDays = d
		}
	}
	for _, v := range []string{p.CrowdSecUIURL, p.GoAccessReport} {
		if v != "" && !validWebURL(v) {
			p.Error = "Indiquez une adresse HTTP ou HTTPS complète."
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.render(w, "settings", p)
			return
		}
	}
	// Une adresse qui est celle proposée par défaut n'est pas enregistrée : sinon elle se figerait
	// (liée à la machine ou au nom par lesquels la page a été ouverte ce jour-là).
	stored := p.CrowdSecUIURL
	switch stored {
	case "":
		stored = "-"
	case defaultWebURL(r, 8090):
		stored = ""
	}
	storedReport := p.GoAccessReport
	switch storedReport {
	case "":
		storedReport = "-"
	case defaultWebURL(r, 8091):
		storedReport = ""
	}
	if err := s.cfg.Store.SetSetting(r.Context(), settingGoAccessReport, storedReport); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.cfg.Store.SetSetting(r.Context(), settingCSWebUI, stored); err != nil {
		s.fail(w, r, err)
		return
	}
	if p.AccessLogAvail {
		if err := s.saveAccessLog(r.Context(), p.AccessLogOn, p.AccessLogDays); err != nil {
			p.Error = explainSettingError(err)
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.render(w, "settings", p)
			return
		}
	}
	if err := s.cfg.Store.SetSetting(r.Context(), settingLanguage, p.UILanguage); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), "settings.update", "applications")
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// languageSetting renvoie le réglage de langue : « auto » par défaut.
func (s *Server) languageSetting(ctx context.Context) string {
	if v, _ := s.cfg.Store.Setting(ctx, settingLanguage); v == "fr" || v == "en" {
		return v
	}
	return "auto"
}
