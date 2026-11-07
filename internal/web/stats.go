package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/jogit/gatewyn/internal/caddyconf"
)

const (
	settingAccessLogDays  = "accesslog.days" // durée de conservation en jours ; 0 : pas de journal ; jamais réglé : défaut
	defaultAccessLogDays  = 30
	defaultGoAccessURL    = "http://goaccess:8080" // adresse de GoAccess pour Gatewyn, sur le réseau du compose
	settingGoAccessReport = "goaccess.report_url"
)

// accessLogChoices : durées proposées pour le journal d'accès, en jours.
var accessLogChoices = []int{7, 30, 90, 365}

// accessLogDays renvoie la durée enregistrée, la durée par défaut tant que rien n'a été réglé, 0 si le
// journal a été désactivé.
func (s *Server) accessLogDays(ctx context.Context) (int, error) {
	v, err := s.cfg.Store.Setting(ctx, settingAccessLogDays)
	if err != nil {
		return 0, err
	}
	if v == "" {
		return defaultAccessLogDays, nil
	}
	days, _ := strconv.Atoi(v)
	return days, nil
}

// accessLog renvoie le journal à publier dans Caddy, nil s'il est désactivé ou indisponible.
func (s *Server) accessLog(ctx context.Context) (*caddyconf.AccessLog, error) {
	days, err := s.accessLogDays(ctx)
	if err != nil || days <= 0 || s.cfg.AccessLogFile == "" {
		return nil, err
	}
	return &caddyconf.AccessLog{File: s.cfg.AccessLogFile, KeepDays: days}, nil
}

// reqView est une ligne de « Dernières requêtes ».
type reqView struct {
	Time, IP, Host, Request string
	Status                  int
	Class                   string
}

// reqSummary résume les requêtes lues dans la fin du journal.
type reqSummary struct {
	Total, Visitors, Errors int           // requêtes, adresses distinctes, réponses 4xx et 5xx
	Since                   string        // date de la plus ancienne requête lue
	Hosts                   []hostTraffic // requêtes par hôte, les plus sollicités d'abord
}

// hostTraffic : les requêtes d'un hôte dans l'échantillon lu ; Pct est sa part du plus sollicité (barre).
type hostTraffic struct {
	Host           string
	Requests, Errs int
	Pct            int
}

// readRequests lit la fin du journal d'accès JSON : les show dernières requêtes (la plus récente d'abord)
// et le résumé des sample dernières. Sans fichier lisible, le résultat est vide.
func readRequests(path string, show, sample int) ([]reqView, reqSummary) {
	var sum reqSummary
	f, err := os.Open(path)
	if err != nil {
		return nil, sum
	}
	defer f.Close()
	const tail = 1 << 20
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, sum
	}
	start := max(size-tail, 0)
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil, sum
	}
	lines := bytes.Split(buf, []byte("\n"))
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // la première ligne est coupée
	}
	var out []reqView
	visitors := map[string]bool{}
	perHost := map[string]*hostTraffic{}
	var oldest int64
	for i := len(lines) - 1; i >= 0 && sum.Total < sample; i-- {
		var e struct {
			TS      float64 `json:"ts"`
			Request struct {
				ClientIP string `json:"client_ip"`
				Host     string `json:"host"`
				Method   string `json:"method"`
				URI      string `json:"uri"`
			} `json:"request"`
			Status int `json:"status"`
		}
		if json.Unmarshal(lines[i], &e) != nil || e.Status == 0 {
			continue
		}
		sum.Total++
		visitors[e.Request.ClientIP] = true
		oldest = int64(e.TS)
		class := "ok"
		switch {
		case e.Status >= 500:
			class = "err"
		case e.Status >= 400:
			class = "warn"
		case e.Status >= 300:
			class = "info"
		}
		if e.Status >= 400 {
			sum.Errors++
		}
		if h := e.Request.Host; h != "" {
			ht := perHost[h]
			if ht == nil {
				ht = &hostTraffic{Host: h}
				perHost[h] = ht
			}
			ht.Requests++
			if e.Status >= 400 {
				ht.Errs++
			}
		}
		if len(out) < show {
			out = append(out, reqView{
				Time: time.Unix(int64(e.TS), 0).Format("02/01 15:04:05"), IP: e.Request.ClientIP, Host: e.Request.Host,
				Request: e.Request.Method + " " + e.Request.URI, Status: e.Status, Class: class,
			})
		}
	}
	sum.Visitors = len(visitors)
	for _, ht := range perHost {
		sum.Hosts = append(sum.Hosts, *ht)
	}
	sort.Slice(sum.Hosts, func(i, j int) bool {
		if sum.Hosts[i].Requests != sum.Hosts[j].Requests {
			return sum.Hosts[i].Requests > sum.Hosts[j].Requests
		}
		return sum.Hosts[i].Host < sum.Hosts[j].Host
	})
	if len(sum.Hosts) > 10 {
		sum.Hosts = sum.Hosts[:10]
	}
	for i := range sum.Hosts {
		sum.Hosts[i].Pct = max(sum.Hosts[i].Requests*100/sum.Hosts[0].Requests, 1)
	}
	if oldest > 0 {
		sum.Since = time.Unix(oldest, 0).Format("02/01 15:04")
	}
	return out, sum
}

// fillAccessLog prépare les champs du journal d'accès (page Réglages et page Statistiques).
func (s *Server) fillAccessLog(ctx context.Context, p *page) {
	p.AccessLogAvail, p.AccessLogChoices = s.cfg.AccessLogFile != "", accessLogChoices
	days, _ := s.accessLogDays(ctx)
	p.AccessLogOn, p.AccessLogDays = days > 0, days
	if days <= 0 {
		p.AccessLogDays = defaultAccessLogDays
	}
}

// statsPage prépare la page Statistiques : journal d'accès, état de GoAccess et lien vers son rapport.
func (s *Server) statsPage(r *http.Request, p *page) {
	ctx := r.Context()
	s.fillAccessLog(ctx, p)
	p.GoAccessUp = s.goAccessUp(ctx)
	if p.AccessLogOn {
		p.Recent, p.StatsSum = readRequests(s.cfg.AccessLogFile, 50, 5000)
	}
	p.GoAccessTarget, p.GoAccessReport = s.cfg.GoAccessURL, s.goAccessReportURL(ctx, pageHost(r))
}

// goAccessUp : GoAccess répond-il ? Toute réponse HTTP suffit (lecture seule, aucune action).
func (s *Server) goAccessUp(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.GoAccessURL, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// goAccessReportURL renvoie l'adresse du rapport choisie dans les réglages. Une valeur « - » distingue
// un bouton volontairement masqué de l'absence de réglage (adresse locale par défaut).
func (s *Server) goAccessReportURL(ctx context.Context, host string) string {
	v, err := s.cfg.Store.Setting(ctx, settingGoAccessReport)
	if err != nil {
		s.cfg.Logger.Error("GoAccess link", "error", err)
		return ""
	}
	switch v {
	case "-":
		return ""
	case "":
		return "http://" + host + ":8091" // rapport publié par le compose, sur la machine de Gatewyn
	}
	return v
}

func (s *Server) statsGet(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Trafic", "stats")
	s.statsPage(r, &p)
	s.render(w, "stats", p)
}

func (s *Server) statsInstall(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Activer les statistiques", "stats")
	s.statsPage(r, &p)
	s.render(w, "statsinstall", p)
}

// saveAccessLog enregistre le journal d'accès (activé, durée) et le publie dans Caddy ; en cas de refus,
// l'état précédent est rétabli et l'erreur est renvoyée. Appelé par la page Réglages.
func (s *Server) saveAccessLog(ctx context.Context, on bool, days int) error {
	if !on {
		days = 0
	}
	old, _ := s.cfg.Store.Setting(ctx, settingAccessLogDays)
	if err := s.cfg.Store.SetSetting(ctx, settingAccessLogDays, strconv.Itoa(days)); err != nil {
		return err
	}
	if err := s.sync(ctx); err != nil {
		_ = s.cfg.Store.SetSetting(ctx, settingAccessLogDays, old)
		_ = s.sync(ctx)
		return err
	}
	return nil
}

// statsJournal active le journal d'accès en un clic (étape 1 de l'installation de GoAccess), avec la durée
// déjà choisie dans Réglages, sinon 30 jours. Revient à la page d'où part le bouton.
func (s *Server) statsJournal(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	ctx := r.Context()
	back, name := "/stats", "stats"
	if r.PostFormValue("back") == "install" {
		back, name = "/stats/install", "statsinstall"
	}
	days, _ := s.accessLogDays(ctx)
	if days <= 0 {
		days = defaultAccessLogDays
	}
	if s.cfg.AccessLogFile != "" {
		if err := s.saveAccessLog(ctx, true, days); err != nil {
			p := s.authedPage(r, "Trafic", "stats")
			s.statsPage(r, &p)
			p.Error = explainSettingError(err)
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.render(w, name, p)
			return
		}
		s.audit(ctx, "stats.journal", strconv.Itoa(days)+" jour(s)")
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
