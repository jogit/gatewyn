package web

import (
	"bytes"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/jogit/gatewyn/internal/i18n"
)

// settingLanguage : langue de l'interface. « auto » (défaut) suit le navigateur ; « fr » ou « en » l'imposent.
const settingLanguage = "ui.language"

// language renvoie la langue de la requête : « fr » (langue de référence) ou « en ».
func (s *Server) language(r *http.Request) string {
	switch v, _ := s.cfg.Store.Setting(r.Context(), settingLanguage); v {
	case "fr", "en":
		return v
	}
	return fromAcceptLanguage(r.Header.Get("Accept-Language"))
}

// fromAcceptLanguage choisit entre le français et l'anglais d'après l'en-tête du navigateur.
// Sans en-tête (curl, tests) : le français. Une liste sans français ni anglais : l'anglais.
func fromAcceptLanguage(h string) string {
	type lang struct {
		tag string
		q   float64
	}
	var list []lang
	for _, part := range strings.Split(h, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if q > 0 {
			list = append(list, lang{tag, q})
		}
	}
	if len(list) == 0 {
		return "fr"
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].q > list[j].q })
	for _, l := range list {
		switch base, _, _ := strings.Cut(l.tag, "-"); base {
		case "fr":
			return "fr"
		case "en":
			return "en"
		}
	}
	return "en"
}

// translated traduit en anglais les réponses HTML (et les messages d'erreur en texte) quand la
// langue de la requête est l'anglais. En français, rien n'est touché.
func (s *Server) translated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || s.language(r) != "en" {
			next.ServeHTTP(w, r)
			return
		}
		tw := &translateWriter{ResponseWriter: w}
		next.ServeHTTP(tw, r)
		tw.finish()
	})
}

type translateWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (t *translateWriter) WriteHeader(code int) { t.status = code }

func (t *translateWriter) Write(b []byte) (int, error) { return t.buf.Write(b) }

func (t *translateWriter) finish() {
	body := t.buf.Bytes()
	ct := t.Header().Get("Content-Type")
	if ct == "" && len(body) > 0 { // petit message écrit sans type : le serveur le détecterait à l'envoi
		ct = http.DetectContentType(body)
	}
	switch {
	case strings.HasPrefix(ct, "text/html"):
		body = i18n.HTML(body)
	case strings.HasPrefix(ct, "text/plain"):
		body = []byte(i18n.Text(string(body)))
	}
	if t.status == 0 {
		t.status = http.StatusOK
	}
	if len(body) > 0 {
		t.Header().Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		t.Header().Del("Content-Length")
	}
	t.ResponseWriter.WriteHeader(t.status)
	t.ResponseWriter.Write(body)
}
