// Package acmelog lit les journaux JSON de Caddy et retient, pour chaque domaine, le dernier
// échec d'obtention de certificat. Caddy n'expose ces échecs nulle part ailleurs : sans cette
// lecture, un certificat qui n'arrive pas est invisible dans l'interface.
package acmelog

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
)

// Failure est le dernier échec connu pour un domaine.
type Failure struct {
	Raw string    // erreur brute de Caddy (à traduire avant de l'afficher)
	At  time.Time // moment où Gatewyn l'a lue
}

// Tracker retient les échecs. Le zéro n'est pas utilisable : passer par New. Un *Tracker nil est
// accepté partout (Caddy lancé ailleurs : aucun journal à lire).
type Tracker struct {
	mu    sync.Mutex
	fails map[string]Failure
	now   func() time.Time
}

// New crée un Tracker vide.
func New() *Tracker { return &Tracker{fails: map[string]Failure{}, now: time.Now} }

// Failure renvoie le dernier échec d'obtention du certificat de domain, s'il n'a pas été suivi d'un succès.
func (t *Tracker) Failure(domain string) (Failure, bool) {
	if t == nil {
		return Failure{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.fails[strings.ToLower(domain)]
	return f, ok
}

// Wrap renvoie un io.Writer qui transmet tout à out (les journaux restent visibles comme avant)
// et analyse chaque ligne complète.
func (t *Tracker) Wrap(out io.Writer) io.Writer {
	if t == nil {
		return out
	}
	return &lineWriter{t: t, out: out}
}

// maxLine : une ligne plus longue est ignorée par l'analyse (elle est quand même transmise).
const maxLine = 1 << 20

type lineWriter struct {
	t    *Tracker
	out  io.Writer
	mu   sync.Mutex
	buf  []byte
	skip bool // la ligne en cours dépasse maxLine
}

func (w *lineWriter) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if !w.skip {
				if len(w.buf)+len(p) > maxLine {
					w.buf, w.skip = nil, true
				} else {
					w.buf = append(w.buf, p...)
				}
			}
			break
		}
		if !w.skip {
			w.t.observe(append(w.buf, p[:i]...))
		}
		w.buf, w.skip = w.buf[:0], false
		p = p[i+1:]
	}
	return n, err
}

// observe lit une ligne de journal de Caddy.
func (t *Tracker) observe(line []byte) {
	if len(line) == 0 || line[0] != '{' {
		return
	}
	var e struct {
		Logger     string `json:"logger"`
		Msg        string `json:"msg"`
		Identifier string `json:"identifier"`
		Error      string `json:"error"`
	}
	if json.Unmarshal(line, &e) != nil || e.Identifier == "" || !strings.HasPrefix(e.Logger, "tls.") {
		return
	}
	id := strings.ToLower(e.Identifier)
	switch e.Msg {
	case "could not get certificate from issuer":
		// Caddy annule les demandes en cours à chaque rechargement de sa configuration (à chaque
		// modification d'hôte) : ce n'est pas un échec du certificat.
		if strings.Contains(e.Error, "context canceled") {
			return
		}
		t.mu.Lock()
		t.fails[id] = Failure{Raw: e.Error, At: t.now()}
		t.mu.Unlock()
	case "certificate obtained successfully", "certificate renewed successfully":
		t.mu.Lock()
		delete(t.fails, id)
		t.mu.Unlock()
	}
}
