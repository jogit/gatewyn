package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/store"
)

type listView struct {
	ID        int64
	Name      string
	Addresses string
	Hosts     int // nombre d'hôtes limités à cette liste
}

// listViews renvoie les listes d'accès pour l'affichage ; une erreur donne une liste vide.
func (s *Server) listViews(ctx context.Context) []listView {
	lists, err := s.cfg.Store.AccessLists(ctx)
	if err != nil {
		s.cfg.Logger.Error("access lists", "error", err)
	}
	hosts, _ := s.cfg.Store.ListHosts(ctx)
	used := map[int64]int{}
	for _, h := range hosts {
		ids := map[int64]bool{} // un hôte compte une fois par liste, même s'il l'utilise sur plusieurs chemins
		if h.AccessListID != 0 {
			ids[h.AccessListID] = true
		}
		for _, l := range h.Locations {
			if l.Access > 0 {
				ids[l.Access] = true
			}
		}
		for id := range ids {
			used[id]++
		}
	}
	out := make([]listView, len(lists))
	for i, l := range lists {
		out[i] = listView{l.ID, l.Name, strings.Join(l.Addresses, " · "), used[l.ID]}
	}
	return out
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/security/protection", http.StatusSeeOther)
}

func (s *Server) crowdSecPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Protection CrowdSec", "security-crowdsec")
	p.CS = s.crowdSecView(r.Context(), pageHost(r))
	q := r.URL.Query()
	switch {
	case q.Get("csconnected") != "":
		p.Flash = "CrowdSec est connecté : Caddy bloque maintenant les adresses qu'il signale."
	case q.Get("csenabled") != "":
		p.Flash = "CrowdSec est réactivé."
	case q.Get("csdisabled") != "":
		p.Flash = "CrowdSec est désactivé : Caddy ne bloque plus rien de sa part."
	case q.Get("csremoved") != "":
		p.Flash = "La connexion CrowdSec a été retirée de Gatewyn."
	}
	s.render(w, "security", p)
}

func (s *Server) accessPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Accès réseau", "security-access")
	p.Lists = s.listViews(r.Context())
	q := r.URL.Query()
	switch {
	case q.Get("added") != "":
		p.Flash = fmt.Sprintf("La liste « %s » est créée.", q.Get("added"))
	case q.Get("changed") != "":
		p.Flash = fmt.Sprintf("La liste « %s » est mise à jour.", q.Get("changed"))
	case q.Get("deleted") != "":
		p.Flash = fmt.Sprintf("La liste « %s » est supprimée.", q.Get("deleted"))
	}
	s.render(w, "access", p)
}

func (s *Server) listFormPage(r *http.Request, old *store.AccessList) page {
	p := s.authedPage(r, "Nouvelle liste d'accès", "security-access")
	p.Heading, p.Action, p.Submit, p.ListPath = "Nouvelle liste d'accès", "/security/lists", "Créer la liste", "/security/access"
	if old != nil {
		p.Title, p.Editing, p.EditID = "Modifier "+old.Name, true, old.ID
		p.Heading, p.Action, p.Submit = "Modifier « "+old.Name+" »", "/security/lists/"+strconv.FormatInt(old.ID, 10), "Enregistrer"
		p.Name, p.Addresses = old.Name, strings.Join(old.Addresses, "\n")
	}
	return p
}

func (s *Server) newListForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "listform", s.listFormPage(r, nil))
}

func (s *Server) listFromPath(w http.ResponseWriter, r *http.Request) (store.AccessList, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.AccessList{}, false
	}
	l, err := s.cfg.Store.AccessListByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return l, false
	}
	if err != nil {
		s.fail(w, r, err)
		return l, false
	}
	return l, true
}

func (s *Server) editListForm(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	s.render(w, "listform", s.listFormPage(r, &l))
}

func (s *Server) createList(w http.ResponseWriter, r *http.Request) { s.saveList(w, r, nil) }

func (s *Server) updateList(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	s.saveList(w, r, &l)
}

func (s *Server) saveList(w http.ResponseWriter, r *http.Request, old *store.AccessList) {
	if !s.parseForm(w, r) {
		return
	}
	p := s.listFormPage(r, old)
	p.Name, p.Addresses = strings.TrimSpace(r.PostFormValue("name")), r.PostFormValue("addresses")
	reject := func(code int, msg string) {
		p.Error = msg
		w.WriteHeader(code)
		s.render(w, "listform", p)
	}
	if p.Name == "" {
		reject(http.StatusUnprocessableEntity, "Donnez un nom à la liste.")
		return
	}
	addrs, err := caddyconf.ParseAddresses(p.Addresses)
	if err != nil {
		reject(http.StatusUnprocessableEntity, capitalize(err.Error())+".")
		return
	}
	l := store.AccessList{Name: p.Name, Addresses: addrs}
	if old == nil {
		_, err = s.cfg.Store.AddAccessList(r.Context(), l)
	} else {
		l.ID = old.ID
		err = s.cfg.Store.UpdateAccessList(r.Context(), l)
	}
	if errors.Is(err, store.ErrExists) {
		reject(http.StatusConflict, fmt.Sprintf("Une liste « %s » existe déjà.", p.Name))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if old != nil {
		// Les hôtes qui utilisent la liste suivent la modification ; si Caddy refuse, on revient en arrière.
		if err := s.sync(r.Context()); err != nil {
			_ = s.cfg.Store.UpdateAccessList(r.Context(), *old)
			_ = s.sync(r.Context())
			reject(http.StatusBadGateway, explainSyncError(err))
			return
		}
	}
	key, action := "added", "accesslist.create"
	if old != nil {
		key, action = "changed", "accesslist.update"
	}
	s.audit(r.Context(), action, p.Name)
	http.Redirect(w, r, "/security/access?"+key+"="+template.URLQueryEscaper(p.Name), http.StatusSeeOther)
}

func (s *Server) deleteList(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	for _, v := range s.listViews(r.Context()) {
		if v.ID == l.ID && v.Hosts > 0 {
			s.htmxError(w, fmt.Sprintf("Cette liste limite l'accès de %d hôte(s). Choisissez-en une autre ou « Public » dans ces hôtes avant de la supprimer.", v.Hosts))
			return
		}
	}
	if err := s.cfg.Store.DeleteAccessList(r.Context(), l.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), "accesslist.delete", l.Name)
	w.Header().Set("HX-Redirect", "/security/access?deleted="+template.URLQueryEscaper(l.Name))
	w.WriteHeader(http.StatusOK)
}

const settingTrustedProxies = "trusted_proxies"

// trustedProxies renvoie les proxies de confiance enregistrés (adresses ou plages).
func (s *Server) trustedProxies(ctx context.Context) ([]string, error) {
	v, err := s.cfg.Store.Setting(ctx, settingTrustedProxies)
	if err != nil {
		return nil, err
	}
	return strings.Fields(v), nil
}

func (s *Server) proxiesPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Proxies de confiance", "security-proxies")
	if proxies, err := s.trustedProxies(r.Context()); err == nil {
		p.ProxiesText = strings.Join(proxies, "\n")
	}
	if r.URL.Query().Get("saved") != "" {
		p.Flash = "Les proxies de confiance sont enregistrés."
	}
	s.render(w, "proxies", p)
}

// saveProxies enregistre les proxies de confiance ; une saisie vide les retire.
func (s *Server) saveProxies(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	ctx := r.Context()
	old, _ := s.cfg.Store.Setting(ctx, settingTrustedProxies)
	text := strings.TrimSpace(r.PostFormValue("proxies"))
	value := ""
	if text != "" {
		addrs, err := caddyconf.ParseAddresses(text)
		if err != nil {
			s.securityWithError(w, r, capitalize(err.Error())+".", text)
			return
		}
		value = strings.Join(addrs, "\n")
	}
	if err := s.cfg.Store.SetSetting(ctx, settingTrustedProxies, value); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sync(ctx); err != nil { // Caddy refuse : retour à l'état d'avant
		_ = s.cfg.Store.SetSetting(ctx, settingTrustedProxies, old)
		_ = s.sync(ctx)
		s.securityWithError(w, r, explainSyncError(err), text)
		return
	}
	s.audit(ctx, "proxies.update", strconv.Itoa(len(strings.Fields(value)))+" adresse(s)")
	http.Redirect(w, r, "/security/proxies?saved=1", http.StatusSeeOther)
}

// securityWithError réaffiche la page Proxies de confiance avec une erreur et la saisie en cours.
func (s *Server) securityWithError(w http.ResponseWriter, r *http.Request, msg, typed string) {
	p := s.authedPage(r, "Proxies de confiance", "security-proxies")
	p.Error, p.ProxiesText = msg, typed
	w.WriteHeader(http.StatusUnprocessableEntity)
	s.render(w, "proxies", p)
}
