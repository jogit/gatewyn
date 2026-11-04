package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/dnsprov"
	"github.com/jogit/gatewyn/internal/store"
)

type dnsView struct {
	ID       int64
	Name     string
	Provider string // nom affiché, ex. « OVH »
	Hosts    int    // nombre d'hôtes qui l'utilisent
}

type fieldView struct {
	Key, Label, Value string
	Secret, Optional  bool
	Edit              bool // modification : un secret laissé vide reste inchangé
}

// dnsViews renvoie les comptes DNS pour l'affichage.
func (s *Server) dnsViews(ctx context.Context) []dnsView {
	accounts, err := s.cfg.Store.DNSAccounts(ctx)
	if err != nil {
		s.cfg.Logger.Error("DNS accounts", "error", err)
	}
	hosts, _ := s.cfg.Store.ListHosts(ctx)
	used := map[int64]int{}
	for _, h := range hosts {
		if h.DNSAccountID != 0 {
			used[h.DNSAccountID]++
		}
	}
	out := make([]dnsView, len(accounts))
	for i, a := range accounts {
		prov, _ := dnsprov.Get(a.Provider)
		out[i] = dnsView{a.ID, a.Name, prov.Name, used[a.ID]}
	}
	return out
}

// dnsValues déchiffre les identifiants d'un compte.
func (s *Server) dnsValues(a store.DNSAccount) (map[string]string, error) {
	if s.cfg.Secrets == nil {
		return nil, errors.New("le chiffrement des identifiants n'est pas disponible")
	}
	plain, err := s.cfg.Secrets.Unseal(a.Secret)
	if err != nil {
		return nil, fmt.Errorf("compte DNS « %s » : %w", a.Name, err)
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(plain), &values); err != nil {
		return nil, fmt.Errorf("compte DNS « %s » illisible : %w", a.Name, err)
	}
	return values, nil
}

// dnsChallenges prépare, pour chaque compte, ce que Caddy doit utiliser.
func (s *Server) dnsChallenges(ctx context.Context) (map[int64]*caddyconf.DNSChallenge, error) {
	accounts, err := s.cfg.Store.DNSAccounts(ctx)
	if err != nil {
		return nil, err
	}
	out := map[int64]*caddyconf.DNSChallenge{}
	for _, a := range accounts {
		values, err := s.dnsValues(a)
		if err != nil {
			return nil, err
		}
		out[a.ID] = &caddyconf.DNSChallenge{Account: a.ID, Provider: dnsprov.CaddyConfig(a.Provider, values)}
	}
	return out, nil
}

func fieldViews(providerID string, values map[string]string, edit bool) []fieldView {
	prov, ok := dnsprov.Get(providerID)
	if !ok {
		return nil
	}
	out := make([]fieldView, len(prov.Fields))
	for i, f := range prov.Fields {
		v := values[f.Key]
		if v == "" && !edit {
			v = f.Default
		}
		if f.Secret {
			v = "" // jamais réaffiché
		}
		out[i] = fieldView{Key: f.Key, Label: f.Label, Value: v, Secret: f.Secret, Optional: f.Optional, Edit: edit}
	}
	return out
}

func (s *Server) dnsAccountsPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Comptes DNS", "dns")
	p.DNS = s.dnsViews(r.Context())
	q := r.URL.Query()
	switch {
	case q.Get("added") != "":
		p.Flash = fmt.Sprintf("Le compte « %s » est créé.", q.Get("added"))
	case q.Get("changed") != "":
		p.Flash = fmt.Sprintf("Le compte « %s » est mis à jour.", q.Get("changed"))
	case q.Get("deleted") != "":
		p.Flash = fmt.Sprintf("Le compte « %s » est supprimé.", q.Get("deleted"))
	}
	s.render(w, "dnsaccounts", p)
}

func (s *Server) dnsFormPage(r *http.Request, old *store.DNSAccount) page {
	p := s.authedPage(r, "Nouveau compte DNS", "dns")
	p.Heading, p.Action, p.Submit, p.ListPath = "Nouveau compte DNS", "/certificates/dns", "Créer le compte", "/certificates/dns"
	p.Providers = dnsprov.All()
	p.ProviderID = p.Providers[0].ID
	p.DNSFields = fieldViews(p.ProviderID, nil, false)
	if old != nil {
		p.Title, p.Editing, p.EditID = "Modifier "+old.Name, true, old.ID
		p.Heading, p.Action, p.Submit = "Modifier « "+old.Name+" »", "/certificates/dns/"+strconv.FormatInt(old.ID, 10), "Enregistrer"
		p.Name, p.ProviderID = old.Name, old.Provider
		values, err := s.dnsValues(*old)
		if err != nil {
			p.Error = err.Error()
		}
		p.DNSFields = fieldViews(old.Provider, values, true)
	}
	return p
}

func (s *Server) newDNSForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "dnsform", s.dnsFormPage(r, nil))
}

// dnsFields renvoie les champs d'un fournisseur (htmx, quand on change de fournisseur).
func (s *Server) dnsFields(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "dnsform", "fields", fieldViews(r.URL.Query().Get("provider"), nil, false))
}

func (s *Server) dnsFromPath(w http.ResponseWriter, r *http.Request) (store.DNSAccount, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.DNSAccount{}, false
	}
	a, err := s.cfg.Store.DNSAccountByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return a, false
	}
	if err != nil {
		s.fail(w, r, err)
		return a, false
	}
	return a, true
}

func (s *Server) editDNSForm(w http.ResponseWriter, r *http.Request) {
	a, ok := s.dnsFromPath(w, r)
	if !ok {
		return
	}
	s.render(w, "dnsform", s.dnsFormPage(r, &a))
}

func (s *Server) createDNS(w http.ResponseWriter, r *http.Request) { s.saveDNS(w, r, nil) }

func (s *Server) updateDNS(w http.ResponseWriter, r *http.Request) {
	a, ok := s.dnsFromPath(w, r)
	if !ok {
		return
	}
	s.saveDNS(w, r, &a)
}

func (s *Server) saveDNS(w http.ResponseWriter, r *http.Request, old *store.DNSAccount) {
	if !s.parseForm(w, r) {
		return
	}
	p := s.dnsFormPage(r, old)
	p.Error = ""
	p.Name = strings.TrimSpace(r.PostFormValue("name"))
	providerID := r.PostFormValue("provider")
	if old != nil {
		providerID = old.Provider // le fournisseur d'un compte ne change pas
	}
	p.ProviderID = providerID
	typed := map[string]string{}
	for k := range r.PostForm {
		if strings.HasPrefix(k, "f_") {
			typed[strings.TrimPrefix(k, "f_")] = r.PostFormValue(k)
		}
	}
	p.DNSFields = fieldViews(providerID, typed, old != nil)
	reject := func(code int, msg string) {
		p.Error = msg
		w.WriteHeader(code)
		s.render(w, "dnsform", p)
	}
	if p.Name == "" {
		reject(http.StatusUnprocessableEntity, "Donnez un nom au compte.")
		return
	}
	if s.cfg.Secrets == nil {
		reject(http.StatusInternalServerError, "Le chiffrement des identifiants n'est pas disponible : le compte ne peut pas être enregistré.")
		return
	}
	if old != nil { // un secret laissé vide reste inchangé
		prev, err := s.dnsValues(*old)
		if err != nil {
			reject(http.StatusInternalServerError, err.Error())
			return
		}
		for _, f := range p.DNSFields {
			if f.Secret && strings.TrimSpace(typed[f.Key]) == "" {
				typed[f.Key] = prev[f.Key]
			}
		}
	}
	values, err := dnsprov.Clean(providerID, typed)
	if err != nil {
		reject(http.StatusUnprocessableEntity, capitalize(err.Error())+".")
		return
	}
	raw, _ := json.Marshal(values)
	sealed, err := s.cfg.Secrets.Seal(string(raw))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a := store.DNSAccount{Name: p.Name, Provider: providerID, Secret: sealed}
	ctx := r.Context()
	if old == nil {
		_, err = s.cfg.Store.AddDNSAccount(ctx, a)
	} else {
		a.ID = old.ID
		err = s.cfg.Store.UpdateDNSAccount(ctx, a)
	}
	if errors.Is(err, store.ErrExists) {
		reject(http.StatusConflict, fmt.Sprintf("Un compte « %s » existe déjà.", p.Name))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if old != nil { // les hôtes du compte suivent ; si Caddy refuse, retour en arrière
		if err := s.sync(ctx); err != nil {
			_ = s.cfg.Store.UpdateDNSAccount(ctx, *old)
			_ = s.sync(ctx)
			reject(http.StatusBadGateway, explainSyncError(err))
			return
		}
	}
	key, action := "added", "dns.create"
	if old != nil {
		key, action = "changed", "dns.update"
	}
	s.audit(ctx, action, p.Name+" ("+providerID+")")
	http.Redirect(w, r, "/certificates/dns?"+key+"="+template.URLQueryEscaper(p.Name), http.StatusSeeOther)
}

func (s *Server) deleteDNS(w http.ResponseWriter, r *http.Request) {
	a, ok := s.dnsFromPath(w, r)
	if !ok {
		return
	}
	for _, v := range s.dnsViews(r.Context()) {
		if v.ID == a.ID && v.Hosts > 0 {
			s.htmxError(w, fmt.Sprintf("Ce compte sert aux certificats de %d hôte(s). Repassez-les en « Automatique » avant de le supprimer.", v.Hosts))
			return
		}
	}
	if err := s.cfg.Store.DeleteDNSAccount(r.Context(), a.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), "dns.delete", a.Name)
	w.Header().Set("HX-Redirect", "/certificates/dns?deleted="+template.URLQueryEscaper(a.Name))
	w.WriteHeader(http.StatusOK)
}
