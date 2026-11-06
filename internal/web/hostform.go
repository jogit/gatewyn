package web

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jogit/gatewyn/internal/caddyconf"
	"github.com/jogit/gatewyn/internal/checks"
	"github.com/jogit/gatewyn/internal/store"
)

// formInput est ce que la personne a saisi dans le formulaire d'hôte.
type formInput struct {
	Kind       string   // caddyconf.KindProxy, KindRedirect ou KindNotFound
	Domain     string   // premier nom saisi
	Aliases    []string // noms suivants : même hôte, même certificat
	Target     string
	Code       int   // redirection : 301 ou 302
	Preserve   bool  // redirection : garde le chemin
	Access     int64 // service : liste d'accès (0 = public)
	DNS        int64 // compte DNS du certificat (0 = défi HTTP automatique)
	HTTPOnly   bool  // HTTP seulement, sans HTTPS
	SelfSigned bool  // certificat auto-signé par Caddy
	HSTS       int   // 0 aucun, 1 HSTS, 2 HSTS avec les sous-domaines

	Compress, NoBuffering bool   // service : compression, streaming sans tampon
	WAF                   bool   // service : WAF CrowdSec AppSec
	FrameOptions          string // « », « SAMEORIGIN » ou « DENY »
	NoIndex               bool

	Locations    []store.Location // service : chemins vers d'autres cibles
	locationsErr error
}

func kindFromForm(v string) string {
	switch v {
	case caddyconf.KindRedirect, caddyconf.KindNotFound:
		return v
	}
	return caddyconf.KindProxy
}

// readForm lit et nettoie la saisie. Une cible sans protocole est lue comme
// http:// pour un service et https:// pour une destination de redirection.
func readForm(r *http.Request, kind string) formInput {
	f := formInput{Kind: kind, Target: strings.TrimSpace(r.PostFormValue("target"))}
	// Plusieurs noms : séparés par une virgule, un espace ou un retour à la ligne.
	names := strings.FieldsFunc(strings.ToLower(strings.Join(r.PostForm["domain"], ",")), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	for i, n := range names {
		names[i] = toASCII(n)
	}
	if len(names) > 0 {
		f.Domain, f.Aliases = names[0], names[1:]
	}
	f.NoIndex = r.PostFormValue("noindex") == "1"
	if fo := r.PostFormValue("frame"); fo == "SAMEORIGIN" || fo == "DENY" {
		f.FrameOptions = fo
	}
	if r.PostFormValue("hsts") == "1" {
		f.HSTS = 1
		if r.PostFormValue("hsts_sub") == "1" {
			f.HSTS = 2
		}
	}
	switch r.PostFormValue("dns") {
	case "http":
		f.HTTPOnly = true
	case "internal":
		f.SelfSigned = true
	default:
		f.DNS, _ = strconv.ParseInt(r.PostFormValue("dns"), 10, 64)
	}
	if kind == caddyconf.KindProxy {
		f.Locations, f.locationsErr = readLocations(r)
		f.Compress, f.NoBuffering = r.PostFormValue("compress") == "1", r.PostFormValue("no_buffering") == "1"
		f.WAF = r.PostFormValue("waf") == "1"
	}
	switch kind {
	case caddyconf.KindNotFound:
		f.Target = ""
	case caddyconf.KindRedirect:
		f.Code = 301
		if c, _ := strconv.Atoi(r.PostFormValue("code")); c == 302 {
			f.Code = c
		}
		f.Preserve = r.PostFormValue("preserve") == "1"
		if f.Target != "" && !strings.Contains(f.Target, "://") {
			f.Target = "https://" + f.Target
		}
	default:
		if f.Target != "" && !strings.Contains(f.Target, "://") {
			f.Target = "http://" + f.Target
		}
		f.Access, _ = strconv.ParseInt(r.PostFormValue("access"), 10, 64)
	}
	return f
}

// toASCII convertit un nom accentué en punycode (café.fr devient xn--caf-dma.fr). Un nom
// qui n'est pas convertible reste tel quel : la validation du domaine le refusera.
func toASCII(name string) string {
	wild := strings.HasPrefix(name, "*.")
	base := strings.TrimPrefix(name, "*.")
	ascii, err := idna.Lookup.ToASCII(base)
	if err != nil {
		return name
	}
	if wild {
		return "*." + ascii
	}
	return ascii
}

// readLocations lit les règles « chemin, accès, cible facultative » du formulaire ; une
// ligne entièrement vide est ignorée. Sans cible, le chemin garde celle de l'hôte.
// Une cible sans protocole est lue comme http://.
func readLocations(r *http.Request) ([]store.Location, error) {
	paths, targets, accesses, strips := r.PostForm["loc_path"], r.PostForm["loc_target"], r.PostForm["loc_access"], r.PostForm["loc_strip"]
	var out []store.Location
	for i, p := range paths {
		path := strings.TrimSpace(p)
		var target string
		var access int64
		if i < len(targets) {
			target = strings.TrimSpace(targets[i])
		}
		if i < len(accesses) {
			access, _ = strconv.ParseInt(accesses[i], 10, 64)
		}
		if path == "" && target == "" && access == 0 {
			continue
		}
		if path == "" {
			return nil, errors.New("chaque règle a besoin d'un chemin (exemple : /admin)")
		}
		if target == "" && access == 0 {
			return nil, fmt.Errorf("la règle %s ne change rien : choisissez qui y accède, ou une autre adresse", path)
		}
		if target != "" && !strings.Contains(target, "://") {
			target = "http://" + target
		}
		out = append(out, store.Location{Path: path, Target: target, Access: access, StripPath: target != "" && i < len(strips) && strips[i] == "1"})
	}
	return out, nil
}

// locRowView est une ligne « chemin, cible, accès » du formulaire.
type locRowView struct {
	Path, Target string
	Access       int64
	Strip        bool
	Lists        []listView
}

// locRows prépare les lignes à afficher : les chemins existants, puis une ligne vide.
func (s *Server) locRows(ctx context.Context, ls []store.Location) []locRowView {
	lists := s.listViews(ctx)
	rows := make([]locRowView, 0, len(ls)+1)
	for _, l := range ls {
		rows = append(rows, locRowView{l.Path, l.Target, l.Access, l.StripPath, lists})
	}
	return rows
}

// locationRow renvoie une ligne vide (htmx, bouton « Ajouter un chemin »).
func (s *Server) domainRow(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "new", "domrow", "")
}

func (s *Server) locationRow(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "new", "locrow", locRowView{Lists: s.listViews(r.Context())})
}

func confLocations(ls []store.Location, access map[int64][]string) []caddyconf.Location {
	out := make([]caddyconf.Location, len(ls))
	for i, l := range ls {
		out[i] = caddyconf.Location{Path: l.Path, Target: l.Target, Public: l.Access == store.PublicAccess, StripPath: l.StripPath}
		if l.Access > 0 {
			out[i].Access = access[l.Access]
		}
	}
	return out
}

// domains renvoie tous les noms saisis.
func (f formInput) domains() []string {
	if f.Domain == "" {
		return nil
	}
	return f.Domains()
}

func (f formInput) Domains() []string { return append([]string{f.Domain}, f.Aliases...) }

// domainsText est la saisie telle qu'on la réaffiche dans le champ Domaine.
func domainsText(domain string, aliases []string) string {
	return strings.Join(append([]string{domain}, aliases...), ", ")
}

func (f formInput) store() store.Host {
	return store.Host{Domain: f.Domain, Aliases: f.Aliases, Kind: f.Kind, Target: f.Target, Code: f.Code, PreservePath: f.Preserve, AccessListID: f.Access, DNSAccountID: f.DNS, HTTPOnly: f.HTTPOnly, SelfSigned: f.SelfSigned, HSTS: f.HSTS, Locations: f.Locations, Compress: f.Compress, NoBuffering: f.NoBuffering, FrameOptions: f.FrameOptions, NoIndex: f.NoIndex, WAF: f.WAF}
}

func (f formInput) same(h store.Host) bool {
	return f.Domain == h.Domain && slices.Equal(f.Aliases, h.Aliases) && f.Target == h.Target && f.Code == h.Code && f.Preserve == h.PreservePath && f.Access == h.AccessListID && f.DNS == h.DNSAccountID && slices.Equal(f.Locations, h.Locations) && f.Compress == h.Compress && f.NoBuffering == h.NoBuffering && f.FrameOptions == h.FrameOptions && f.NoIndex == h.NoIndex && f.WAF == h.WAF && f.HTTPOnly == h.HTTPOnly && f.SelfSigned == h.SelfSigned && f.HSTS == h.HSTS
}

// problems renvoie les erreurs de format de la saisie (jamais contournables).
func (f formInput) problems() []checks.Result {
	var out []checks.Result
	bad := func(code string, err error) {
		out = append(out, checks.Result{Status: checks.Error, Code: code, Message: capitalize(err.Error()) + "."})
	}
	seen := map[string]bool{}
	for _, d := range f.domains() {
		if err := caddyconf.ValidateDomain(d); err != nil {
			bad("domain_invalid", err)
		} else if seen[d] {
			bad("domain_invalid", fmt.Errorf("le domaine %s est saisi deux fois", d))
		}
		seen[d] = true
	}
	if f.locationsErr != nil {
		bad("locations_invalid", f.locationsErr)
	} else if f.Kind == caddyconf.KindProxy {
		if err := caddyconf.ValidateLocations(confLocations(f.Locations, nil)); err != nil {
			bad("locations_invalid", err)
		}
	}
	if f.Target != "" {
		switch f.Kind {
		case caddyconf.KindRedirect:
			for _, d := range f.domains() {
				if err := caddyconf.ValidateRedirect(d, f.Target, f.Code, f.Preserve); err != nil {
					bad("target_invalid", err)
					break
				}
			}
		case caddyconf.KindProxy:
			if _, _, err := caddyconf.ParseTarget(f.Target); err != nil {
				bad("target_invalid", err)
			}
		}
	}
	return out
}

func hasCode(rs []checks.Result, code string) bool {
	for _, r := range rs {
		if r.Code == code {
			return true
		}
	}
	return false
}

// runChecks valide la saisie puis vérifie le DNS (tous les types) et la réponse
// du service (type service seulement) en parallèle.
func (s *Server) runChecks(ctx context.Context, f formInput) (results []checks.Result, blocking bool) {
	formatErrs := f.problems()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var tgt *checks.Result
	var wg sync.WaitGroup
	dns := s.checkAllDNS(ctx, f.domains(), &wg)
	if f.Kind == caddyconf.KindProxy && f.Target != "" && !hasCode(formatErrs, "target_invalid") {
		wg.Add(1)
		go func() { defer wg.Done(); r := s.cfg.CheckTarget(ctx, f.Target); tgt = &r }()
	}
	wg.Wait()
	results = append(results, formatErrs...)
	for _, r := range *dns {
		if r != nil {
			results = append(results, *r)
		}
	}
	if tgt != nil {
		results = append(results, *tgt)
	}
	for _, r := range results {
		if r.Status == checks.Error {
			blocking = true
		}
	}
	return results, blocking
}

// checkAllDNS lance en parallèle la vérification DNS de chaque nom valide ; les
// résultats (dans l'ordre des noms, nil pour un nom invalide) sont prêts après wg.Wait.
func (s *Server) checkAllDNS(ctx context.Context, domains []string, wg *sync.WaitGroup) *[]*checks.Result {
	out := make([]*checks.Result, len(domains))
	for i, d := range domains {
		if caddyconf.ValidateDomain(d) != nil {
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); r := s.cfg.CheckDNS(ctx, d); out[i] = &r }()
	}
	return &out
}

// --- pages ---

// formPage prépare la page du formulaire : création (old == nil) ou modification.
func (s *Server) formPage(r *http.Request, old *store.Host, kind string) page {
	p := s.authedPage(r, "Nouvel hôte", kind)
	p.Kind, p.ListPath, p.Heading, p.Action, p.Submit = kind, listPath(kind), "Nouvel hôte", "/hosts", "Créer"
	p.Code, p.Preserve = 301, true
	switch kind {
	case caddyconf.KindRedirect:
		p.Heading, p.Submit = "Nouvelle redirection", "Créer la redirection"
	case caddyconf.KindNotFound:
		p.Heading, p.Submit = "Nouvelle erreur 404", "Créer l'erreur 404"
	default:
		p.Heading, p.Submit = "Nouvel hôte", "Créer l'hôte"
	}
	p.Title = p.Heading // le titre de l'onglet suit le titre de la page (redirection, erreur 404)
	if kind == caddyconf.KindProxy {
		p.Lists = s.listViews(r.Context())
	}
	p.DNS = s.dnsViews(r.Context())
	p.LocRows = s.locRows(r.Context(), nil)
	if cs, _ := s.activeCrowdSec(r.Context()); cs != nil && cs.AppSecURL != "" {
		p.WAFAvailable = true // le WAF n'est proposé que si AppSec est connecté
	}
	p.Compress = true // activée par défaut pour un nouvel hôte
	if old == nil && kind == caddyconf.KindProxy {
		p.Target = strings.TrimSpace(r.URL.Query().Get("target"))
	}
	if old != nil {
		p.LocRows, p.HasLocations = s.locRows(r.Context(), old.Locations), len(old.Locations) > 0
		p.Compress, p.NoBuffering, p.FrameOptions, p.NoIndex, p.WAF = old.Compress, old.NoBuffering, old.FrameOptions, old.NoIndex, old.WAF
		p.AccessID, p.DNSID, p.HTTPOnly, p.SelfSigned, p.HSTS = old.AccessListID, old.DNSAccountID, old.HTTPOnly, old.SelfSigned, old.HSTS
		p.Title, p.Editing = "Modifier "+old.Domain, true
		p.EditID, p.EditDisabled = old.ID, old.Disabled
		p.Heading, p.Action, p.Submit = "Modifier "+old.Domain, "/hosts/"+strconv.FormatInt(old.ID, 10), "Enregistrer"
		p.Domain, p.Target = domainsText(old.Domain, old.Aliases), old.Target
		if old.Kind == caddyconf.KindRedirect {
			p.Code, p.Preserve = old.Code, old.PreservePath
		}
	}
	return p
}

func (s *Server) newForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "new", s.formPage(r, nil, kindFromForm(r.URL.Query().Get("kind"))))
}

func (s *Server) editForm(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostFromPath(w, r)
	if !ok {
		return
	}
	s.render(w, "new", s.formPage(r, &h, kindFromForm(h.Kind)))
}

// --- vérifications en direct (appelées séparément par la page) ---

func (s *Server) liveForm(w http.ResponseWriter, r *http.Request) (formInput, bool) {
	if !s.parseForm(w, r) {
		return formInput{}, false
	}
	return readForm(r, kindFromForm(r.PostFormValue("kind"))), true
}

func (s *Server) checkDNS(w http.ResponseWriter, r *http.Request) {
	f, ok := s.liveForm(w, r)
	if !ok {
		return
	}
	if f.Domain == "" {
		fmt.Fprint(w, `<small class="muted wait">…</small>`)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	dns := s.checkAllDNS(ctx, f.domains(), &wg)
	wg.Wait()
	var res []checks.Result
	for i, d := range f.domains() {
		if err := caddyconf.ValidateDomain(d); err != nil {
			res = append(res, checks.Result{Status: checks.Error, Code: "domain_invalid", Message: capitalize(err.Error()) + "."})
		} else if r := (*dns)[i]; r != nil {
			res = append(res, *r)
		}
	}
	s.renderFragment(w, "new", "checks", viewResults(res))
}

func (s *Server) checkTarget(w http.ResponseWriter, r *http.Request) {
	f, ok := s.liveForm(w, r)
	if !ok {
		return
	}
	if f.Kind == caddyconf.KindNotFound || f.Target == "" {
		fmt.Fprint(w, `<small class="muted wait">…</small>`)
		return
	}
	var res checks.Result
	if errs := f.problems(); hasCode(errs, "target_invalid") {
		res = errs[len(errs)-1]
		for _, e := range errs {
			if e.Code == "target_invalid" {
				res = e
			}
		}
	} else if f.Kind == caddyconf.KindRedirect {
		// Pas de test réseau : la destination est validée sur sa forme et l'absence de boucle.
		res = checks.Result{Status: checks.OK, Code: "redirect_ok", Message: fmt.Sprintf("Les visiteurs seront envoyés vers %s.", f.Target)}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		res = s.cfg.CheckTarget(ctx, f.Target)
	}
	s.renderFragment(w, "new", "checks", viewResults([]checks.Result{res}))
}

// caddyfilePreview montre l'équivalent Caddyfile de ce que Gatewyn va publier.
// lists : adresses de chaque liste d'accès, par identifiant.
func caddyfilePreview(f formInput, lists map[int64][]string) string {
	var body string
	switch f.Kind {
	case caddyconf.KindRedirect:
		to := f.Target
		if f.Preserve {
			to = strings.TrimRight(to, "/") + "{uri}"
		}
		body = fmt.Sprintf("redir %s %d", to, f.Code)
	case caddyconf.KindNotFound:
		body = `respond "404 Not Found" 404`
	default:
		// withRefuse ajoute le refus 403 des adresses hors liste avant la ligne du service.
		withRefuse := func(line string, ranges []string, indent string) string {
			if len(ranges) == 0 {
				return line
			}
			return "@refuse not client_ip " + strings.Join(ranges, " ") + "\n" + indent + "respond @refuse 403\n" + indent + line
		}
		dialOf := func(target string) string {
			d, tls, _ := caddyconf.ParseTarget(target)
			switch {
			case tls:
				d = "https://" + d
			case caddyconf.IsH2C(target):
				d = "h2c://" + d
			}
			return d
		}
		proxy := func(target string) string {
			line := "reverse_proxy " + dialOf(target)
			if f.NoBuffering {
				line = "reverse_proxy " + dialOf(target) + " {\n    flush_interval -1\n  }"
			}
			return line
		}
		hostAccess := lists[f.Access]
		body = withRefuse(proxy(f.Target), hostAccess, "  ")
		if len(f.Locations) > 0 {
			var handles string
			for _, l := range f.Locations {
				ranges := hostAccess
				switch {
				case l.Access == store.PublicAccess:
					ranges = nil
				case l.Access > 0:
					ranges = lists[l.Access]
				}
				line := proxy(cmp.Or(l.Target, f.Target))
				if l.StripPath {
					line = "uri strip_prefix " + l.Path + "\n    " + line
				}
				handles += "handle " + l.Path + "* {\n    " + withRefuse(line, ranges, "    ") + "\n  }\n  "
			}
			body = handles + "handle {\n    " + withRefuse(proxy(f.Target), hostAccess, "    ") + "\n  }"
		}
	}
	if f.Kind == caddyconf.KindProxy && f.Compress {
		body = "encode zstd gzip\n  " + body
	}
	set := (caddyconf.Host{HSTS: f.HSTS, FrameOptions: f.FrameOptions, NoIndex: f.NoIndex, HTTPOnly: f.HTTPOnly}).ResponseHeaders()
	for _, name := range []string{"Strict-Transport-Security", "X-Frame-Options", "X-Robots-Tag"} {
		if v := set.Get(name); v != "" {
			body = "header " + name + ` "` + v + "\"\n  " + body
		}
	}
	names := f.domains()
	if f.HTTPOnly {
		for i, d := range names {
			names[i] = "http://" + d
		}
	} else if f.SelfSigned {
		body = "tls internal\n  " + body
	}
	return strings.Join(names, ", ") + " {\n  " + body + "\n}"
}

func (s *Server) checkPreview(w http.ResponseWriter, r *http.Request) {
	f, ok := s.liveForm(w, r)
	if !ok {
		return
	}
	if f.Domain == "" || (f.Kind != caddyconf.KindNotFound && f.Target == "") || len(f.problems()) > 0 {
		fmt.Fprint(w, `<small class="muted">L'équivalent Caddyfile de ce que Gatewyn publiera apparaît ici.</small>`)
		return
	}
	lists := map[int64][]string{}
	if all, err := s.cfg.Store.AccessLists(r.Context()); err == nil {
		for _, l := range all {
			lists[l.ID] = l.Addresses
		}
	}
	fmt.Fprintf(w, "<pre>%s</pre>", template.HTMLEscapeString(caddyfilePreview(f, lists)))
}

func viewResults(rs []checks.Result) []resultView {
	out := make([]resultView, len(rs))
	for i, r := range rs {
		out[i] = view(r)
	}
	return out
}

// --- création et modification ---

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) { s.saveHost(w, r, nil) }

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostFromPath(w, r)
	if !ok {
		return
	}
	s.saveHost(w, r, &h)
}

// saveHost crée un hôte (old == nil) ou modifie old ; le type d'un hôte existant
// ne change pas. Une saisie invalide est refusée sans possibilité de forcer ; un
// problème de DNS ou de service demande une confirmation ; un refus de Caddy
// annule le changement.
func (s *Server) saveHost(w http.ResponseWriter, r *http.Request, old *store.Host) {
	if !s.parseForm(w, r) {
		return
	}
	ctx := r.Context()
	kind := kindFromForm(r.PostFormValue("kind"))
	if old != nil {
		kind = kindFromForm(old.Kind)
	}
	f := readForm(r, kind)
	p := s.formPage(r, old, kind)
	p.LocRows, p.HasLocations = s.locRows(ctx, f.Locations), len(f.Locations) > 0
	p.Compress, p.NoBuffering, p.FrameOptions, p.NoIndex, p.WAF = f.Compress, f.NoBuffering, f.FrameOptions, f.NoIndex, f.WAF
	p.Domain, p.Target, p.Preserve, p.AccessID, p.DNSID, p.HTTPOnly, p.SelfSigned, p.HSTS = domainsText(f.Domain, f.Aliases), f.Target, f.Preserve, f.Access, f.DNS, f.HTTPOnly, f.SelfSigned, f.HSTS
	if f.Kind == caddyconf.KindRedirect {
		p.Code = f.Code
	}
	reject := func(code int, msg string, rs []checks.Result, canForce bool) {
		p.Error, p.CanForce = msg, canForce
		p.Checks = viewResults(rs)
		w.WriteHeader(code)
		s.render(w, "new", p)
	}

	if old != nil && f.same(*old) {
		http.Redirect(w, r, listPath(kind), http.StatusSeeOther)
		return
	}
	results, blocking := s.runChecks(ctx, f)
	if f.Access != 0 {
		if _, err := s.cfg.Store.AccessListByID(ctx, f.Access); err != nil {
			reject(http.StatusUnprocessableEntity, "Cette liste d'accès n'existe plus. Choisissez-en une autre.", results, false)
			return
		}
	}
	for _, l := range f.Locations {
		if l.Access > 0 {
			if _, err := s.cfg.Store.AccessListByID(ctx, l.Access); err != nil {
				reject(http.StatusUnprocessableEntity, "Une liste d'accès choisie pour un chemin n'existe plus. Choisissez-en une autre.", results, false)
				return
			}
		}
	}
	if f.DNS != 0 {
		if _, err := s.cfg.Store.DNSAccountByID(ctx, f.DNS); err != nil {
			reject(http.StatusUnprocessableEntity, "Ce compte DNS n'existe plus. Choisissez-en un autre.", results, false)
			return
		}
	}
	switch {
	case f.Domain == "" || (f.Kind != caddyconf.KindNotFound && f.Target == ""):
		missing := "Indiquez le domaine et la cible."
		if f.Kind == caddyconf.KindRedirect {
			missing = "Indiquez le domaine et la destination."
		} else if f.Kind == caddyconf.KindNotFound {
			missing = "Indiquez le domaine."
		}
		reject(http.StatusUnprocessableEntity, missing, results, false)
		return
	case hasCode(results, "domain_invalid") || hasCode(results, "target_invalid") || hasCode(results, "locations_invalid"):
		reject(http.StatusUnprocessableEntity, "Corrigez la saisie avant de continuer.", results, false)
		return
	case blocking && r.PostFormValue("force") != "1":
		reject(http.StatusUnprocessableEntity,
			"Cet hôte ne fonctionnera pas tant que ces problèmes ne sont pas réglés. Corrigez-les, ou continuez quand même.", results, true)
		return
	}

	var exceptID int64
	if old != nil {
		exceptID = old.ID
	}
	if taken, err := s.domainTaken(ctx, f.domains(), exceptID); err != nil {
		s.fail(w, r, err)
		return
	} else if taken != "" {
		reject(http.StatusConflict, fmt.Sprintf("%s existe déjà dans la liste.", taken), results, false)
		return
	}

	var id int64
	var err error
	if old == nil {
		id, err = s.cfg.Store.AddHostFull(ctx, f.store())
	} else {
		id = old.ID
		err = s.cfg.Store.UpdateHostFull(ctx, old.ID, f.store())
	}
	if errors.Is(err, store.ErrExists) {
		reject(http.StatusConflict, fmt.Sprintf("%s existe déjà dans la liste.", f.Domain), results, false)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sync(ctx); err != nil {
		// Caddy a refusé : on revient à l'état d'avant pour que la liste reste vraie.
		if old == nil {
			_ = s.cfg.Store.DeleteHost(ctx, id)
		} else {
			_ = s.cfg.Store.UpdateHostFull(ctx, id, *old)
		}
		_ = s.sync(ctx)
		reject(http.StatusBadGateway, explainSyncError(err), results, false)
		return
	}
	if old == nil {
		s.audit(ctx, "host.create", f.Domain+" ("+kind+") → "+f.Target)
		http.Redirect(w, r, listPath(kind)+"?added="+template.URLQueryEscaper(f.Domain), http.StatusSeeOther)
		return
	}
	s.audit(ctx, "host.update", old.Domain+" → "+f.Domain+" "+f.Target)
	http.Redirect(w, r, listPath(kind)+"?changed="+template.URLQueryEscaper(f.Domain), http.StatusSeeOther)
}

// domainTaken renvoie le premier nom déjà utilisé par un autre hôte (domaine ou alias), ou "".
func (s *Server) domainTaken(ctx context.Context, domains []string, exceptID int64) (string, error) {
	hosts, err := s.cfg.Store.ListHosts(ctx)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, h := range hosts {
		if h.ID != exceptID {
			for _, d := range append([]string{h.Domain}, h.Aliases...) {
				used[d] = true
			}
		}
	}
	for _, d := range domains {
		if used[d] {
			return d, nil
		}
	}
	return "", nil
}

// --- affichage d'un hôte dans la liste ---

func toView(h store.Host, listNames map[int64]string) hostView {
	v := hostView{ID: h.ID, Domain: h.Domain, Aliases: strings.Join(h.Aliases, ", "), Kind: kindFromForm(h.Kind), Target: h.Target, Disabled: h.Disabled}
	switch v.Kind {
	case caddyconf.KindRedirect:
		v.Type = "Permanente"
		if h.Code == 302 {
			v.Type = "Temporaire"
		}
		v.Detail = "tout le monde arrive sur la même page"
		if h.PreservePath {
			v.Detail = "garde le chemin"
		}
		v.Dest = "→\u00a0" + h.Target
	case caddyconf.KindNotFound:
		v.Dest = "Répond « 404 Not Found »"
	default:
		v.Dest = h.Target
		v.IsProxy = true
		v.Tags = hostTags(h, listNames)
	}
	return v
}

// hostTags liste les options d'un service qui comptent pour l'accès ou la sécurité : qui peut
// venir, et si la connexion est protégée. Les réglages de confort (compression…) restent dans le formulaire.
func hostTags(h store.Host, listNames map[int64]string) []tagView {
	var tags []tagView
	if h.AccessListID != 0 {
		name := listNames[h.AccessListID]
		if name == "" {
			name = "inconnue"
		}
		tags = append(tags, tagView{"info", fmt.Sprintf("Liste d'accès : %s", name)})
	}
	if h.WAF {
		tags = append(tags, tagView{"ok", "WAF"})
	}
	if h.HSTS > 0 {
		tags = append(tags, tagView{"ok", "HSTS"})
	}
	if h.HTTPOnly {
		tags = append(tags, tagView{"warn", "HTTP seulement"})
	}
	if h.SelfSigned {
		tags = append(tags, tagView{"warn", "Certificat auto-signé"})
	}
	return tags
}
