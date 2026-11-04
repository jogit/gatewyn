// Package npmimport lit la base SQLite de Nginx Proxy Manager, en lecture seule,
// et en tire des hôtes Gatewyn. Ce qui ne peut pas être repris est signalé
// plutôt que perdu en silence.
//
// Travaillez sur une copie de la base (fichier et son -wal) : même en lecture
// seule, SQLite peut créer des fichiers annexes à côté de la base ouverte.
package npmimport

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/jogit/gatewyn/internal/caddyconf"
)

// Codes des remarques, stables pour permettre la traduction de l'interface.
const (
	CodeAccessList     = "access_list"
	CodeAdvancedConfig = "advanced_config"
	CodeLocations      = "locations"
	CodeCaching        = "caching"
	CodeCustomCert     = "custom_certificate"
	CodeDNSChallenge   = "dns_challenge"
	CodeMultiDomain    = "multi_domain"
	CodeDisabled       = "disabled"
	CodeInvalid        = "invalid"
)

// Note signale ce qui n'a pas pu être repris tel quel pour un hôte.
type Note struct {
	Code    string
	Message string
}

// Imported est un hôte NPM converti.
type Imported struct {
	NPMID int
	Host  caddyconf.Host
	Notes []Note
}

// Skipped est un hôte NPM qui n'a pas pu être importé du tout.
type Skipped struct {
	NPMID   int
	Domains []string
	Reason  string
}

// Report est le résultat d'une lecture de la base NPM.
type Report struct {
	Hosts   []Imported
	Skipped []Skipped
	// Éléments NPM d'autres types, non repris par Gatewyn : seulement comptés.
	Redirections, DeadHosts, Streams int
}

// Read ouvre la base NPM en lecture seule et construit le rapport d'import.
func Read(path string) (*Report, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("base NPM illisible (%s) : %w", path, err)
	}
	cols, err := columns(db, "proxy_host")
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("%s n'est pas une base Nginx Proxy Manager (table proxy_host absente)", path)
	}
	for _, c := range []string{"id", "domain_names", "forward_host", "forward_port"} {
		if !cols[c] {
			return nil, fmt.Errorf("base NPM de version non reconnue : colonne proxy_host.%s absente", c)
		}
	}

	certs, err := readCertificates(db)
	if err != nil {
		return nil, err
	}
	lists, err := readAccessLists(db)
	if err != nil {
		return nil, err
	}

	rep := &Report{}
	rows, err := db.Query(hostQuery(cols))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r hostRow
		if err := rows.Scan(&r.id, &r.domains, &r.scheme, &r.host, &r.port, &r.enabled,
			&r.accessList, &r.certificate, &r.advanced, &r.locations, &r.caching); err != nil {
			return nil, err
		}
		rep.addHost(r, certs, lists)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(rep.Hosts, func(i, j int) bool { return rep.Hosts[i].Host.Domain < rep.Hosts[j].Host.Domain })

	rep.Redirections = count(db, "redirection_host")
	rep.DeadHosts = count(db, "dead_host")
	rep.Streams = count(db, "stream")
	return rep, nil
}

type hostRow struct {
	id                                     int
	domains, scheme, host, advanced        string
	locations                              sql.NullString
	port, enabled, accessList, certificate int
	caching                                int
}

// hostQuery tolère les anciennes versions de NPM en remplaçant les colonnes
// absentes par leur valeur par défaut.
func hostQuery(cols map[string]bool) string {
	// col renvoie la colonne, ou sa valeur par défaut sous le même nom.
	col := func(name, def string) string {
		if cols[name] {
			return name
		}
		return def + " AS " + name
	}
	advanced := "'' AS advanced_config"
	if cols["advanced_config"] {
		advanced = "COALESCE(advanced_config, '') AS advanced_config"
	}
	deleted := ""
	if cols["is_deleted"] {
		deleted = " WHERE is_deleted = 0"
	}
	return "SELECT id, domain_names, " + col("forward_scheme", "'http'") + ", forward_host, forward_port, " +
		col("enabled", "1") + ", " + col("access_list_id", "0") + ", " + col("certificate_id", "0") + ", " +
		advanced + ", " + col("locations", "NULL") + ", " + col("caching_enabled", "0") +
		" FROM proxy_host" + deleted + " ORDER BY id"
}

func (rep *Report) addHost(r hostRow, certs map[int]certInfo, lists map[int]listInfo) {
	var domains []string
	if err := json.Unmarshal([]byte(r.domains), &domains); err != nil || len(domains) == 0 {
		rep.Skipped = append(rep.Skipped, Skipped{NPMID: r.id, Reason: "liste de domaines illisible"})
		return
	}
	target, err := buildTarget(r.scheme, r.host, r.port)
	if err != nil {
		rep.Skipped = append(rep.Skipped, Skipped{NPMID: r.id, Domains: domains, Reason: err.Error()})
		return
	}
	if _, _, err := caddyconf.ParseTarget(target); err != nil {
		rep.Skipped = append(rep.Skipped, Skipped{NPMID: r.id, Domains: domains, Reason: err.Error()})
		return
	}

	var notes []Note
	if len(domains) > 1 {
		notes = append(notes, Note{CodeMultiDomain, fmt.Sprintf(
			"cet hôte NPM a %d domaines ; Gatewyn crée un hôte par domaine, avec la même cible", len(domains))})
	}
	if r.enabled == 0 {
		notes = append(notes, Note{CodeDisabled, "hôte désactivé dans NPM : importé désactivé"})
	}
	if r.accessList != 0 {
		l, ok := lists[r.accessList]
		msg := "liste d'accès non importée : l'hôte sera public tant que vous n'avez pas recréé la règle"
		if ok {
			msg = fmt.Sprintf("liste d'accès « %s » (%d règles) non importée : l'hôte sera public tant que vous n'avez pas recréé la règle", l.name, l.clients)
		}
		notes = append(notes, Note{CodeAccessList, msg})
	}
	if strings.TrimSpace(r.advanced) != "" {
		notes = append(notes, Note{CodeAdvancedConfig, "directives nginx personnalisées non importées"})
	}
	if r.locations.Valid && strings.TrimSpace(r.locations.String) != "" &&
		strings.TrimSpace(r.locations.String) != "[]" && strings.TrimSpace(r.locations.String) != "null" {
		notes = append(notes, Note{CodeLocations, "chemins personnalisés (locations) non importés"})
	}
	if r.caching != 0 {
		notes = append(notes, Note{CodeCaching, "mise en cache nginx non reprise"})
	}
	if c, ok := certs[r.certificate]; ok && r.certificate != 0 {
		switch {
		case c.provider == "other":
			notes = append(notes, Note{CodeCustomCert, "certificat importé à la main non repris : Caddy en demandera un automatiquement"})
		case c.dnsChallenge:
			msg := "certificat obtenu par défi DNS"
			if c.dnsProvider != "" {
				msg += " (" + c.dnsProvider + ")"
			}
			notes = append(notes, Note{CodeDNSChallenge, msg + " : Caddy en aura besoin du module DNS correspondant (OVH seulement dans l'image par défaut)"})
		}
	}

	for _, d := range domains {
		h := caddyconf.Host{Domain: strings.ToLower(strings.TrimSpace(d)), Target: target, Disabled: r.enabled == 0}
		if err := caddyconf.ValidateDomain(h.Domain); err != nil {
			rep.Skipped = append(rep.Skipped, Skipped{NPMID: r.id, Domains: []string{d}, Reason: err.Error()})
			continue
		}
		rep.Hosts = append(rep.Hosts, Imported{NPMID: r.id, Host: h, Notes: append([]Note(nil), notes...)})
	}
}

func buildTarget(scheme, host string, port int) (string, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "http"
	}
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "/ ") {
		return "", fmt.Errorf("cible illisible : hôte %q", host)
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("cible illisible : port %d", port)
	}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	return u.String(), nil
}

type certInfo struct {
	provider     string
	dnsChallenge bool
	dnsProvider  string
}

// readCertificates ne lit que le type de certificat et, dans meta, le défi DNS
// et son fournisseur. Les identifiants DNS stockés dans meta ne sont jamais lus.
func readCertificates(db *sql.DB) (map[int]certInfo, error) {
	out := map[int]certInfo{}
	cols, err := columns(db, "certificate")
	if err != nil || len(cols) == 0 {
		return out, err
	}
	rows, err := db.Query(`SELECT id, provider, COALESCE(meta, '{}') FROM certificate WHERE is_deleted = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var provider, meta string
		if err := rows.Scan(&id, &provider, &meta); err != nil {
			return nil, err
		}
		var m struct {
			DNSChallenge bool   `json:"dns_challenge"`
			DNSProvider  string `json:"dns_provider"`
		}
		_ = json.Unmarshal([]byte(meta), &m) // meta absent ou illisible : valeurs par défaut
		out[id] = certInfo{provider: provider, dnsChallenge: m.DNSChallenge, dnsProvider: m.DNSProvider}
	}
	return out, rows.Err()
}

type listInfo struct {
	name    string
	clients int
}

func readAccessLists(db *sql.DB) (map[int]listInfo, error) {
	out := map[int]listInfo{}
	cols, err := columns(db, "access_list")
	if err != nil || len(cols) == 0 {
		return out, err
	}
	rows, err := db.Query(`SELECT id, name FROM access_list WHERE is_deleted = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = listInfo{name: name, clients: countWhere(db, "access_list_client", "access_list_id", id)}
	}
	return out, rows.Err()
}

func columns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		cols[n] = true
	}
	return cols, rows.Err()
}

// count renvoie le nombre de lignes non supprimées d'une table, 0 si elle est absente.
func count(db *sql.DB, table string) int {
	return countWhere(db, table, "", 0)
}

// countWhere compte aussi avec la condition colonne = valeur si colonne n'est pas vide.
func countWhere(db *sql.DB, table, column string, value int) int {
	cols, err := columns(db, table)
	if err != nil || len(cols) == 0 {
		return 0
	}
	var conds []string
	var args []any
	if cols["is_deleted"] {
		conds = append(conds, "is_deleted = 0")
	}
	if column != "" {
		conds = append(conds, column+" = ?")
		args = append(args, value)
	}
	q := "SELECT COUNT(*) FROM " + table
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}
