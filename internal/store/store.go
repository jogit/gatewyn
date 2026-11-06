// Package store garde l'état de Gatewyn dans un fichier SQLite (pilote Go pur,
// sans CGO). Les migrations sont versionnées ; avant d'en appliquer une sur une
// base existante, le fichier est copié.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// migrations[i] fait passer le schéma de la version i à i+1.
var migrations = []string{
	`CREATE TABLE users (
	   id INTEGER PRIMARY KEY CHECK (id = 1),
	   username TEXT NOT NULL,
	   password_hash TEXT NOT NULL,
	   created_at INTEGER NOT NULL);
	 CREATE TABLE sessions (
	   token_hash TEXT PRIMARY KEY,
	   expires_at INTEGER NOT NULL);
	 CREATE TABLE hosts (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   domain TEXT NOT NULL UNIQUE,
	   target TEXT NOT NULL,
	   disabled INTEGER NOT NULL DEFAULT 0,
	   created_at INTEGER NOT NULL);
	 CREATE TABLE audit (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   at INTEGER NOT NULL,
	   action TEXT NOT NULL,
	   detail TEXT NOT NULL);
	 CREATE TABLE settings (
	   key TEXT PRIMARY KEY,
	   value TEXT NOT NULL);`,
	// 2 : historique des changements. Chaque entrée garde la liste complète des
	// hôtes ; la configuration Caddy en découle, donc revenir en arrière = rejouer une liste.
	`CREATE TABLE snapshots (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   at INTEGER NOT NULL,
	   reason TEXT NOT NULL,
	   hosts TEXT NOT NULL);
	 INSERT INTO snapshots (at, reason, hosts)
	   SELECT CAST(strftime('%s','now') AS INTEGER), 'État de départ',
	     (SELECT json_group_array(json_object('domain', domain, 'target', target,
	        'disabled', json(CASE disabled WHEN 1 THEN 'true' ELSE 'false' END))) FROM hosts);`,
	// 3 : types d'hôte (service, redirection, page introuvable). Les hôtes existants restent des services.
	`ALTER TABLE hosts ADD COLUMN kind TEXT NOT NULL DEFAULT 'proxy';
	 ALTER TABLE hosts ADD COLUMN code INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE hosts ADD COLUMN preserve_path INTEGER NOT NULL DEFAULT 0;`,
	// 4 : l'historique des changements est abandonné (il n'a jamais été demandé).
	`DROP TABLE snapshots;`,
	// 5 : listes d'accès par IP (adresses ou plages, une par ligne).
	`CREATE TABLE access_lists (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   name TEXT NOT NULL UNIQUE,
	   addresses TEXT NOT NULL);`,
	// 6 : un hôte peut être limité à une liste d'accès (NULL = public).
	`ALTER TABLE hosts ADD COLUMN access_list_id INTEGER REFERENCES access_lists(id);`,
	// 7 : comptes DNS pour le défi ACME (secret = identifiants chiffrés) ; un hôte peut en utiliser un (NULL = défi HTTP).
	`CREATE TABLE dns_accounts (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   name TEXT NOT NULL UNIQUE,
	   provider TEXT NOT NULL,
	   secret TEXT NOT NULL);
	 ALTER TABLE hosts ADD COLUMN dns_account_id INTEGER REFERENCES dns_accounts(id);`,
	// 8 : un hôte peut rester publié sans que Caddy demande de certificat pour lui.
	`ALTER TABLE hosts ADD COLUMN no_cert INTEGER NOT NULL DEFAULT 0;`,
	// 9 : noms supplémentaires d'un hôte (un par ligne).
	`ALTER TABLE hosts ADD COLUMN aliases TEXT NOT NULL DEFAULT '';`,
	// 10 : en-tête HSTS (0 = aucun, 1 = HSTS, 2 = HSTS avec les sous-domaines).
	`ALTER TABLE hosts ADD COLUMN hsts INTEGER NOT NULL DEFAULT 0;`,
	// 11 : « sans certificat » devient « HTTP seulement » (publié sur le port 80, sans HTTPS) ;
	// nouveau : certificat auto-signé par Caddy.
	`ALTER TABLE hosts RENAME COLUMN no_cert TO http_only;
	 ALTER TABLE hosts ADD COLUMN self_signed INTEGER NOT NULL DEFAULT 0;`,
	// 12 : chemins envoyés vers une autre cible (un par ligne : « /api http://192.0.2.5:3000 »).
	`ALTER TABLE hosts ADD COLUMN locations TEXT NOT NULL DEFAULT '';`,
	// 13 : options d'un hôte : compression, streaming sans tampon, en-têtes (cadre, noindex).
	`ALTER TABLE hosts ADD COLUMN compress INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE hosts ADD COLUMN no_buffering INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE hosts ADD COLUMN frame_options TEXT NOT NULL DEFAULT '';
	 ALTER TABLE hosts ADD COLUMN noindex INTEGER NOT NULL DEFAULT 0;`,
	// 14 : WAF (CrowdSec AppSec) activé pour un hôte.
	`ALTER TABLE hosts ADD COLUMN waf INTEGER NOT NULL DEFAULT 0;`,
}

// Version est la version de schéma que ce code attend.
var Version = len(migrations)

// ErrNotFound est renvoyée quand un élément demandé n'existe pas.
var ErrNotFound = errors.New("introuvable")

// ErrExists est renvoyée quand un domaine est déjà enregistré.
var ErrExists = errors.New("existe déjà")

// Store est une base Gatewyn ouverte.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Host est un hôte enregistré.
type Host struct {
	ID        int64
	Domain    string
	Kind      string // "proxy", "redirect" ou "404"
	Target    string // service (proxy), destination (redirect), vide (404)
	Disabled  bool
	CreatedAt time.Time

	// Redirection seulement.
	Code         int
	PreservePath bool

	// Service seulement : liste d'accès qui limite les adresses autorisées (0 = public).
	AccessListID int64

	// Compte DNS utilisé pour le certificat (0 = défi HTTP automatique).
	DNSAccountID int64

	// Publié en HTTP seulement (port 80), sans HTTPS ni certificat.
	HTTPOnly bool

	// Service seulement : chemins envoyés vers une autre cible.
	Locations []Location

	// Certificat auto-signé par l'autorité interne de Caddy.
	SelfSigned bool

	// Autres noms servis par le même hôte.
	Aliases []string

	// En-tête HSTS : 0 = aucun, 1 = HSTS, 2 = HSTS avec les sous-domaines.
	HSTS int

	// Service : compression des réponses (zstd, gzip) et streaming sans tampon.
	Compress, NoBuffering bool

	// Service : les requêtes passent par le WAF de CrowdSec (AppSec).
	WAF bool

	// En-têtes de réponse : X-Frame-Options (« », « SAMEORIGIN » ou « DENY ») et X-Robots-Tag: noindex.
	FrameOptions string
	NoIndex      bool
}

// AuditEntry est une ligne du journal d'audit.
type AuditEntry struct {
	At     time.Time
	Action string
	Detail string
}

// Open ouvre (ou crée) la base et applique les migrations manquantes. Si la
// base existait déjà dans une version plus ancienne, elle est d'abord copiée
// dans <chemin>.avant-v<N>-<date> (la copie reste en place).
func Open(path string) (*Store, error) {
	_, statErr := os.Stat(path)
	existed := statErr == nil

	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // une seule connexion : pas de verrou entre requêtes
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(path, existed); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close ferme la base.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(path string, existed bool) error {
	var current int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	if current > Version {
		return fmt.Errorf("la base %s est d'une version plus récente (%d) que ce Gatewyn (%d) : mettez Gatewyn à jour, ne revenez pas en arrière", path, current, Version)
	}
	if current == Version {
		return nil
	}
	if existed && current > 0 {
		backup := fmt.Sprintf("%s.avant-v%d-%s", path, current, s.now().UTC().Format("20060102T150405Z"))
		if _, err := s.db.Exec("VACUUM INTO ?", backup); err != nil {
			return fmt.Errorf("copie de sécurité avant migration impossible : %w", err)
		}
	}
	for v := current; v < Version; v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration vers la version %d : %w", v+1, err)
		}
		// PRAGMA user_version n'accepte pas de paramètre : la valeur est un entier du code.
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// --- compte administrateur ---

// AdminExists indique si le compte administrateur a été créé.
func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n > 0, err
}

// CreateAdmin crée le compte administrateur ; échoue s'il existe déjà.
func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO users (id, username, password_hash, created_at) VALUES (1, ?, ?, ?)", username, passwordHash, s.now().Unix())
	if err != nil && strings.Contains(err.Error(), "constraint") {
		return ErrExists
	}
	return err
}

// AdminCredentials renvoie l'identifiant et l'empreinte du mot de passe administrateur.
func (s *Store) AdminCredentials(ctx context.Context) (username, hash string, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT username, password_hash FROM users WHERE id = 1").Scan(&username, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return username, hash, err
}

// ChangePassword remplace l'empreinte du mot de passe et ferme toutes les sessions sauf celle
// dont l'empreinte est keepToken (la session qui a fait le changement).
func (s *Store) ChangePassword(ctx context.Context, passwordHash, keepToken string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE users SET password_hash = ? WHERE id = 1", passwordHash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash <> ?", keepToken); err != nil {
		return err
	}
	return tx.Commit()
}

// --- sessions (seule l'empreinte du jeton est stockée) ---

func (s *Store) CreateSession(ctx context.Context, tokenHash string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)", tokenHash, expires.Unix())
	return err
}

// SessionValid indique si la session existe et n'a pas expiré.
func (s *Store) SessionValid(ctx context.Context, tokenHash string) (bool, error) {
	var exp int64
	err := s.db.QueryRowContext(ctx, "SELECT expires_at FROM sessions WHERE token_hash = ?", tokenHash).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exp > s.now().Unix(), nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ?", tokenHash)
	return err
}

// PurgeSessions supprime les sessions expirées.
func (s *Store) PurgeSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ?", s.now().Unix())
	return err
}

// --- hôtes ---

const hostColumns = "id, domain, kind, target, disabled, created_at, code, preserve_path, COALESCE(access_list_id, 0), COALESCE(dns_account_id, 0), http_only, aliases, hsts, self_signed, locations, compress, no_buffering, frame_options, noindex, waf"

func scanHost(r scanner) (Host, error) {
	var h Host
	var dis, keep, httpOnly, selfSigned, compress, noBuffering, noIndex, waf int
	var aliases, locations string
	var at int64
	if err := r.Scan(&h.ID, &h.Domain, &h.Kind, &h.Target, &dis, &at, &h.Code, &keep, &h.AccessListID, &h.DNSAccountID, &httpOnly, &aliases, &h.HSTS, &selfSigned, &locations, &compress, &noBuffering, &h.FrameOptions, &noIndex, &waf); err != nil {
		return Host{}, err
	}
	h.Aliases = strings.Fields(aliases)
	h.Locations = decodeLocations(locations)
	h.Compress, h.NoBuffering, h.NoIndex, h.WAF = compress != 0, noBuffering != 0, noIndex != 0, waf != 0
	h.Disabled, h.PreservePath, h.HTTPOnly, h.SelfSigned, h.CreatedAt = dis != 0, keep != 0, httpOnly != 0, selfSigned != 0, time.Unix(at, 0)
	return h, nil
}

func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+hostColumns+" FROM hosts ORDER BY domain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) HostByID(ctx context.Context, id int64) (Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, "SELECT "+hostColumns+" FROM hosts WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	return h, err
}

// AddHostFull enregistre un hôte de n'importe quel type.
func (s *Store) AddHostFull(ctx context.Context, h Host) (int64, error) {
	if h.Kind == "" {
		h.Kind = "proxy"
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO hosts (domain, kind, target, code, preserve_path, access_list_id, dns_account_id, http_only, aliases, hsts, self_signed, locations, compress, no_buffering, frame_options, noindex, waf, created_at) VALUES (?, ?, ?, ?, ?, NULLIF(?, 0), NULLIF(?, 0), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		h.Domain, h.Kind, h.Target, h.Code, boolInt(h.PreservePath), h.AccessListID, h.DNSAccountID, boolInt(h.HTTPOnly), strings.Join(h.Aliases, "\n"), h.HSTS, boolInt(h.SelfSigned), encodeLocations(h.Locations), boolInt(h.Compress), boolInt(h.NoBuffering), h.FrameOptions, boolInt(h.NoIndex), boolInt(h.WAF), s.now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrExists
		}
		return 0, err
	}
	return res.LastInsertId()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM hosts WHERE id = ?", id)
	return affected(res, err)
}

func (s *Store) SetHostDisabled(ctx context.Context, id int64, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	res, err := s.db.ExecContext(ctx, "UPDATE hosts SET disabled = ? WHERE id = ?", v, id)
	return affected(res, err)
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- réglages et audit ---

// Setting renvoie un réglage, ou "" s'il n'est pas défini.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

// Audit ajoute une ligne au journal d'audit. Ne jamais y mettre de secret.
func (s *Store) Audit(ctx context.Context, action, detail string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit (at, action, detail) VALUES (?, ?, ?)", s.now().Unix(), action, detail)
	return err
}

// RecentAudit renvoie les n dernières lignes, la plus récente d'abord.
func (s *Store) RecentAudit(ctx context.Context, n int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT at, action, detail FROM audit ORDER BY id DESC LIMIT ?", n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- modification d'hôtes ---

// UpdateHostFull remplace le domaine, la destination et les options d'un hôte ;
// le type et l'état (désactivé) ne changent pas.
func (s *Store) UpdateHostFull(ctx context.Context, id int64, h Host) error {
	res, err := s.db.ExecContext(ctx, "UPDATE hosts SET domain = ?, target = ?, code = ?, preserve_path = ?, access_list_id = NULLIF(?, 0), dns_account_id = NULLIF(?, 0), http_only = ?, aliases = ?, hsts = ?, self_signed = ?, locations = ?, compress = ?, no_buffering = ?, frame_options = ?, noindex = ?, waf = ? WHERE id = ?",
		h.Domain, h.Target, h.Code, boolInt(h.PreservePath), h.AccessListID, h.DNSAccountID, boolInt(h.HTTPOnly), strings.Join(h.Aliases, "\n"), h.HSTS, boolInt(h.SelfSigned), encodeLocations(h.Locations), boolInt(h.Compress), boolInt(h.NoBuffering), h.FrameOptions, boolInt(h.NoIndex), boolInt(h.WAF), id)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrExists
	}
	return affected(res, err)
}

type scanner interface{ Scan(dest ...any) error }

// Location applique une règle à un chemin : vers une autre cible (Target vide : celle de l'hôte). Access : 0 = comme l'hôte,
// PublicAccess = ouvert à tous, sinon identifiant de la liste d'accès.
type Location struct {
	Path, Target string
	Access       int64
	StripPath    bool // retirer le chemin avant de transmettre : /api/x devient /x
}

// PublicAccess : le chemin est ouvert à tous, même si l'hôte a une liste d'accès.
const PublicAccess = -1

func encodeLocations(ls []Location) string {
	lines := make([]string, len(ls))
	for i, l := range ls {
		target := l.Target
		if target == "" {
			target = "-" // même cible que l'hôte
		}
		lines[i] = l.Path + " " + target + " " + strconv.FormatInt(l.Access, 10) + " " + strconv.Itoa(boolInt(l.StripPath))
	}
	return strings.Join(lines, "\n")
}

func decodeLocations(text string) []Location {
	var out []Location
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || len(f) > 4 {
			continue
		}
		l := Location{Path: f[0], Target: f[1]}
		if l.Target == "-" {
			l.Target = ""
		}
		if len(f) >= 3 {
			l.Access, _ = strconv.ParseInt(f[2], 10, 64)
		}
		l.StripPath = len(f) == 4 && f[3] == "1"
		out = append(out, l)
	}
	return out
}

// AccessList est une liste d'adresses IP ou de plages (CIDR).
type AccessList struct {
	ID        int64
	Name      string
	Addresses []string
}

func (s *Store) AccessLists(ctx context.Context) ([]AccessList, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, addresses FROM access_lists ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessList
	for rows.Next() {
		var l AccessList
		var addrs string
		if err := rows.Scan(&l.ID, &l.Name, &addrs); err != nil {
			return nil, err
		}
		l.Addresses = strings.Fields(addrs)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) AccessListByID(ctx context.Context, id int64) (AccessList, error) {
	var l AccessList
	var addrs string
	err := s.db.QueryRowContext(ctx, "SELECT id, name, addresses FROM access_lists WHERE id = ?", id).Scan(&l.ID, &l.Name, &addrs)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	l.Addresses = strings.Fields(addrs)
	return l, err
}

func (s *Store) AddAccessList(ctx context.Context, l AccessList) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO access_lists (name, addresses) VALUES (?, ?)", l.Name, strings.Join(l.Addresses, "\n"))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrExists
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateAccessList(ctx context.Context, l AccessList) error {
	res, err := s.db.ExecContext(ctx, "UPDATE access_lists SET name = ?, addresses = ? WHERE id = ?", l.Name, strings.Join(l.Addresses, "\n"), l.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrExists
	}
	return affected(res, err)
}

func (s *Store) DeleteAccessList(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM access_lists WHERE id = ?", id)
	return affected(res, err)
}

// DNSAccount est un compte chez un fournisseur DNS. Secret contient les
// identifiants déjà chiffrés : le chiffrement n'est pas l'affaire de la base.
type DNSAccount struct {
	ID       int64
	Name     string
	Provider string
	Secret   string
}

func (s *Store) DNSAccounts(ctx context.Context) ([]DNSAccount, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, provider, secret FROM dns_accounts ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSAccount
	for rows.Next() {
		var a DNSAccount
		if err := rows.Scan(&a.ID, &a.Name, &a.Provider, &a.Secret); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DNSAccountByID(ctx context.Context, id int64) (DNSAccount, error) {
	var a DNSAccount
	err := s.db.QueryRowContext(ctx, "SELECT id, name, provider, secret FROM dns_accounts WHERE id = ?", id).Scan(&a.ID, &a.Name, &a.Provider, &a.Secret)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (s *Store) AddDNSAccount(ctx context.Context, a DNSAccount) (int64, error) {
	res, err := s.db.ExecContext(ctx, "INSERT INTO dns_accounts (name, provider, secret) VALUES (?, ?, ?)", a.Name, a.Provider, a.Secret)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrExists
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateDNSAccount(ctx context.Context, a DNSAccount) error {
	res, err := s.db.ExecContext(ctx, "UPDATE dns_accounts SET name = ?, provider = ?, secret = ? WHERE id = ?", a.Name, a.Provider, a.Secret, a.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrExists
	}
	return affected(res, err)
}

func (s *Store) DeleteDNSAccount(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM dns_accounts WHERE id = ?", id)
	return affected(res, err)
}
