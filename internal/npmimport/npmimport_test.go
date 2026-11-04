package npmimport

import (
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jogit/gatewyn/internal/caddyconf"
)

// Schéma de NPM tel que produit par ses migrations (colonnes utiles seulement).
// Toutes les données sont fictives : example.com et 192.0.2.x.
const schema = `
CREATE TABLE proxy_host (
  id INTEGER PRIMARY KEY AUTOINCREMENT, is_deleted INTEGER NOT NULL DEFAULT 0,
  domain_names JSON NOT NULL, forward_scheme TEXT NOT NULL DEFAULT 'http',
  forward_host TEXT NOT NULL, forward_port INTEGER NOT NULL,
  access_list_id INTEGER NOT NULL DEFAULT 0, certificate_id INTEGER NOT NULL DEFAULT 0,
  ssl_forced INTEGER NOT NULL DEFAULT 0, caching_enabled INTEGER NOT NULL DEFAULT 0,
  block_exploits INTEGER NOT NULL DEFAULT 0, advanced_config TEXT NOT NULL DEFAULT '',
  allow_websocket_upgrade INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
  locations JSON, meta JSON NOT NULL DEFAULT '{}');
CREATE TABLE certificate (
  id INTEGER PRIMARY KEY AUTOINCREMENT, is_deleted INTEGER NOT NULL DEFAULT 0,
  provider TEXT NOT NULL, nice_name TEXT NOT NULL DEFAULT '', domain_names JSON NOT NULL,
  meta JSON NOT NULL DEFAULT '{}');
CREATE TABLE access_list (
  id INTEGER PRIMARY KEY AUTOINCREMENT, is_deleted INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL);
CREATE TABLE access_list_client (
  id INTEGER PRIMARY KEY AUTOINCREMENT, access_list_id INTEGER NOT NULL, address TEXT NOT NULL,
  directive TEXT NOT NULL);
CREATE TABLE redirection_host (id INTEGER PRIMARY KEY AUTOINCREMENT, is_deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE dead_host (id INTEGER PRIMARY KEY AUTOINCREMENT, is_deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE stream (id INTEGER PRIMARY KEY AUTOINCREMENT, is_deleted INTEGER NOT NULL DEFAULT 0);

INSERT INTO certificate (id, provider, domain_names, meta) VALUES
  (1, 'letsencrypt', '["wiki.example.com"]', '{"letsencrypt_email":"admin@example.com"}'),
  (2, 'letsencrypt', '["dns.example.com"]', '{"dns_challenge":true,"dns_provider":"ovh","dns_provider_credentials":"SECRET-NE-PAS-LIRE"}'),
  (3, 'other', '["other.example.com"]', '{}');
INSERT INTO access_list (id, name) VALUES (1, 'Famille');
INSERT INTO access_list_client (access_list_id, address, directive) VALUES (1, '192.0.2.0/24', 'allow'), (1, 'all', 'deny');

INSERT INTO proxy_host (id, is_deleted, domain_names, forward_scheme, forward_host, forward_port, access_list_id, certificate_id, ssl_forced, caching_enabled, advanced_config, enabled, locations) VALUES
  (1, 0, '["wiki.example.com"]',                 'http',  '192.0.2.21', 8080, 0, 1, 1, 0, '',                       1, NULL),
  (2, 0, '["a.example.com","b.example.com"]',    'http',  '192.0.2.22', 3000, 0, 0, 0, 0, '',                       1, '[]'),
  (3, 0, '["private.example.com"]',              'http',  '192.0.2.23', 80,   1, 0, 1, 0, '',                       1, NULL),
  (4, 0, '["nginx.example.com"]',                'http',  '192.0.2.24', 9000, 0, 0, 0, 1, 'proxy_buffering off;',   1, '[{"path":"/api","forward_host":"192.0.2.25","forward_port":1}]'),
  (5, 0, '["old.example.com"]',                  'http',  '192.0.2.26', 8081, 0, 0, 0, 0, '',                       0, NULL),
  (6, 1, '["gone.example.com"]',                 'http',  '192.0.2.27', 8082, 0, 0, 0, 0, '',                       1, NULL),
  (7, 0, '["dns.example.com"]',                  'http',  '192.0.2.28', 8083, 0, 2, 1, 0, '',                       1, NULL),
  (8, 0, '["other.example.com"]',                'http',  '192.0.2.29', 8084, 0, 3, 1, 0, '',                       1, NULL),
  (9, 0, '["nas.example.com"]',                  'https', '192.0.2.30', 5001, 0, 0, 1, 0, '',                       1, NULL),
  (10, 0, '["pas un domaine"]',                  'http',  '192.0.2.31', 8085, 0, 0, 0, 0, '',                       1, NULL),
  (11, 0, '["empty.example.com"]',               'http',  '',           8086, 0, 0, 0, 0, '',                       1, NULL),
  (12, 0, '["v6.example.com"]',                  'http',  '2001:db8::1', 8087, 0, 0, 0, 0, '',                      1, NULL);
INSERT INTO redirection_host (is_deleted) VALUES (0), (0), (1);
INSERT INTO dead_host (is_deleted) VALUES (0);
INSERT INTO stream (is_deleted) VALUES (0), (0), (0);
`

func newDB(t *testing.T, ddl string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "database.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	return path
}

func byDomain(rep *Report, domain string) *Imported {
	for i := range rep.Hosts {
		if rep.Hosts[i].Host.Domain == domain {
			return &rep.Hosts[i]
		}
	}
	return nil
}

func hasNote(h *Imported, code string) bool {
	for _, n := range h.Notes {
		if n.Code == code {
			return true
		}
	}
	return false
}

func TestReadImportsHosts(t *testing.T) {
	rep, err := Read(newDB(t, schema))
	if err != nil {
		t.Fatal(err)
	}

	wiki := byDomain(rep, "wiki.example.com")
	if wiki == nil || wiki.Host.Target != "http://192.0.2.21:8080" || wiki.Host.Disabled || len(wiki.Notes) != 0 {
		t.Errorf("wiki = %+v", wiki)
	}
	if nas := byDomain(rep, "nas.example.com"); nas == nil || nas.Host.Target != "https://192.0.2.30:5001" {
		t.Errorf("nas = %+v", nas)
	}
	if v6 := byDomain(rep, "v6.example.com"); v6 == nil || v6.Host.Target != "http://[2001:db8::1]:8087" {
		t.Errorf("v6 = %+v", v6)
	}
	if byDomain(rep, "gone.example.com") != nil {
		t.Error("hôte supprimé dans NPM importé")
	}
}

func TestReadMultiDomainSplits(t *testing.T) {
	rep, _ := Read(newDB(t, schema))
	a, b := byDomain(rep, "a.example.com"), byDomain(rep, "b.example.com")
	if a == nil || b == nil || a.NPMID != 2 || b.NPMID != 2 || a.Host.Target != b.Host.Target {
		t.Fatalf("a = %+v, b = %+v", a, b)
	}
	if !hasNote(a, CodeMultiDomain) || !hasNote(b, CodeMultiDomain) {
		t.Error("remarque multi-domaines absente")
	}
}

func TestReadSignalsWhatIsNotImported(t *testing.T) {
	rep, _ := Read(newDB(t, schema))

	private := byDomain(rep, "private.example.com")
	if private == nil || !hasNote(private, CodeAccessList) {
		t.Fatalf("private = %+v", private)
	}
	if msg := private.Notes[0].Message; !strings.Contains(msg, "Famille") || !strings.Contains(msg, "2 règles") || !strings.Contains(msg, "public") {
		t.Errorf("message de liste d'accès : %q", msg)
	}

	nginx := byDomain(rep, "nginx.example.com")
	for _, code := range []string{CodeAdvancedConfig, CodeLocations, CodeCaching} {
		if nginx == nil || !hasNote(nginx, code) {
			t.Errorf("nginx sans remarque %s : %+v", code, nginx)
		}
	}
	if old := byDomain(rep, "old.example.com"); old == nil || !old.Host.Disabled || !hasNote(old, CodeDisabled) {
		t.Errorf("old = %+v", old)
	}
	if other := byDomain(rep, "other.example.com"); other == nil || !hasNote(other, CodeCustomCert) {
		t.Errorf("other = %+v", other)
	}
	dns := byDomain(rep, "dns.example.com")
	if dns == nil || !hasNote(dns, CodeDNSChallenge) || !strings.Contains(dns.Notes[0].Message, "ovh") {
		t.Errorf("dns = %+v", dns)
	}
}

func TestReadNeverExposesDNSCredentials(t *testing.T) {
	rep, _ := Read(newDB(t, schema))
	for _, h := range rep.Hosts {
		for _, n := range h.Notes {
			if strings.Contains(n.Message, "SECRET") {
				t.Errorf("identifiant DNS dans une remarque : %q", n.Message)
			}
		}
	}
}

func TestReadSkipsUnusableHosts(t *testing.T) {
	rep, _ := Read(newDB(t, schema))
	ids := map[int]string{}
	for _, s := range rep.Skipped {
		ids[s.NPMID] = s.Reason
	}
	if _, ok := ids[10]; !ok {
		t.Errorf("domaine invalide non signalé : %v", ids)
	}
	if _, ok := ids[11]; !ok {
		t.Errorf("hôte de cible vide non signalé : %v", ids)
	}
	if len(rep.Skipped) != 2 {
		t.Errorf("ignorés = %+v", rep.Skipped)
	}
}

func TestReadCountsOtherKinds(t *testing.T) {
	rep, _ := Read(newDB(t, schema))
	if rep.Redirections != 2 || rep.DeadHosts != 1 || rep.Streams != 3 {
		t.Errorf("redirections %d, 404 %d, flux %d", rep.Redirections, rep.DeadHosts, rep.Streams)
	}
}

func TestReadDoesNotModifyDatabase(t *testing.T) {
	path := newDB(t, schema)
	before, _ := os.ReadFile(path)
	filesBefore, _ := os.ReadDir(filepath.Dir(path))
	if _, err := Read(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	filesAfter, _ := os.ReadDir(filepath.Dir(path))
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Error("le fichier de base a changé")
	}
	if len(filesBefore) != len(filesAfter) {
		t.Errorf("fichiers annexes créés : %d -> %d", len(filesBefore), len(filesAfter))
	}
}

func TestReadOldSchemaWithoutOptionalColumns(t *testing.T) {
	path := newDB(t, `
CREATE TABLE proxy_host (id INTEGER PRIMARY KEY, domain_names JSON NOT NULL, forward_host TEXT NOT NULL, forward_port INTEGER NOT NULL);
INSERT INTO proxy_host VALUES (1, '["wiki.example.com"]', '192.0.2.21', 8080);`)
	rep, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	h := byDomain(rep, "wiki.example.com")
	if h == nil || h.Host.Target != "http://192.0.2.21:8080" || h.Host.Disabled {
		t.Errorf("h = %+v", h)
	}
}

func TestReadRejectsNonNPMDatabase(t *testing.T) {
	_, err := Read(newDB(t, `CREATE TABLE other (id INTEGER);`))
	if err == nil || !strings.Contains(err.Error(), "n'est pas une base Nginx Proxy Manager") {
		t.Errorf("erreur = %v", err)
	}
}

func TestReadMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sqlite")
	if _, err := Read(path); err == nil {
		t.Error("fichier absent accepté")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("fichier créé par une lecture")
	}
}

func TestImportedHostsBuildCaddyConfig(t *testing.T) {
	rep, err := Read(newDB(t, schema))
	if err != nil {
		t.Fatal(err)
	}
	hosts := make([]caddyconf.Host, 0, len(rep.Hosts))
	for _, h := range rep.Hosts {
		hosts = append(hosts, h.Host)
	}
	if _, err := caddyconf.BuildServer(hosts); err != nil {
		t.Errorf("les hôtes importés ne produisent pas de configuration Caddy : %v", err)
	}
}
