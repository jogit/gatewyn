package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gatewyn.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

var ctx = context.Background()

func TestAdminLifecycle(t *testing.T) {
	s, _ := open(t)
	if ok, _ := s.AdminExists(ctx); ok {
		t.Fatal("administrateur présent sur une base neuve")
	}
	if _, _, err := s.AdminCredentials(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("AdminCredentials = %v", err)
	}
	if err := s.CreateAdmin(ctx, "alice", "hash1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAdmin(ctx, "bob", "hash2"); !errors.Is(err, ErrExists) {
		t.Errorf("deuxième administrateur : %v", err)
	}
	if u, h, _ := s.AdminCredentials(ctx); u != "alice" || h != "hash1" {
		t.Errorf("compte = %q, %q", u, h)
	}
}

func TestSessions(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	if err := s.CreateSession(ctx, "h-ok", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.CreateSession(ctx, "h-old", now.Add(-time.Minute))
	if ok, _ := s.SessionValid(ctx, "h-ok"); !ok {
		t.Error("session valide refusée")
	}
	if ok, _ := s.SessionValid(ctx, "h-old"); ok {
		t.Error("session expirée acceptée")
	}
	if ok, _ := s.SessionValid(ctx, "inconnue"); ok {
		t.Error("session inconnue acceptée")
	}
	s.PurgeSessions(ctx)
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n)
	if n != 1 {
		t.Errorf("%d sessions après purge, attendu 1", n)
	}
	s.DeleteSession(ctx, "h-ok")
	if ok, _ := s.SessionValid(ctx, "h-ok"); ok {
		t.Error("session supprimée encore valide")
	}
}

func TestHosts(t *testing.T) {
	s, _ := open(t)
	id, err := s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.99"}); !errors.Is(err, ErrExists) {
		t.Errorf("doublon : %v", err)
	}
	s.AddHostFull(ctx, Host{Domain: "a.example.com", Target: "http://192.0.2.1"})
	hosts, _ := s.ListHosts(ctx)
	if len(hosts) != 2 || hosts[0].Domain != "a.example.com" {
		t.Errorf("hôtes = %+v", hosts)
	}
	if err := s.SetHostDisabled(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.HostByID(ctx, id); !h.Disabled {
		t.Error("hôte non désactivé")
	}
	if err := s.DeleteHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHost(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("suppression d'un hôte absent : %v", err)
	}
	if _, err := s.HostByID(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("HostByID absent : %v", err)
	}
}

func TestSettingsAndAudit(t *testing.T) {
	s, _ := open(t)
	if v, _ := s.Setting(ctx, "public_ip"); v != "" {
		t.Errorf("réglage absent = %q", v)
	}
	s.SetSetting(ctx, "public_ip", "203.0.113.5")
	s.SetSetting(ctx, "public_ip", "203.0.113.6")
	if v, _ := s.Setting(ctx, "public_ip"); v != "203.0.113.6" {
		t.Errorf("réglage = %q", v)
	}
	s.Audit(ctx, "host.add", "wiki.example.com")
	s.Audit(ctx, "host.delete", "wiki.example.com")
	got, _ := s.RecentAudit(ctx, 10)
	if len(got) != 2 || got[0].Action != "host.delete" {
		t.Errorf("audit = %+v", got)
	}
}

func TestReopenKeepsDataAndNoBackupWhenUpToDate(t *testing.T) {
	s, path := open(t)
	s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21"})
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if h, _ := s2.ListHosts(ctx); len(h) != 1 {
		t.Errorf("hôtes après réouverture : %v", h)
	}
	matches, _ := filepath.Glob(path + ".avant-*")
	if len(matches) != 0 {
		t.Errorf("copie inutile créée : %v", matches)
	}
}

func TestMigrationBacksUpExistingDatabase(t *testing.T) {
	// Base existante à la version courante avec des données, mais code attendant plus récent.
	path := filepath.Join(t.TempDir(), "gatewyn.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21"})
	s.Close()

	saved := migrations
	defer func() { migrations = saved; Version = len(saved) }()
	migrations = append(append([]string{}, saved...), `ALTER TABLE hosts ADD COLUMN note TEXT NOT NULL DEFAULT ''`)
	Version = len(migrations)

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	matches, _ := filepath.Glob(path + ".avant-v" + strconv.Itoa(len(saved)) + "-*")
	if len(matches) != 1 {
		t.Fatalf("copie avant migration : %v", matches)
	}
	// La copie contient les données de l'ancienne version, sans la nouvelle colonne.
	bdb, err := sql.Open("sqlite", "file:"+matches[0]+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	var n int
	if err := bdb.QueryRow("SELECT COUNT(*) FROM hosts").Scan(&n); err != nil || n != 1 {
		t.Errorf("copie : %d hôtes, %v", n, err)
	}
	if _, err := bdb.Exec("SELECT note FROM hosts"); err == nil {
		t.Error("la copie contient déjà la nouvelle colonne")
	}
	// La base migrée a la colonne et ses données.
	var note string
	if err := s2.db.QueryRow("SELECT note FROM hosts").Scan(&note); err != nil {
		t.Errorf("migration non appliquée : %v", err)
	}
}

func TestFailedMigrationLeavesVersionUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gatewyn.db")
	s, _ := Open(path)
	s.Close()
	saved := migrations
	defer func() { migrations = saved; Version = len(saved) }()
	migrations = append(append([]string{}, saved...), `CREATE TABLE ok (a); SELECT FROM nonsense;`)
	Version = len(migrations)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "migration vers la version "+strconv.Itoa(len(saved)+1)) {
		t.Fatalf("erreur = %v", err)
	}
	migrations, Version = saved, len(saved)
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("base inutilisable après migration échouée : %v", err)
	}
	s2.Close()
}

func TestRefusesNewerDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gatewyn.db")
	db, _ := sql.Open("sqlite", path)
	db.Exec("PRAGMA user_version = 99")
	db.Close()
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "plus récente") {
		t.Errorf("erreur = %v", err)
	}
	if _, err := os.Stat(path + ".avant-v99"); err == nil {
		t.Error("copie créée pour une base trop récente")
	}
}

func TestHostKindsRoundTrip(t *testing.T) {
	s, _ := open(t)
	rid, err := s.AddHostFull(ctx, Host{Domain: "old.example.com", Kind: "redirect", Target: "https://new.example.org", Code: 301, PreservePath: true})
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostFull(ctx, Host{Domain: "gone.example.com", Kind: "404"})
	s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21"})
	h, _ := s.HostByID(ctx, rid)
	if h.Kind != "redirect" || h.Code != 301 || !h.PreservePath || h.Target != "https://new.example.org" {
		t.Errorf("redirection = %+v", h)
	}
	if err := s.UpdateHostFull(ctx, rid, Host{Domain: "old2.example.com", Target: "https://autre.example.org", Code: 302}); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.HostByID(ctx, rid); h.Domain != "old2.example.com" || h.Code != 302 || h.PreservePath || h.Kind != "redirect" {
		t.Errorf("après modification = %+v", h)
	}
	if _, err := s.AddHostFull(ctx, Host{Domain: "gone.example.com", Kind: "404"}); !errors.Is(err, ErrExists) {
		t.Errorf("doublon entre types : %v", err)
	}
}

func TestMigrationToKindsKeepsExistingHostsAsProxies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gatewyn.db")
	db, _ := sql.Open("sqlite", path)
	for _, m := range migrations[:2] {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec("INSERT INTO hosts (domain, target, disabled, created_at) VALUES ('a.example.com','http://192.0.2.1',0,1)")
	db.Exec("PRAGMA user_version = 2")
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hosts, _ := s.ListHosts(ctx)
	if len(hosts) != 1 || hosts[0].Kind != "proxy" || hosts[0].Code != 0 || hosts[0].PreservePath {
		t.Errorf("hôte migré = %+v", hosts)
	}
}

func TestMigrationDropsHistoryAndKeepsHosts(t *testing.T) {
	// Une base à l'ancienne version 3 (avec historique) perd la table d'historique et garde ses hôtes.
	path := filepath.Join(t.TempDir(), "gatewyn.db")
	db, _ := sql.Open("sqlite", path)
	for _, m := range migrations[:3] {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec("INSERT INTO hosts (domain, target, created_at) VALUES ('a.example.com','http://192.0.2.1',1)")
	db.Exec("PRAGMA user_version = 3")
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if hosts, _ := s.ListHosts(ctx); len(hosts) != 1 || hosts[0].Domain != "a.example.com" {
		t.Errorf("hôtes après migration : %+v", hosts)
	}
	if _, err := s.db.Exec("SELECT 1 FROM snapshots"); err == nil {
		t.Error("la table d'historique existe encore")
	}
	if matches, _ := filepath.Glob(path + ".avant-v3-*"); len(matches) != 1 {
		t.Errorf("copie de sécurité avant migration : %v", matches)
	}
}

func TestHostAliasesRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "gatewyn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Aliases: []string{"docs.example.com", "wiki.example.org"}, Target: "http://192.0.2.21"})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := s.HostByID(ctx, id)
	if strings.Join(h.Aliases, " ") != "docs.example.com wiki.example.org" {
		t.Errorf("alias : %v", h.Aliases)
	}
	h.Aliases = nil
	if err := s.UpdateHostFull(ctx, id, h); err != nil {
		t.Fatal(err)
	}
	if h, _ = s.HostByID(ctx, id); len(h.Aliases) != 0 {
		t.Errorf("après retrait : %v", h.Aliases)
	}
}

func TestHostLocationsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "gatewyn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	locs := []Location{{"/api", "http://192.0.2.5:3000", 0, false}, {"/admin", "https://192.0.2.6:8443", 3, true}, {"/open", "http://192.0.2.7:80", PublicAccess, false}, {"/vault", "", 4, false}}
	id, _ := s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21", Locations: locs})
	h, _ := s.HostByID(ctx, id)
	if len(h.Locations) != 4 || h.Locations[0] != locs[0] || h.Locations[1] != locs[1] || h.Locations[2] != locs[2] || h.Locations[3] != locs[3] {
		t.Errorf("chemins : %+v", h.Locations)
	}
	h.Locations = nil
	s.UpdateHostFull(ctx, id, h)
	if h, _ = s.HostByID(ctx, id); len(h.Locations) != 0 {
		t.Errorf("après retrait : %+v", h.Locations)
	}
}

func TestHostOptionsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "gatewyn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, _ := s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21", Compress: true, NoBuffering: true, FrameOptions: "SAMEORIGIN", NoIndex: true})
	h, _ := s.HostByID(ctx, id)
	if !h.Compress || !h.NoBuffering || h.FrameOptions != "SAMEORIGIN" || !h.NoIndex {
		t.Errorf("options : %+v", h)
	}
	h.Compress, h.NoBuffering, h.FrameOptions, h.NoIndex = false, false, "", false
	s.UpdateHostFull(ctx, id, h)
	if h, _ = s.HostByID(ctx, id); h.Compress || h.NoBuffering || h.FrameOptions != "" || h.NoIndex {
		t.Errorf("après retrait : %+v", h)
	}
}

func TestHostWAFRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "gatewyn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, _ := s.AddHostFull(ctx, Host{Domain: "wiki.example.com", Target: "http://192.0.2.21", WAF: true})
	h, _ := s.HostByID(ctx, id)
	if !h.WAF {
		t.Errorf("WAF non relu : %+v", h)
	}
	h.WAF = false
	s.UpdateHostFull(ctx, id, h)
	if h, _ = s.HostByID(ctx, id); h.WAF {
		t.Errorf("WAF non retiré : %+v", h)
	}
}
