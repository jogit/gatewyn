package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jogit/gatewyn/internal/store"
)

// newInstall crée un dossier de données avec une base contenant un compte et une clé.
func newInstall(t *testing.T, user, key string) (dbPath, keyPath string, st *store.Store) {
	t.Helper()
	dir := t.TempDir()
	dbPath, keyPath = filepath.Join(dir, "gatewyn.db"), filepath.Join(dir, "secret.key")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.CreateAdmin(context.Background(), user, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte(key), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return dbPath, keyPath, st
}

func makeBackup(t *testing.T, st *store.Store, keyPath string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(context.Background(), &buf, st, keyPath); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tarGz fabrique une archive à partir de fichiers nommés.
func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestBackupThenRestoreOnAnotherInstall(t *testing.T) {
	_, srcKey, src := newInstall(t, "alice", "a")
	archive := makeBackup(t, src, srcKey)

	// Une autre installation, avec son propre compte et sa propre clé.
	dstDB, dstKey, dst := newInstall(t, "bob", "b")
	dst.Close()
	if err := Stage(bytes.NewReader(archive), dstDB); err != nil {
		t.Fatal(err)
	}
	// Rien n'est remplacé avant le redémarrage.
	if b, _ := os.ReadFile(dstKey); !bytes.Equal(b, bytes.Repeat([]byte("b"), 32)) {
		t.Fatal("la clé a été remplacée avant le redémarrage")
	}
	applied, err := Apply(dstDB, dstKey, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
	if err != nil || !applied {
		t.Fatalf("Apply = %v, %v", applied, err)
	}
	if b, _ := os.ReadFile(dstKey); !bytes.Equal(b, bytes.Repeat([]byte("a"), 32)) {
		t.Fatal("la clé de la sauvegarde n'est pas installée")
	}
	st, err := store.Open(dstDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if user, _, err := st.AdminCredentials(context.Background()); err != nil || user != "alice" {
		t.Fatalf("compte restauré = %q, %v ; attendu alice", user, err)
	}
	// L'ancienne base et l'ancienne clé restent à côté.
	for _, p := range []string{dstDB, dstKey} {
		if _, err := os.Stat(p + ".avant-restauration-20261111T100000Z"); err != nil {
			t.Errorf("ancien fichier non conservé : %v", err)
		}
	}
	// Une deuxième fois, il n'y a plus rien à installer.
	if applied, err := Apply(dstDB, dstKey, time.Now()); applied || err != nil {
		t.Fatalf("second Apply = %v, %v", applied, err)
	}
}

func TestStageRefusesBadArchives(t *testing.T) {
	_, key, st := newInstall(t, "alice", "a")
	good := makeBackup(t, st, key)
	dbPath, _, other := newInstall(t, "bob", "b")
	other.Close()
	dbData, _ := os.ReadFile(dbPath)

	cases := map[string][]byte{
		"pas une archive":        []byte("hello"),
		"sans base":              tarGz(t, map[string][]byte{keyName: bytes.Repeat([]byte("a"), 32)}),
		"sans clé":               tarGz(t, map[string][]byte{dbName: dbData}),
		"clé de mauvaise taille": tarGz(t, map[string][]byte{dbName: dbData, keyName: []byte("court")}),
		"base abîmée":            tarGz(t, map[string][]byte{dbName: []byte("pas du sqlite"), keyName: bytes.Repeat([]byte("a"), 32)}),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			target, targetKey, tst := newInstall(t, "carol", "c")
			tst.Close()
			err := Stage(bytes.NewReader(archive), target)
			var inv *ErrInvalid
			if !errors.As(err, &inv) {
				t.Fatalf("erreur = %v ; attendu ErrInvalid", err)
			}
			if applied, _ := Apply(target, targetKey, time.Now()); applied {
				t.Fatal("une archive refusée ne doit rien déposer")
			}
		})
	}
	// Contrôle : l'archive saine passe.
	target, _, tst := newInstall(t, "carol", "c")
	tst.Close()
	if err := Stage(bytes.NewReader(good), target); err != nil {
		t.Fatal(err)
	}
}

func TestStageRefusesNewerDatabase(t *testing.T) {
	dbPath, _, st := newInstall(t, "alice", "a")
	// Une base dont la version est plus récente que ce Gatewyn.
	newer := filepath.Join(t.TempDir(), "newer.db")
	if err := st.CopyTo(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := setVersion(newer, store.Version+1); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(newer)
	archive := tarGz(t, map[string][]byte{dbName: data, keyName: bytes.Repeat([]byte("a"), 32)})
	err := Stage(bytes.NewReader(archive), dbPath)
	var inv *ErrInvalid
	if !errors.As(err, &inv) {
		t.Fatalf("erreur = %v ; attendu ErrInvalid", err)
	}
}

func setVersion(path string, v int) error {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v))
	return err
}

func TestAutomaticCopiesAreListedAndPruned(t *testing.T) {
	dbPath, key, st := newInstall(t, "alice", "a")
	dir := AutoDir(dbPath)
	now := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	var names []string
	for _, age := range []int{10, 5, 1, 0} {
		name, err := CreateCopy(context.Background(), dir, st, key, now.AddDate(0, 0, -age))
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	// Des fichiers étrangers ou à moitié écrits ne sont jamais comptés ni supprimés.
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, names[0]+".tmp"), []byte("x"), 0o600)

	list := List(dir)
	if len(list) != 4 || list[0].Name != names[3] || list[0].Size == 0 {
		t.Fatalf("liste = %+v", list)
	}
	if n := Prune(dir, 7, now); n != 1 {
		t.Fatalf("supprimées = %d, attendu 1 (celle de 10 jours)", n)
	}
	if got := List(dir); len(got) != 3 || got[2].Name != names[1] {
		t.Fatalf("après nettoyage : %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("un fichier étranger a été supprimé")
	}
	// Une copie automatique se restaure comme un téléchargement.
	data, _ := os.ReadFile(filepath.Join(dir, names[3]))
	other, _, ost := newInstall(t, "bob", "b")
	ost.Close()
	if err := Stage(bytes.NewReader(data), other); err != nil {
		t.Fatal(err)
	}
}

func TestCopyNames(t *testing.T) {
	good := CopyName(time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC))
	if good != "gatewyn-20261111-030000.tar.gz" || !ValidCopyName(good) {
		t.Fatalf("nom = %q", good)
	}
	for _, bad := range []string{"", "../gatewyn-20261111-030000.tar.gz", "gatewyn-20261111-030000.tar.gz.tmp", "gatewyn-x.tar.gz", "secret.key", "a/gatewyn-20261111-030000.tar.gz"} {
		if ValidCopyName(bad) {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestDue(t *testing.T) {
	paris := time.FixedZone("CET", 3600)
	at := func(day, h, min int) time.Time { return time.Date(2026, 11, day, h, min, 0, 0, paris) }
	cases := []struct {
		name    string
		last    time.Time
		hasLast bool
		now     time.Time
		want    bool
	}{
		{"aucune copie", time.Time{}, false, at(11, 12, 0), true},
		{"avant l'heure, copie de la veille faite", at(11, 3, 5), true, at(11, 2, 0), false},
		{"avant l'heure, copie de la veille manquée", at(9, 3, 5), true, at(11, 2, 0), true},
		{"à l'heure, pas encore faite aujourd'hui", at(10, 3, 5), true, at(11, 3, 0), true},
		{"déjà faite aujourd'hui", at(11, 3, 1), true, at(11, 18, 0), false},
		{"faite juste avant l'heure prévue", at(11, 2, 59), true, at(11, 3, 0), true},
		{"rattrapage au démarrage dans la journée", at(10, 3, 1), true, at(11, 14, 0), true},
	}
	for _, c := range cases {
		if got := Due(c.last, c.hasLast, c.now, 3); got != c.want {
			t.Errorf("%s : %v, attendu %v", c.name, got, c.want)
		}
	}
}
