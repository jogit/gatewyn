// Package backup crée et restaure une sauvegarde de Gatewyn : une archive tar.gz qui contient la
// base SQLite et la clé de chiffrement des identifiants DNS (l'une ne sert à rien sans l'autre).
//
// La restauration ne remplace rien pendant que Gatewyn tourne : Stage vérifie l'archive et la
// dépose à côté de la base, Apply l'installe au démarrage suivant, avant l'ouverture de la base.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pilote SQLite, pour lire la version de la base déposée

	"github.com/jogit/gatewyn/internal/store"
)

const (
	dbName   = "gatewyn.db"
	keyName  = "secret.key"
	stageDir = "restore"
	maxDB    = 256 << 20 // taille maximale de la base dans l'archive
)

// ErrInvalid : l'archive n'est pas une sauvegarde de Gatewyn utilisable. Son message est affiché tel quel.
type ErrInvalid struct{ Msg string }

func (e *ErrInvalid) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ErrInvalid{fmt.Sprintf(format, a...)} }

// Write écrit la sauvegarde : une copie cohérente de la base et la clé.
func Write(ctx context.Context, w io.Writer, st *store.Store, keyFile string) error {
	tmp, err := os.MkdirTemp("", "gatewyn-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	dbCopy := filepath.Join(tmp, dbName)
	if err := st.CopyTo(ctx, dbCopy); err != nil {
		return fmt.Errorf("copying the database: %w", err)
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, path string }{{dbName, dbCopy}, {keyName, keyFile}} {
		if err := addFile(tw, f.name, f.path); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// Stage vérifie l'archive lue dans r et la dépose dans le dossier de la base (dbPath), prête à être
// installée par Apply au prochain démarrage. Une archive refusée ne change rien.
func Stage(r io.Reader, dbPath string) error {
	dir := filepath.Dir(dbPath)
	tmp := filepath.Join(dir, stageDir+".tmp")
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	gz, err := gzip.NewReader(r)
	if err != nil {
		return invalid("Ce fichier n'est pas une sauvegarde de Gatewyn.")
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return invalid("Ce fichier n'est pas une sauvegarde de Gatewyn.")
		}
		if hdr.Name != dbName && hdr.Name != keyName {
			continue // les autres entrées sont ignorées : rien d'autre n'est jamais écrit
		}
		if err := extract(filepath.Join(tmp, hdr.Name), tr); err != nil {
			return err
		}
	}

	if _, err := os.Stat(filepath.Join(tmp, dbName)); err != nil {
		return invalid("La sauvegarde ne contient pas la base de données.")
	}
	key, err := os.ReadFile(filepath.Join(tmp, keyName))
	if err != nil || len(key) != 32 {
		return invalid("La sauvegarde ne contient pas une clé de chiffrement valide.")
	}
	if err := checkDB(filepath.Join(tmp, dbName)); err != nil {
		return err
	}

	final := filepath.Join(dir, stageDir)
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func extract(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxDB+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return invalid("Ce fichier n'est pas une sauvegarde de Gatewyn.")
	}
	if n > maxDB {
		return invalid("La sauvegarde est trop volumineuse.")
	}
	return nil
}

// checkDB vérifie que le fichier est une base saine, d'une version que ce Gatewyn sait ouvrir.
func checkDB(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		return invalid("La base de données de la sauvegarde est abîmée.")
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version < 1 {
		return invalid("Ce fichier n'est pas une sauvegarde de Gatewyn.")
	}
	if version > store.Version {
		return invalid("Cette sauvegarde vient d'une version plus récente de Gatewyn : mettez Gatewyn à jour avant de la restaurer.")
	}
	return nil
}

// Apply installe la sauvegarde déposée par Stage, s'il y en a une. À appeler au démarrage, avant
// d'ouvrir la base. La base et la clé remplacées restent à côté, suffixées .avant-restauration-<date>.
func Apply(dbPath, keyFile string, now time.Time) (bool, error) {
	staged := filepath.Join(filepath.Dir(dbPath), stageDir)
	if _, err := os.Stat(staged); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	suffix := ".avant-restauration-" + now.UTC().Format("20060102T150405Z")
	for _, old := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", keyFile} {
		if err := os.Rename(old, old+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	if err := os.Rename(filepath.Join(staged, dbName), dbPath); err != nil {
		return false, err
	}
	if err := os.Rename(filepath.Join(staged, keyName), keyFile); err != nil {
		return false, err
	}
	return true, os.RemoveAll(staged)
}

// --- copies automatiques ---

const autoPrefix, autoSuffix, autoLayout = "gatewyn-", ".tar.gz", "20060102-150405"

// Copy est une sauvegarde automatique conservée sur le disque.
type Copy struct {
	Name string
	At   time.Time
	Size int64
}

// AutoDir : dossier des copies automatiques, à côté de la base.
func AutoDir(dbPath string) string { return filepath.Join(filepath.Dir(dbPath), "backups") }

// CopyName : nom d'une copie automatique faite à l'instant at.
func CopyName(at time.Time) string { return autoPrefix + at.UTC().Format(autoLayout) + autoSuffix }

// copyTime lit la date dans le nom d'une copie ; ok est faux si ce n'est pas le nom d'une copie.
func copyTime(name string) (time.Time, bool) {
	if len(name) <= len(autoPrefix)+len(autoSuffix) || name[:len(autoPrefix)] != autoPrefix || name[len(name)-len(autoSuffix):] != autoSuffix {
		return time.Time{}, false
	}
	t, err := time.Parse(autoLayout, name[len(autoPrefix):len(name)-len(autoSuffix)])
	return t, err == nil
}

// ValidCopyName : le nom est celui d'une copie automatique (jamais un chemin).
func ValidCopyName(name string) bool { _, ok := copyTime(name); return ok }

// CreateCopy écrit une sauvegarde dans dir (créé au besoin) et renvoie son nom.
func CreateCopy(ctx context.Context, dir string, st *store.Store, keyFile string, now time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := CopyName(now)
	tmp := filepath.Join(dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	err = Write(ctx, f, st, keyFile)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return name, nil
}

// List renvoie les copies de dir, la plus récente d'abord.
func List(dir string) []Copy {
	entries, _ := os.ReadDir(dir)
	var out []Copy
	for i := len(entries) - 1; i >= 0; i-- { // les noms sont datés : l'ordre alphabétique est chronologique
		at, ok := copyTime(entries[i].Name())
		info, err := entries[i].Info()
		if ok && err == nil {
			out = append(out, Copy{entries[i].Name(), at, info.Size()})
		}
	}
	return out
}

// Prune supprime les copies de plus de days jours et renvoie leur nombre.
func Prune(dir string, days int, now time.Time) int {
	n := 0
	for _, c := range List(dir) {
		if now.Sub(c.At) > time.Duration(days)*24*time.Hour && os.Remove(filepath.Join(dir, c.Name)) == nil {
			n++
		}
	}
	return n
}

// Due indique si la copie du jour doit être faite : l'heure prévue (hour, dans le fuseau de now) est
// passée et aucune copie n'a été faite depuis. Au démarrage, une heure manquée est donc rattrapée.
func Due(last time.Time, hasLast bool, now time.Time, hour int) bool {
	y, m, d := now.Date()
	scheduled := time.Date(y, m, d, hour, 0, 0, 0, now.Location())
	if now.Before(scheduled) {
		scheduled = scheduled.AddDate(0, 0, -1)
	}
	return !hasLast || last.Before(scheduled)
}
