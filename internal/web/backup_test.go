package web

import (
	"bytes"
	"context"
	"github.com/jogit/gatewyn/internal/backup"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (e *env) upload(path, field, name string, data []byte) (*http.Response, string) {
	e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile(field, name)
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest("POST", e.ts.URL+path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestBackupDownloadAndRestore(t *testing.T) {
	e := newEnv(t)
	e.setup()
	dir := t.TempDir()
	restarts := 0
	e.srv.cfg.DBPath, e.srv.cfg.KeyFile = filepath.Join(dir, "g.db"), filepath.Join(dir, "secret.key")
	e.srv.cfg.Restart = func() { restarts++ }
	if err := os.WriteFile(e.srv.cfg.KeyFile, bytes.Repeat([]byte("k"), 32), 0o600); err != nil {
		t.Fatal(err)
	}

	// « Sauvegarder maintenant » crée une copie, qu'on télécharge ensuite depuis la liste.
	if resp, _ := e.do("POST", "/settings/backup", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sauvegarde : %d", resp.StatusCode)
	}
	copies := backup.List(backup.AutoDir(e.srv.cfg.DBPath))
	if len(copies) != 1 {
		t.Fatalf("%d copie(s), attendu 1", len(copies))
	}
	resp, body := e.do("GET", "/settings/backup/"+copies[0].Name, nil)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("téléchargement : %d %v", resp.StatusCode, resp.Header)
	}
	archive := []byte(body)

	if resp, body := e.upload("/settings/restore", "archive", "x.tar.gz", []byte("pas une archive")); resp.StatusCode != 422 || !strings.Contains(body, "pas une sauvegarde") || restarts != 0 {
		t.Fatalf("archive refusée : %d, %d redémarrage(s)", resp.StatusCode, restarts)
	}
	if resp, body := e.upload("/settings/restore", "archive", "g.tar.gz", archive); resp.StatusCode != 200 || !strings.Contains(body, "redémarre") || restarts != 1 {
		t.Fatalf("restauration : %d, %d redémarrage(s)", resp.StatusCode, restarts)
	}
	if _, err := os.Stat(filepath.Join(dir, "restore", "gatewyn.db")); err != nil {
		t.Fatalf("archive non déposée : %v", err)
	}
}

func TestBackupNeedsLoginAndConfiguration(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if resp, _ := e.do("POST", "/settings/backup", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("sans chemins configurés : %d, attendu 404", resp.StatusCode)
	}
	e.srv.cfg.DBPath, e.srv.cfg.KeyFile, e.srv.cfg.Restart = "x", "y", func() {}
	e.client.Jar = nil
	if resp, _ := e.do("POST", "/settings/backup", nil); resp.StatusCode == 200 {
		t.Fatal("sauvegarde téléchargeable sans session")
	}
}

func TestAutomaticBackupSettingsAndDownload(t *testing.T) {
	e := newEnv(t)
	e.setup()
	dir := t.TempDir()
	e.srv.cfg.DBPath, e.srv.cfg.KeyFile, e.srv.cfg.Restart = filepath.Join(dir, "g.db"), filepath.Join(dir, "secret.key"), func() {}
	os.WriteFile(e.srv.cfg.KeyFile, bytes.Repeat([]byte("k"), 32), 0o600)

	// Par défaut : activé, 7 jours.
	if got := e.srv.backupDays(context.Background()); got != 7 {
		t.Fatalf("défaut = %d", got)
	}
	if resp, _ := e.do("POST", "/settings/backup/auto", url.Values{"auto": {"1"}, "days": {"14"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("enregistrement : %d", resp.StatusCode)
	}
	if got := e.srv.backupDays(context.Background()); got != 14 {
		t.Fatalf("durée = %d, attendu 14", got)
	}
	// L'heure : 3 h par défaut, choisie entre 0 et 23, sinon retour au défaut.
	if got := e.srv.backupHour(context.Background()); got != 3 {
		t.Fatalf("heure par défaut = %d", got)
	}
	e.do("POST", "/settings/backup/auto", url.Values{"auto": {"1"}, "days": {"14"}, "hour": {"22"}})
	if got := e.srv.backupHour(context.Background()); got != 22 {
		t.Fatalf("heure = %d, attendu 22", got)
	}
	e.do("POST", "/settings/backup/auto", url.Values{"auto": {"1"}, "days": {"14"}, "hour": {"25"}})
	if got := e.srv.backupHour(context.Background()); got != 3 {
		t.Fatalf("heure invalide = %d, attendu 3", got)
	}
	// Une durée hors liste retombe sur le défaut ; sans la case, c'est désactivé.
	e.do("POST", "/settings/backup/auto", url.Values{"auto": {"1"}, "days": {"9999"}})
	if got := e.srv.backupDays(context.Background()); got != 7 {
		t.Fatalf("durée invalide = %d, attendu 7", got)
	}
	e.do("POST", "/settings/backup/auto", url.Values{"days": {"14"}})
	if got := e.srv.backupDays(context.Background()); got != 0 {
		t.Fatalf("désactivée = %d, attendu 0", got)
	}

	// Une copie s'affiche et se télécharge ; aucun autre nom n'est accepté.
	name, err := backup.CreateCopy(context.Background(), backup.AutoDir(e.srv.cfg.DBPath), e.store, e.srv.cfg.KeyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, body := e.do("GET", "/settings", nil); !strings.Contains(body, "/settings/backup/"+name) {
		t.Fatal("la copie n'est pas listée dans Réglages")
	}
	if resp, body := e.do("GET", "/settings/backup/"+name, nil); resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("téléchargement de la copie : %d", resp.StatusCode)
	}
	for _, bad := range []string{"secret.key", "..%2Fg.db", "gatewyn-20200101-000000.tar.gz"} {
		if resp, _ := e.do("GET", "/settings/backup/"+bad, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%q : %d, attendu 404", bad, resp.StatusCode)
		}
	}
}

func TestBackupListFoldsOldCopiesAndRestoreAsksConfirmation(t *testing.T) {
	e := newEnv(t)
	e.setup()
	dir := t.TempDir()
	e.srv.cfg.DBPath, e.srv.cfg.KeyFile, e.srv.cfg.Restart = filepath.Join(dir, "g.db"), filepath.Join(dir, "secret.key"), func() {}
	os.WriteFile(e.srv.cfg.KeyFile, bytes.Repeat([]byte("k"), 32), 0o600)
	now := time.Now()
	for i := 0; i < 8; i++ {
		if _, err := backup.CreateCopy(context.Background(), backup.AutoDir(e.srv.cfg.DBPath), e.store, e.srv.cfg.KeyFile, now.AddDate(0, 0, -i)); err != nil {
			t.Fatal(err)
		}
	}
	_, body := e.do("GET", "/settings", nil)
	if strings.Count(body, `class="copies"`) != 2 || !strings.Contains(body, "3 copies plus anciennes") {
		t.Fatal("5 copies visibles et 3 repliées attendues")
	}
	if !strings.Contains(body, `data-confirm="Restaurer cette sauvegarde ?`) {
		t.Fatal("la restauration doit demander confirmation")
	}
}
