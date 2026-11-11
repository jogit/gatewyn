package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/jogit/gatewyn/internal/backup"
)

const maxRestoreBytes = 300 << 20 // l'archive complète (la base seule est limitée à 256 Mo)

// backupAvailable : la sauvegarde a besoin du chemin de la base et de celui de la clé.
func (s *Server) backupAvailable() bool {
	return s.cfg.DBPath != "" && s.cfg.KeyFile != "" && s.cfg.Restart != nil
}

// backupNow crée tout de suite une copie, qui apparaît dans la liste de Réglages.
func (s *Server) backupNow(w http.ResponseWriter, r *http.Request) {
	if !s.backupAvailable() {
		http.NotFound(w, r)
		return
	}
	if _, err := backup.CreateCopy(r.Context(), backup.AutoDir(s.cfg.DBPath), s.cfg.Store, s.cfg.KeyFile, s.cfg.Now()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), "backup.create", fmt.Sprintf("sauvegarde créée, origine %s", clientIP(r)))
	http.Redirect(w, r, "/settings?backupnow=1#backup", http.StatusSeeOther)
}

// restoreBackup dépose l'archive envoyée, puis fait redémarrer Gatewyn : elle est installée au démarrage.
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupAvailable() {
		http.NotFound(w, r)
		return
	}
	again := func(status int, msg string) {
		p := s.settingsData(r)
		p.BackupError = msg
		w.WriteHeader(status)
		s.render(w, "settings", p)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRestoreBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		again(http.StatusBadRequest, "Choisissez le fichier de sauvegarde à restaurer.")
		return
	}
	for {
		part, err := mr.NextPart()
		if err != nil {
			again(http.StatusBadRequest, "Choisissez le fichier de sauvegarde à restaurer.")
			return
		}
		if part.FormName() != "archive" || part.FileName() == "" {
			continue
		}
		err = backup.Stage(part, s.cfg.DBPath)
		var inv *backup.ErrInvalid
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &inv):
			again(http.StatusUnprocessableEntity, inv.Msg)
		case errors.As(err, &tooBig), errors.Is(err, io.ErrUnexpectedEOF):
			again(http.StatusRequestEntityTooLarge, "La sauvegarde est trop volumineuse.")
		case err != nil:
			s.fail(w, r, err)
		default:
			s.audit(r.Context(), "backup.restore", fmt.Sprintf("sauvegarde déposée, installée au redémarrage, origine %s", clientIP(r)))
			p := s.settingsData(r)
			p.Flash = "La sauvegarde est vérifiée. Gatewyn redémarre pour l'installer : reconnectez-vous dans quelques secondes avec le compte de la sauvegarde."
			s.render(w, "settings", p)
			s.cfg.Restart()
		}
		return
	}
}

const (
	settingBackupDays = "backup.auto_days"
	settingBackupHour = "backup.auto_hour"
	defaultBackupDays = 7
	defaultBackupHour = 3
	visibleCopies     = 5 // copies montrées d'emblée ; les plus anciennes sont repliées
)

// backupHours : les heures proposées (0 à 23).
var backupHours = func() []int {
	h := make([]int, 24)
	for i := range h {
		h[i] = i
	}
	return h
}()

// backupDaysChoices : durées de conservation proposées, en jours.
var backupDaysChoices = []int{3, 7, 14, 30}

// backupDays renvoie la durée de conservation des copies automatiques ; 0 : copies désactivées.
func (s *Server) backupDays(ctx context.Context) int {
	v, err := s.cfg.Store.Setting(ctx, settingBackupDays)
	if err != nil || v == "" {
		return defaultBackupDays
	}
	if d, err := strconv.Atoi(v); err == nil && (d == 0 || slices.Contains(backupDaysChoices, d)) {
		return d
	}
	return defaultBackupDays
}

// backupHour renvoie l'heure (0 à 23, heure du serveur) de la copie automatique.
func (s *Server) backupHour(ctx context.Context) int {
	if h, err := strconv.Atoi(s.settingOrEmpty(ctx, settingBackupHour)); err == nil && h >= 0 && h <= 23 {
		return h
	}
	return defaultBackupHour
}

func (s *Server) settingOrEmpty(ctx context.Context, key string) string {
	v, _ := s.cfg.Store.Setting(ctx, key)
	return v
}

// copyView est une ligne de la liste des copies automatiques.
type copyView struct{ Name, When, Size string }

// fillBackup prépare la section Sauvegarde de la page Réglages.
func (s *Server) fillBackup(ctx context.Context, p *page) {
	p.BackupAvail = s.backupAvailable()
	if !p.BackupAvail {
		return
	}
	days := s.backupDays(ctx)
	p.BackupOn, p.BackupDays, p.BackupChoices = days > 0, days, backupDaysChoices
	p.BackupHour = s.backupHour(ctx)
	p.BackupHours = backupHours
	if days == 0 {
		p.BackupDays = defaultBackupDays
	}
	defer func() {
		switch n := len(p.BackupMore); n {
		case 0:
		case 1:
			p.BackupMoreLabel = "1 copie plus ancienne"
		default:
			p.BackupMoreLabel = fmt.Sprintf("%d copies plus anciennes", n)
		}
	}()
	for i, c := range backup.List(backup.AutoDir(s.cfg.DBPath)) {
		v := copyView{c.Name, c.At.Local().Format("02/01/2006 15:04"), humanSize(c.Size)}
		if i < visibleCopies {
			p.BackupCopies = append(p.BackupCopies, v)
		} else {
			p.BackupMore = append(p.BackupMore, v)
		}
	}
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f Mo", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d Ko", n>>10)
	}
	return fmt.Sprintf("%d o", n)
}

// saveBackupSettings enregistre l'activation et la durée de conservation des copies automatiques.
func (s *Server) saveBackupSettings(w http.ResponseWriter, r *http.Request) {
	if !s.backupAvailable() {
		http.NotFound(w, r)
		return
	}
	if !s.parseForm(w, r) {
		return
	}
	days := 0
	if r.PostFormValue("auto") == "1" {
		days = defaultBackupDays
		if d, err := strconv.Atoi(r.PostFormValue("days")); err == nil && slices.Contains(backupDaysChoices, d) {
			days = d
		}
	}
	hour := defaultBackupHour
	if h, err := strconv.Atoi(r.PostFormValue("hour")); err == nil && h >= 0 && h <= 23 {
		hour = h
	}
	for key, v := range map[string]int{settingBackupDays: days, settingBackupHour: hour} {
		if err := s.cfg.Store.SetSetting(r.Context(), key, strconv.Itoa(v)); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if days > 0 {
		backup.Prune(backup.AutoDir(s.cfg.DBPath), days, s.cfg.Now())
	}
	s.audit(r.Context(), "backup.settings", fmt.Sprintf("sauvegarde automatique : %d jours (0 : désactivée), à %d h", days, hour))
	http.Redirect(w, r, "/settings?backup=1#backup", http.StatusSeeOther)
}

// downloadCopy envoie une copie automatique. Le nom est vérifié : il ne peut désigner que ces fichiers.
func (s *Server) downloadCopy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.backupAvailable() || !backup.ValidCopyName(name) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(backup.AutoDir(s.cfg.DBPath), name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	s.audit(r.Context(), "backup.export", fmt.Sprintf("sauvegarde téléchargée, origine %s", clientIP(r)))
	h := w.Header()
	h.Set("Content-Type", "application/gzip")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

// RunAutoBackups fait une copie par jour tant que la fonction est activée, et supprime les copies trop
// anciennes. Bloque jusqu'à l'arrêt de ctx.
func (s *Server) RunAutoBackups(ctx context.Context) {
	if !s.backupAvailable() {
		return
	}
	dir := backup.AutoDir(s.cfg.DBPath)
	tick := time.NewTimer(time.Minute) // laisse le démarrage se terminer
	defer tick.Stop()
	pruned := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		tick.Reset(time.Minute)
		days := s.backupDays(ctx)
		if days == 0 {
			continue
		}
		now := s.cfg.Now()
		list := backup.List(dir)
		if len(list) == 0 || backup.Due(list[0].At, true, now, s.backupHour(ctx)) {
			if _, err := backup.CreateCopy(ctx, dir, s.cfg.Store, s.cfg.KeyFile, now); err != nil {
				s.cfg.Logger.Error("automatic backup", "error", err)
			}
		}
		if now.Sub(pruned) >= time.Hour {
			backup.Prune(dir, days, now)
			pruned = now
		}
	}
}
