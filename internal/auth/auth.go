// Package auth gère l'identifiant et le mot de passe administrateur (argon2id), les jetons de
// session et la limitation des tentatives de connexion. Aucun identifiant par
// défaut : le compte est créé au premier lancement.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Paramètres argon2id (recommandation OWASP : 19 Mio, 2 itérations, 1 voie).
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLength est la longueur minimale d'un mot de passe, en caractères.
const MinPasswordLength = 12

// maxPasswordLength borne le travail demandé au serveur par une requête.
const maxPasswordLength = 256

// NormalizeUsername met un identifiant sous sa forme stockée (sans espaces autour, en minuscules).
func NormalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

// ValidateUsername vérifie qu'un identifiant est acceptable : 3 à 32 caractères,
// lettres, chiffres, point, tiret et tiret bas. Il s'attend à une valeur déjà normalisée.
func ValidateUsername(u string) error {
	if n := utf8.RuneCountInString(u); n < 3 || n > 32 {
		return errors.New("l'identifiant doit faire entre 3 et 32 caractères")
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return errors.New("l'identifiant ne peut contenir que des lettres sans accent, des chiffres, des points, des tirets et des tirets bas")
		}
	}
	return nil
}

// ValidatePassword vérifie qu'un nouveau mot de passe est acceptable.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < MinPasswordLength:
		return fmt.Errorf("le mot de passe doit faire au moins %d caractères (une phrase courte convient très bien)", MinPasswordLength)
	case n > maxPasswordLength:
		return fmt.Errorf("le mot de passe est trop long (%d caractères au plus)", maxPasswordLength)
	case strings.TrimSpace(pw) == "":
		return errors.New("le mot de passe ne peut pas être vide")
	}
	return nil
}

// HashPassword renvoie l'empreinte argon2id d'un mot de passe, avec son sel et ses paramètres.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword compare un mot de passe à une empreinte, en temps constant.
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var version int
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	// Borne les paramètres lus dans la base pour ne pas se laisser imposer un calcul énorme.
	if m == 0 || m > 1<<20 || t == 0 || t > 10 || p == 0 || p > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewToken crée un jeton de session aléatoire (256 bits) et son empreinte.
// Seule l'empreinte est stockée : une fuite de la base ne donne pas de session.
func NewToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken renvoie l'empreinte stockée d'un jeton.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Limiter refuse les connexions d'une même origine après trop d'échecs.
type Limiter struct {
	Max    int           // échecs permis dans la fenêtre
	Window time.Duration // durée de la fenêtre
	Now    func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewLimiter crée un limiteur : max échecs par fenêtre et par clé.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{Max: max, Window: window, Now: time.Now, failures: map[string][]time.Time{}}
}

// Allowed indique si la clé (par exemple une adresse IP) peut encore essayer.
func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < l.Max
}

// Fail enregistre un échec.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.recent(key), l.Now())
}

// Reset oublie les échecs d'une clé (après une connexion réussie).
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// RetryAfter renvoie le délai avant la prochaine tentative permise.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.recent(key)
	if len(r) < l.Max {
		return 0
	}
	return r[0].Add(l.Window).Sub(l.Now())
}

// recent garde et renvoie les échecs de la fenêtre. À appeler verrou pris.
func (l *Limiter) recent(key string) []time.Time {
	cutoff := l.Now().Add(-l.Window)
	var keep []time.Time
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = keep
	}
	return keep
}
