package auth

import (
	"strings"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("une phrase de passe correcte")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "argon2id$") || strings.Contains(h, "une phrase") {
		t.Errorf("empreinte inattendue : %s", h)
	}
	if !VerifyPassword("une phrase de passe correcte", h) {
		t.Error("bon mot de passe refusé")
	}
	for _, bad := range []string{"", "une phrase de passe correcte ", "Une phrase de passe correcte", "autre chose"} {
		if VerifyPassword(bad, h) {
			t.Errorf("mauvais mot de passe %q accepté", bad)
		}
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("même mot de passe 123")
	b, _ := HashPassword("même mot de passe 123")
	if a == b {
		t.Error("deux empreintes identiques : pas de sel")
	}
}

func TestVerifyRejectsMalformedAndHostileHashes(t *testing.T) {
	good, _ := HashPassword("une phrase de passe correcte")
	parts := strings.Split(good, "$")
	hostile := []string{
		"", "pas une empreinte", "argon2id$v=19$m=1,t=1,p=1$x", "bcrypt$v=19$m=1,t=1,p=1$AAAA$AAAA",
		"argon2id$v=19$m=4294967295,t=1,p=1$" + parts[3] + "$" + parts[4],  // mémoire énorme
		"argon2id$v=19$m=19456,t=1000000,p=1$" + parts[3] + "$" + parts[4], // temps énorme
		"argon2id$v=19$m=19456,t=2,p=0$" + parts[3] + "$" + parts[4],
		"argon2id$v=19$m=19456,t=2,p=1$!!!$" + parts[4],
		"argon2id$v=19$m=19456,t=2,p=1$" + parts[3] + "$",
		"argon2id$v=18$m=19456,t=2,p=1$" + parts[3] + "$" + parts[4],
	}
	for _, h := range hostile {
		if VerifyPassword("une phrase de passe correcte", h) {
			t.Errorf("empreinte invalide acceptée : %q", h)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	ok := []string{"douze caractères!", "une phrase de passe correcte", strings.Repeat("é", 12)}
	for _, pw := range ok {
		if err := ValidatePassword(pw); err != nil {
			t.Errorf("%q refusé : %v", pw, err)
		}
	}
	bad := map[string]string{
		"":                       "au moins",
		"court":                  "au moins",
		"12345678901":            "au moins",
		"            ":           "vide",
		strings.Repeat("a", 300): "trop long",
	}
	for pw, want := range bad {
		if err := ValidatePassword(pw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q : erreur = %v, attendu %q", pw, err, want)
		}
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 40 || HashToken(tok) != hash || strings.Contains(hash, tok) {
		t.Errorf("jeton %q, empreinte %q", tok, hash)
	}
	tok2, hash2, _ := NewToken()
	if tok == tok2 || hash == hash2 {
		t.Error("jetons identiques")
	}
	if HashToken("x") == HashToken("y") {
		t.Error("collision d'empreintes")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewLimiter(3, 10*time.Minute)
	l.Now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.Allowed("192.0.2.1") {
			t.Fatalf("bloqué trop tôt à l'essai %d", i)
		}
		l.Fail("192.0.2.1")
	}
	if l.Allowed("192.0.2.1") {
		t.Error("pas bloqué après 3 échecs")
	}
	if d := l.RetryAfter("192.0.2.1"); d <= 0 || d > 10*time.Minute {
		t.Errorf("RetryAfter = %v", d)
	}
	if !l.Allowed("192.0.2.2") {
		t.Error("une autre adresse est bloquée")
	}
	now = now.Add(11 * time.Minute)
	if !l.Allowed("192.0.2.1") {
		t.Error("toujours bloqué après la fenêtre")
	}
	l.Fail("192.0.2.1")
	l.Reset("192.0.2.1")
	if l.RetryAfter("192.0.2.1") != 0 || !l.Allowed("192.0.2.1") {
		t.Error("Reset sans effet")
	}
}
