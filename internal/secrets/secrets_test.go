package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealUnseal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("droits de la clé : %v", st.Mode().Perm())
	}
	sealed, _ := b.Seal(`{"api_token":"jeton-fictif"}`)
	if strings.Contains(sealed, "jeton") {
		t.Error("le texte clair apparaît dans la donnée chiffrée")
	}
	again, _ := b.Seal(`{"api_token":"jeton-fictif"}`)
	if sealed == again {
		t.Error("deux chiffrements identiques : nonce réutilisé")
	}
	// Une autre ouverture du même fichier déchiffre ; une autre clé échoue.
	b2, _ := Open(path)
	if got, err := b2.Unseal(sealed); err != nil || got != `{"api_token":"jeton-fictif"}` {
		t.Errorf("%q %v", got, err)
	}
	other, _ := Open(filepath.Join(t.TempDir(), "autre.key"))
	if _, err := other.Unseal(sealed); err == nil {
		t.Error("déchiffré avec une autre clé")
	}
	if _, err := b.Unseal("n'importe quoi"); err == nil {
		t.Error("donnée invalide acceptée")
	}
}
