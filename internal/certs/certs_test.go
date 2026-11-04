package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// write crée <dir>/<issuer>/<name>/<name>.crt avec un certificat qui expire à notAfter.
func write(t *testing.T, dir, issuer, name string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{strings.Replace(name, "wildcard_.", "*.", 1), "example.com"}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(dir, issuer, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(d, name+".crt"), pemData, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	soon := time.Now().Add(9 * 24 * time.Hour).Truncate(time.Second)
	write(t, dir, "acme-v02.api.letsencrypt.org-directory", "wiki.example.com", time.Now().Add(62*24*time.Hour))
	write(t, dir, "acme-v02.api.letsencrypt.org-directory", "wildcard_.example.com", soon)
	write(t, dir, "local", "wiki.localhost", time.Now().Add(24*time.Hour))
	// Ignorés : fichier qui n'est pas un certificat, dossier sans certificat.
	os.MkdirAll(filepath.Join(dir, "local", "vide"), 0o755)
	os.MkdirAll(filepath.Join(dir, "local", "casse"), 0o755)
	os.WriteFile(filepath.Join(dir, "local", "casse", "casse.crt"), []byte("pas un certificat"), 0o644)

	got, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d certificats : %+v", len(got), got)
	}
	want := []struct{ domain, issuer string }{{"*.example.com", "Let's Encrypt"}, {"wiki.example.com", "Let's Encrypt"}, {"wiki.localhost", "Caddy (interne)"}}
	for i, w := range want {
		if got[i].Domain != w.domain || got[i].Issuer != w.issuer {
			t.Errorf("ligne %d : %+v, attendu %v", i, got[i], w)
		}
	}
	if !got[0].Expires.Equal(soon) || !got[0].Issued.Equal(soon.Add(-90*24*time.Hour)) {
		t.Errorf("dates : émis %v, expire %v", got[0].Issued, got[0].Expires)
	}
	if strings.Join(got[0].Names, " ") != "*.example.com example.com" {
		t.Errorf("noms couverts : %v", got[0].Names)
	}
}

func TestListMissingDirIsEmpty(t *testing.T) {
	got, err := List(filepath.Join(t.TempDir(), "absent"))
	if err != nil || len(got) != 0 {
		t.Errorf("%v %v", got, err)
	}
}

func TestIssuerName(t *testing.T) {
	for dir, want := range map[string]string{
		"acme-v02.api.letsencrypt.org-directory":         "Let's Encrypt",
		"acme-staging-v02.api.letsencrypt.org-directory": "Let's Encrypt (test)",
		"acme.zerossl.com-v2-DV90":                       "ZeroSSL",
		"local":                                          "Caddy (interne)",
		"autre":                                          "autre",
	} {
		if got := issuerName(dir); got != want {
			t.Errorf("%s → %q, attendu %q", dir, got, want)
		}
	}
}
