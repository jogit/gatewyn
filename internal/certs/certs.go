// Package certs lit les certificats que Caddy a obtenus, dans son dossier de données.
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Cert est un certificat émis pour un domaine.
type Cert struct {
	Domain  string
	Issuer  string
	Issued  time.Time
	Expires time.Time
	Names   []string // tous les noms couverts (le domaine y figure)
}

// List lit <dir>/<émetteur>/<domaine>/<domaine>.crt (l'organisation du stockage de
// Caddy). Un dossier absent donne une liste vide ; un fichier illisible est ignoré.
func List(dir string) ([]Cert, error) {
	issuers, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Cert
	for _, iss := range issuers {
		if !iss.IsDir() {
			continue
		}
		domains, _ := os.ReadDir(filepath.Join(dir, iss.Name()))
		for _, d := range domains {
			data, err := os.ReadFile(filepath.Join(dir, iss.Name(), d.Name(), d.Name()+".crt"))
			if err != nil {
				continue
			}
			block, _ := pem.Decode(data)
			if block == nil {
				continue
			}
			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			out = append(out, Cert{
				Domain:  strings.Replace(d.Name(), "wildcard_.", "*.", 1),
				Issuer:  issuerName(iss.Name()),
				Issued:  crt.NotBefore,
				Expires: crt.NotAfter,
				Names:   crt.DNSNames,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// issuerName traduit le nom du dossier de Caddy en nom lisible.
func issuerName(dir string) string {
	switch {
	case strings.Contains(dir, "letsencrypt") && strings.Contains(dir, "staging"):
		return "Let's Encrypt (test)"
	case strings.Contains(dir, "letsencrypt"):
		return "Let's Encrypt"
	case strings.Contains(dir, "zerossl"):
		return "ZeroSSL"
	case dir == "local":
		return "Caddy (interne)"
	}
	return dir
}
