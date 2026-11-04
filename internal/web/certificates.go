package web

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jogit/gatewyn/internal/certs"
	"github.com/jogit/gatewyn/internal/store"
)

type certView struct {
	Domain, Issuer, Left, Class string
	Challenge                   string // défi configuré pour l'hôte (pas forcément celui qui a servi à l'émission)
	Issued, ExpiresOn           string
	Covers                      string // autres noms couverts par le même certificat
}

func (s *Server) certificatesPage(w http.ResponseWriter, r *http.Request) {
	p := s.authedPage(r, "Certificats", "certificates")
	p.DNS = s.dnsViews(r.Context())
	p.CertsReadable = s.cfg.CertDir != ""
	p.RootCert = s.rootCert() != nil
	if p.CertsReadable {
		list, err := certs.List(s.cfg.CertDir)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		now := s.cfg.Now()
		hosts, _ := s.cfg.Store.ListHosts(r.Context())
		accounts := map[int64]dnsView{}
		for _, v := range p.DNS {
			accounts[v.ID] = v
		}
		for _, c := range list {
			p.Certs = append(p.Certs, certView{
				Domain: c.Domain, Issuer: c.Issuer, Left: daysLeft(now, c.Expires), Class: expiryClass(now, c.Expires),
				Challenge: challengeOf(c, hosts, accounts),
				Issued:    dateFR(c.Issued), ExpiresOn: dateFR(c.Expires),
				Covers: covers(c),
			})
		}
	}
	s.render(w, "certificates", p)
}

// rootCertPath : le certificat racine de l'autorité interne de Caddy, à côté du
// dossier des certificats. Seul root.crt est servi, jamais la clé voisine.
func (s *Server) rootCertPath() string {
	if s.cfg.CertDir == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.cfg.CertDir), "pki", "authorities", "local", "root.crt")
}

// rootCert renvoie le certificat racine au format PEM, ou nil s'il n'existe pas encore.
func (s *Server) rootCert() []byte {
	path := s.rootCertPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if block, _ := pem.Decode(data); block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return data
}

func (s *Server) downloadRootCert(w http.ResponseWriter, r *http.Request) {
	data := s.rootCert()
	if data == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="caddy-root.crt"`)
	_, _ = w.Write(data)
}

func dateFR(t time.Time) string { return t.Local().Format("02/01/2006") }

// covers liste les noms couverts en plus du domaine.
func covers(c certs.Cert) string {
	var others []string
	for _, n := range c.Names {
		if n != c.Domain {
			others = append(others, n)
		}
	}
	return strings.Join(others, ", ")
}

// challengeOf dit comment l'hôte de ce certificat obtient le sien, d'après sa configuration.
func challengeOf(c certs.Cert, hosts []store.Host, accounts map[int64]dnsView) string {
	if c.Issuer == "Caddy (interne)" {
		return "Interne (Caddy)"
	}
	for _, h := range hosts {
		if h.Domain != c.Domain {
			continue
		}
		switch a, ok := accounts[h.DNSAccountID]; {
		case h.HTTPOnly:
			return "Aucun (HTTP seulement)"
		case h.SelfSigned:
			return "Auto-signé (Caddy)"
		case ok:
			return "DNS · " + a.Provider + " (" + a.Name + ")"
		}
		return "Automatique (HTTP)"
	}
	return "Aucun hôte"
}

func daysLeft(now, expires time.Time) string {
	d := expires.Sub(now)
	if d <= 0 {
		return "expiré"
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d j", int(d.Hours()/24))
}

// expiryClass : vert, orange sous 14 jours, rouge une fois expiré.
func expiryClass(now, expires time.Time) string {
	switch d := expires.Sub(now); {
	case d <= 0:
		return "err"
	case d < 14*24*time.Hour:
		return "warn"
	}
	return "ok"
}
