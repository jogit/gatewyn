package web

import (
	"testing"
	"time"

	"github.com/jogit/gatewyn/internal/certs"
)

// Un ancien certificat expiré du même domaine ne doit pas masquer le certificat
// valide (ici un générique obtenu par défi DNS).
func TestCertForPrefersLatest(t *testing.T) {
	now := time.Now()
	old := certs.Cert{Domain: "app.example.com", Names: []string{"app.example.com"}, Expires: now.Add(-24 * time.Hour)}
	wild := certs.Cert{Domain: "*.example.com", Names: []string{"*.example.com", "example.com"}, Expires: now.Add(60 * 24 * time.Hour)}
	m := map[string]certs.Cert{"app.example.com": old, "*.example.com": wild, "example.com": wild}
	c, ok := certFor(m, "app.example.com")
	if !ok || c.Domain != "*.example.com" {
		t.Errorf("%+v %v", c, ok)
	}
}
