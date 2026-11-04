package acmelog

import (
	"bytes"
	"strings"
	"testing"
)

// Lignes au format réel du journal de Caddy 2.11 (domaines fictifs).
const (
	failUnauthorized = `{"level":"error","ts":1793738388.3,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"Wiki.Example.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 400 urn:ietf:params:acme:error:unauthorized - Invalid response from http://wiki.example.com/.well-known/acme-challenge/x"}`
	failCanceled     = `{"level":"error","ts":1793738389.1,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"blog.example.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"[blog.example.com] creating new order: provisioning client: context canceled (ca=https://acme-v02.api.letsencrypt.org/directory)"}`
	okObtained       = `{"level":"info","ts":1793738400.2,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"wiki.example.com","issuer":"acme-v02.api.letsencrypt.org-directory"}`
	okRenewed        = `{"level":"info","ts":1793738401.2,"logger":"tls.renew","msg":"certificate renewed successfully","identifier":"docs.example.com"}`
	failRenew        = `{"level":"error","ts":1793738390.4,"logger":"tls.renew","msg":"could not get certificate from issuer","identifier":"docs.example.com","error":"no valid A records found for docs.example.com; no valid AAAA records found"}`
	unrelated        = `{"level":"info","ts":1793738391.0,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"wiki.example.com"}`
)

func feed(t *testing.T, tr *Tracker, lines ...string) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	w := tr.Wrap(&out)
	for _, l := range lines {
		if _, err := w.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	return &out
}

func TestFailureIsRecordedClearedAndCaseInsensitive(t *testing.T) {
	tr := New()
	feed(t, tr, unrelated, failUnauthorized)
	f, ok := tr.Failure("wiki.example.com")
	if !ok || !strings.Contains(f.Raw, "unauthorized") || f.At.IsZero() {
		t.Fatalf("échec non retenu : %+v %v", f, ok)
	}
	if _, ok := tr.Failure("WIKI.example.com"); !ok {
		t.Error("la recherche doit ignorer la casse")
	}
	// Un succès efface l'échec ; un échec du renouvellement le remet.
	feed(t, tr, okObtained)
	if _, ok := tr.Failure("wiki.example.com"); ok {
		t.Error("échec encore affiché après un succès")
	}
	feed(t, tr, failRenew)
	if f, ok := tr.Failure("docs.example.com"); !ok || !strings.Contains(f.Raw, "no valid A records") {
		t.Errorf("échec de renouvellement : %+v %v", f, ok)
	}
	feed(t, tr, okRenewed)
	if _, ok := tr.Failure("docs.example.com"); ok {
		t.Error("échec encore affiché après un renouvellement réussi")
	}
}

func TestCanceledRequestsAreNotFailures(t *testing.T) {
	tr := New()
	feed(t, tr, failCanceled)
	if _, ok := tr.Failure("blog.example.com"); ok {
		t.Error("une demande annulée par un rechargement de Caddy est comptée comme un échec")
	}
}

func TestWrapForwardsEverythingAndHandlesSplitWrites(t *testing.T) {
	tr := New()
	var out bytes.Buffer
	w := tr.Wrap(&out)
	data := []byte("texte brut qui n'est pas du JSON\n" + failUnauthorized + "\n{pas fini")
	for i := 0; i < len(data); i += 7 { // écritures coupées au milieu des lignes
		end := min(i+7, len(data))
		if _, err := w.Write(data[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if out.String() != string(data) {
		t.Error("les journaux ne sont pas transmis tels quels")
	}
	if _, ok := tr.Failure("wiki.example.com"); !ok {
		t.Error("ligne coupée en plusieurs écritures non analysée")
	}
}

func TestNilTrackerIsHarmless(t *testing.T) {
	var tr *Tracker
	var out bytes.Buffer
	if w := tr.Wrap(&out); w != &out {
		t.Error("un Tracker nil doit renvoyer l'écrivain tel quel")
	}
	if _, ok := tr.Failure("wiki.example.com"); ok {
		t.Error("échec trouvé dans un Tracker nil")
	}
}

func TestVeryLongLineIsSkippedButForwarded(t *testing.T) {
	tr := New()
	var out bytes.Buffer
	w := tr.Wrap(&out)
	long := strings.Repeat("x", maxLine+10)
	w.Write([]byte(long + "\n"))
	w.Write([]byte(failUnauthorized + "\n"))
	if out.Len() != len(long)+1+len(failUnauthorized)+1 {
		t.Error("ligne trop longue non transmise")
	}
	if _, ok := tr.Failure("wiki.example.com"); !ok {
		t.Error("la ligne suivante une ligne trop longue doit être analysée")
	}
}
