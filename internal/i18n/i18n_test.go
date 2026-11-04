package i18n

import (
	"strings"
	"testing"
)

func TestTextExactPatternsAndUnknown(t *testing.T) {
	for in, want := range map[string]string{
		"Hôtes":                                 "Hosts",                         // clé exacte
		"  Hôtes \n":                            "  Hosts \n",                    // les espaces autour sont conservés
		"Hôte wiki.example.com créé":            "Host wiki.example.com created", // motif avec une valeur
		"Aucun résultat pour « abc ».":          `No results for "abc".`,
		"3 hôtes":                               "3 hosts",
		"1 hôte":                                "1 host",
		"Texte qui n'est pas dans le catalogue": "Texte qui n'est pas dans le catalogue", // rendu tel quel
		"":                                      "",
		"192.0.2.1":                             "192.0.2.1",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestSentencesAreTranslatedBeforeTheirPieces(t *testing.T) {
	// La phrase complète a sa propre entrée : elle passe avant le mot « Désactiver » qu'elle contient.
	got := Text("wiki.example.com est désactivé : il n'est plus publié.")
	if got != "wiki.example.com is disabled: it is no longer published." {
		t.Errorf("phrase : %q", got)
	}
}

func TestCapitalisedMessageMatchesLowercaseKey(t *testing.T) {
	// Un message d'erreur est affiché avec une majuscule ; sa clé, écrite en minuscule, vaut aussi pour lui.
	if got := Text("Le mot de passe ne peut pas être vide."); got != "The password cannot be empty." {
		t.Errorf("majuscule : %q", got)
	}
	if got := Text("le mot de passe ne peut pas être vide"); got != "the password cannot be empty" {
		t.Errorf("minuscule : %q", got)
	}
	// Une clé qui commence par une majuscule n'est pas appliquée à un mot en minuscule au milieu d'une phrase.
	if got := Text("connecté"); got != "connecté" {
		t.Errorf("clé capitalisée prise pour une minuscule : %q", got)
	}
}

func TestWordBoundariesAreRespected(t *testing.T) {
	// « hôte » ne doit pas être traduit au milieu de « hôtes », ni « activé » dans « désactivé ».
	if got := Text("désactivé"); got != "disabled" {
		t.Errorf("désactivé : %q", got)
	}
	if got := Text("hôtesse"); got != "hôtesse" {
		t.Errorf("hôtesse : %q", got)
	}
}

func TestNestedFrenchInsideAValueIsTranslated(t *testing.T) {
	// Une valeur entre guillemets est conservée telle quelle.
	got := Text(`Le chemin "/api" est invalide.`)
	if got != `The path "/api" is invalid.` {
		t.Errorf("valeur citée : %q", got)
	}
	// Un caractère cité entre apostrophes (%q d'un rune) est reconnu aussi.
	got = Text("Le chemin \"/a b\" contient un caractère non accepté (' ') : lettres, chiffres et - . _ ~ / seulement.")
	if !strings.HasPrefix(got, `The path "/a b" contains a character that is not accepted (' ')`) {
		t.Errorf("caractère cité : %q", got)
	}
}

func TestDatesAreWrittenTheEnglishWay(t *testing.T) {
	for in, want := range map[string]string{
		"depuis le 03/11 22:57": "since Nov 3 22:57",
		"il y a 5 min":          "5 min ago",
		"le 02/01/2027":         "on 2027-01-02",
		"8 j":                   "8 d",
	} {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestTranslationIsStableAndDoesNotRetranslateEnglish(t *testing.T) {
	for _, s := range []string{"Hosts", "Settings", "Check for updates", "Services"} {
		if got := Text(s); got != s {
			t.Errorf("l'anglais déjà traduit change : %q → %q", s, got)
		}
	}
	a, b := Text("Hôtes"), Text("Hôtes") // la seconde réponse vient du cache
	if a != b {
		t.Errorf("cache : %q ≠ %q", a, b)
	}
}

func TestHTMLTranslatesTextAndAttributesAndKeepsStructure(t *testing.T) {
	in := `<!doctype html><html lang="fr"><head><title>Hôtes · Gatewyn</title></head><body>` +
		`<a href="/hosts" title="Se déconnecter" class="x">Hôtes</a>` +
		`<input type="submit" value="Enregistrer"><input type="text" value="Enregistrer" placeholder="Optionnel : autre service">` +
		`<button hx-confirm="Supprimer wiki.example.com ? Il ne sera plus publié.">Supprimer</button>` +
		`<pre>Hôtes</pre><textarea>Hôtes</textarea><script>var a = "Hôtes";</script></body></html>`
	got := string(HTML([]byte(in)))
	for _, want := range []string{`lang="en"`, `<title>Hosts · Gatewyn</title>`, `title="Sign out"`, `>Hosts</a>`, `class="x"`, `value="Save"`,
		`placeholder="Optional: other service"`, `hx-confirm="Delete wiki.example.com? It will no longer be published."`, `>Delete</button>`} {
		if !strings.Contains(got, want) {
			t.Errorf("sortie sans %s :\n%s", want, got)
		}
	}
	// Le champ de saisie, le texte préformaté, la zone de texte et le script ne sont pas traduits.
	for _, keep := range []string{`<input type="text" value="Enregistrer"`, `<pre>Hôtes</pre>`, `<textarea>Hôtes</textarea>`, `var a = "Hôtes";`} {
		if !strings.Contains(got, keep) {
			t.Errorf("contenu modifié à tort (%s) :\n%s", keep, got)
		}
	}
}

func TestHTMLFragmentsKeepTheirTableRows(t *testing.T) {
	// Un fragment qui commence par une ligne de tableau ne doit pas perdre ses balises.
	got := string(HTML([]byte(`<tr id="host-1"><td data-l="État">Actif</td><td>Hôte</td></tr>`)))
	if got != `<tr id="host-1"><td data-l="Status">Active</td><td>Host</td></tr>` {
		t.Errorf("ligne de tableau : %s", got)
	}
	if got := string(HTML([]byte(`<span class="pill">Désactivé</span>`))); got != `<span class="pill">Disabled</span>` {
		t.Errorf("fragment : %s", got)
	}
	// Les caractères spéciaux restent échappés.
	if got := string(HTML([]byte(`<p>Hôtes &amp; &lt;b&gt;</p>`))); got != `<p>Hosts &amp; &lt;b&gt;</p>` {
		t.Errorf("échappement : %s", got)
	}
}

func TestLooksFrench(t *testing.T) {
	for s, want := range map[string]bool{
		"Hôtes": true, "Le domaine est invalide": true, "Cible": false, "Hosts": false, "Français": false,
		"Mon OVH": false, "Overview": false, "The domain does not exist": false, "wiki.example.com": false,
	} {
		if got := LooksFrench(s); got != want {
			t.Errorf("LooksFrench(%q) = %v, attendu %v", s, got, want)
		}
	}
}

func TestCatalogHasNoDuplicateKeys(t *testing.T) {
	seen := map[string]string{}
	for _, e := range entries {
		k := norm(e.fr)
		if prev, ok := seen[k]; ok && prev != e.en {
			t.Errorf("clé en double avec deux traductions : %q → %q et %q", e.fr, prev, e.en)
		}
		seen[k] = e.en
	}
}

func TestEveryEnglishValueUsesTheSameVerbsAsItsKey(t *testing.T) {
	for _, e := range entries {
		if a, b := len(verbRe.FindAllString(e.fr, -1)), len(verbRe.FindAllString(e.en, -1)); a != b {
			t.Errorf("%q : %d valeur(s) en français, %d en anglais (%q)", e.fr, a, b, e.en)
		}
	}
}

func TestEnglishValuesLookEnglish(t *testing.T) {
	for _, e := range entries {
		if LooksFrench(e.en) {
			t.Errorf("la traduction ressemble à du français : %q → %q", e.fr, e.en)
		}
	}
}
