package dnsprov

import "testing"

func TestCleanAndConfig(t *testing.T) {
	if len(All()) != 8 {
		t.Errorf("%d fournisseurs", len(All()))
	}
	got, err := Clean("ovh", map[string]string{"endpoint": " ovh-eu ", "application_key": "ak", "application_secret": "as", "consumer_key": "ck", "intrus": "x"})
	if err != nil || len(got) != 4 || got["endpoint"] != "ovh-eu" {
		t.Fatalf("%v %v", got, err)
	}
	cfg := CaddyConfig("ovh", got)
	if cfg["name"] != "ovh" || cfg["consumer_key"] != "ck" || cfg["intrus"] != nil {
		t.Errorf("%v", cfg)
	}
	if _, err := Clean("ovh", map[string]string{"endpoint": "ovh-eu"}); err == nil {
		t.Error("champs obligatoires absents acceptés")
	}
	// Champ optionnel : absent accepté.
	if _, err := Clean("cloudflare", map[string]string{"api_token": "t"}); err != nil {
		t.Error(err)
	}
	if _, err := Clean("inconnu", nil); err == nil {
		t.Error("fournisseur inconnu accepté")
	}
	seen := map[string]bool{}
	for _, p := range All() {
		if seen[p.ID] || len(p.Fields) == 0 {
			t.Errorf("fournisseur %s en double ou sans champ", p.ID)
		}
		seen[p.ID] = true
	}
}
