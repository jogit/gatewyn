// Package dnsprov décrit les fournisseurs DNS pris en charge pour le défi ACME :
// leurs champs et le JSON que Caddy attend. Chaque fournisseur est un module
// compilé dans l'image (voir le Dockerfile) : en ajouter un, c'est une ligne
// là-bas et une entrée ici. Les noms de champs (Key) sont ceux du JSON du module.
package dnsprov

import (
	"fmt"
	"strings"
)

// Field est un champ de configuration d'un fournisseur.
type Field struct {
	Key      string
	Label    string
	Secret   bool // jamais réaffiché après la saisie
	Optional bool
	Default  string // valeur proposée à la création
}

// Provider est un fournisseur DNS. ID est le nom du module Caddy (dns.providers.<ID>).
type Provider struct {
	ID     string
	Name   string
	Fields []Field
}

var providers = []Provider{
	{"cloudflare", "Cloudflare", []Field{
		{Key: "api_token", Label: "Jeton d'API (droit « Zone · DNS · Modifier »)", Secret: true},
		{Key: "zone_token", Label: "Jeton de lecture des zones (si le premier est limité à une zone)", Secret: true, Optional: true},
	}},
	{"ovh", "OVH", []Field{
		{Key: "endpoint", Label: "Région de l'API", Default: "ovh-eu"},
		{Key: "application_key", Label: "Clé d'application"},
		{Key: "application_secret", Label: "Secret d'application", Secret: true},
		{Key: "consumer_key", Label: "Clé du consommateur", Secret: true},
	}},
	{"gandi", "Gandi", []Field{
		{Key: "bearer_token", Label: "Jeton d'accès personnel", Secret: true},
		{Key: "sharing_id", Label: "Identifiant de l'organisation (optionnel)", Optional: true},
	}},
	{"route53", "Amazon Route 53", []Field{
		{Key: "region", Label: "Région AWS", Default: "us-east-1"},
		{Key: "access_key_id", Label: "Identifiant de clé d'accès"},
		{Key: "secret_access_key", Label: "Clé d'accès secrète", Secret: true},
	}},
	{"digitalocean", "DigitalOcean", []Field{
		{Key: "auth_token", Label: "Jeton d'API", Secret: true},
	}},
	{"hetzner", "Hetzner", []Field{
		{Key: "api_token", Label: "Jeton d'API", Secret: true},
	}},
	{"infomaniak", "Infomaniak", []Field{
		{Key: "api_token", Label: "Jeton d'API", Secret: true},
	}},
	{"ionos", "IONOS", []Field{
		{Key: "api_token", Label: "Jeton d'API", Secret: true},
	}},
}

// All renvoie les fournisseurs, dans l'ordre d'affichage.
func All() []Provider { return providers }

// Get renvoie le fournisseur d'identifiant id.
func Get(id string) (Provider, bool) {
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// Clean ne garde que les champs du fournisseur, sans espaces autour, et vérifie
// que les champs obligatoires sont remplis.
func Clean(id string, values map[string]string) (map[string]string, error) {
	p, ok := Get(id)
	if !ok {
		return nil, fmt.Errorf("fournisseur inconnu : %q", id)
	}
	out := map[string]string{}
	for _, f := range p.Fields {
		v := strings.TrimSpace(values[f.Key])
		if v == "" && !f.Optional {
			return nil, fmt.Errorf("le champ « %s » est obligatoire", f.Label)
		}
		if v != "" {
			out[f.Key] = v
		}
	}
	return out, nil
}

// CaddyConfig renvoie le JSON du fournisseur tel que Caddy l'attend :
// {"name": "ovh", "endpoint": "...", ...}.
func CaddyConfig(id string, values map[string]string) map[string]any {
	m := map[string]any{"name": id}
	for k, v := range values {
		m[k] = v
	}
	return m
}
