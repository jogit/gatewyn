package caddyconf

import "encoding/json"

// Build produit le serveur HTTPS des hôtes, comme le fait un export complet (aide pour les tests).
func Build(hosts []Host) (*Server, error) { return BuildServer(hosts) }

// JSON sérialise une configuration Caddy complète : le serveur de Gatewyn dans apps.http.servers.
func JSON(hosts []Host) ([]byte, error) {
	srv, err := BuildServer(hosts)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]*Server `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	cfg.Apps.HTTP.Servers = map[string]*Server{ServerName: srv}
	return json.MarshalIndent(cfg, "", "  ")
}
