package caddyconf

import (
	"encoding/json"
	"net/http"
)

// Ces structures reproduisent la forme du JSON que l'API d'administration de Caddy attend
// (https://caddyserver.com/docs/json/). Elles ne dépendent d'aucun paquet de Caddy : importer ses
// types ajoutait une quarantaine de Mo à Gatewyn. La conformité est vérifiée par les tests,
// qui relisent chaque sortie dans les vrais types de Caddy en mode strict (types_caddy_test.go),
// et sur un Caddy réel (scripts/test-caddy.sh).

// Server est un serveur HTTP de Caddy (apps.http.servers.<nom>).
type Server struct {
	Listen               []string        `json:"listen,omitempty"`
	Routes               []Route         `json:"routes,omitempty"`
	Logs                 *serverLogs     `json:"logs,omitempty"`
	TrustedProxies       *trustedProxies `json:"trusted_proxies,omitempty"`
	TrustedProxiesStrict int             `json:"trusted_proxies_strict,omitempty"` // 1 : X-Forwarded-For lu de droite à gauche
}

type serverLogs struct {
	DefaultLoggerName string `json:"default_logger_name"`
}

type trustedProxies struct {
	Source string   `json:"source"`
	Ranges []string `json:"ranges"`
}

// Route est une règle : les requêtes qui correspondent à un des ensembles de critères
// passent par les gestionnaires, dans l'ordre.
type Route struct {
	Match    []matchers `json:"match,omitempty"`
	Handle   []any      `json:"handle,omitempty"`
	Terminal bool       `json:"terminal,omitempty"`
}

// matchers est un ensemble de critères : tous doivent correspondre.
type matchers struct {
	Host []string     `json:"host,omitempty"`
	Path []string     `json:"path,omitempty"`
	Not  []notMatcher `json:"not,omitempty"`
}

type notMatcher struct {
	ClientIP *clientIP `json:"client_ip"`
}

type clientIP struct {
	Ranges []string `json:"ranges"`
}

// Gestionnaires.

type simpleHandler struct {
	Handler string `json:"handler"`
}

type headersHandler struct {
	Handler  string      `json:"handler"`
	Response respHeaders `json:"response"`
}

type respHeaders struct {
	Set http.Header `json:"set"`
}

// encodeHandler : compression des réponses, zstd de préférence.
const encodeHandler = `{"handler":"encode","encodings":{"zstd":{},"gzip":{}},"prefer":["zstd","gzip"]}`

var encodeRaw = json.RawMessage(encodeHandler)

type rewriteHandler struct {
	Handler         string `json:"handler"`
	StripPathPrefix string `json:"strip_path_prefix"`
}

type staticResponse struct {
	Handler    string      `json:"handler"`
	StatusCode int         `json:"status_code"`
	Body       string      `json:"body,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
}

type reverseProxy struct {
	Handler       string     `json:"handler"`
	Upstreams     []upstream `json:"upstreams"`
	FlushInterval int        `json:"flush_interval,omitempty"` // -1 : les réponses partent au fur et à mesure
	Transport     *transport `json:"transport,omitempty"`
}

type upstream struct {
	Dial string `json:"dial"`
}

type transport struct {
	Protocol string    `json:"protocol"`
	TLS      *struct{} `json:"tls,omitempty"`      // la cible parle HTTPS
	Versions []string  `json:"versions,omitempty"` // « h2c » : HTTP/2 sans chiffrement
}

// Certificats (apps.tls.automation).

type tlsAutomation struct {
	Policies []tlsPolicy `json:"policies,omitempty"`
}

type tlsPolicy struct {
	Subjects []string `json:"subjects"`
	Issuers  []any    `json:"issuers"`
}

type internalIssuer struct {
	Module string `json:"module"`
}

type acmeIssuer struct {
	Module     string         `json:"module"`
	Challenges acmeChallenges `json:"challenges"`
}

type acmeChallenges struct {
	DNS dnsChallenge `json:"dns"`
}

type dnsChallenge struct {
	Provider map[string]any `json:"provider"`
}

// Journal d'accès (logging.logs.<nom>).

type logConfig struct {
	Writer  fileWriter `json:"writer"`
	Encoder logEncoder `json:"encoder"`
	Include []string   `json:"include"`
}

type fileWriter struct {
	Output       string `json:"output"`
	Filename     string `json:"filename"`
	Roll         bool   `json:"roll"`
	RollSizeMB   int    `json:"roll_size_mb"`
	RollKeep     int    `json:"roll_keep"`
	RollKeepDays int    `json:"roll_keep_days"`
}

type logEncoder struct {
	Format string `json:"format"`
}
