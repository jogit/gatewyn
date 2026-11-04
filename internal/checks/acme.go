package checks

import "strings"

// ExplainACME traduit une erreur d'émission de certificat (ACME, Let's Encrypt,
// journaux de Caddy) en message clair avec l'action à faire. Une erreur non
// reconnue donne un message générique, jamais le code brut comme texte principal.
func ExplainACME(raw string) Result {
	l := strings.ToLower(raw)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(l, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("/directory") && has("lookup", "dial tcp", "i/o timeout", "no route to host", "network is unreachable"):
		// Caddy n'atteint pas l'annuaire de Let's Encrypt : le problème est dans le conteneur, pas dans le domaine.
		return Result{Error, "acme_no_outbound", "Caddy n'arrive pas à joindre Let's Encrypt depuis cette machine. Le plus souvent, le DNS des conteneurs ne fonctionne pas : vérifiez que l'hôte a un serveur DNS configuré (/etc/resolv.conf) et que les conteneurs peuvent l'interroger."}
	case has("ratelimited", "too many certificates", "too many failed", "rate limit"):
		return Result{Error, "acme_rate_limit", "Let's Encrypt limite le nombre de demandes de certificat pour ce domaine. Attendez une heure (jusqu'à une semaine pour la limite hebdomadaire) avant de réessayer, et corrigez d'abord la cause de l'échec."}
	case has("nxdomain", "no valid a records", "no valid ip addresses", "dns problem"):
		return Result{Error, "acme_dns", "Let's Encrypt ne trouve pas le domaine dans le DNS. Vérifiez que l'enregistrement A du domaine existe et pointe vers votre adresse publique, puis patientez quelques minutes."}
	case has("timeout during connect", "connection timed out", "i/o timeout", "likely firewall problem"):
		return Result{Error, "acme_unreachable", "Let's Encrypt n'arrive pas à joindre votre serveur. Vérifiez que les ports 80 et 443 de votre box sont redirigés vers cette machine et que le pare-feu les laisse passer."}
	case has("connection refused"):
		return Result{Error, "acme_refused", "Let's Encrypt a été refusé en se connectant à votre serveur. Vérifiez que Caddy tourne et que les ports 80 et 443 sont bien redirigés vers lui."}
	case has("unauthorized", "invalid response", "the key authorization file"):
		return Result{Error, "acme_wrong_server", "Let's Encrypt a joint un autre serveur que celui-ci. Le domaine pointe probablement vers une autre machine ou un autre service : vérifiez l'enregistrement A et la redirection des ports."}
	case has("caa record", "caa "):
		return Result{Error, "acme_caa", "Un enregistrement CAA du domaine interdit à Let's Encrypt d'émettre un certificat. Ajoutez letsencrypt.org aux autorités autorisées chez votre registraire."}
	case has("dns-01", "dns challenge", "txt record", "propagation"):
		return Result{Error, "acme_dns_challenge", "Le défi DNS a échoué. Vérifiez les identifiants de votre fournisseur DNS et attendez la propagation de l'enregistrement TXT."}
	}
	return Result{Error, "acme_unknown", "L'obtention du certificat a échoué pour une raison que Gatewyn ne reconnaît pas. Vérifiez le DNS du domaine et la redirection des ports 80 et 443 ; les détails techniques sont dans les journaux de Caddy."}
}
