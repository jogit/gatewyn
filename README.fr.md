# Gatewyn

[English](README.md) · Français

Interface web simple pour publier des services en HTTPS, par-dessus Caddy.

Site et vidéo de démonstration : <https://jogit.github.io/gatewyn/fr.html>

État : publiée et utilisée. L'image est publiée sur GitHub Container Registry (`ghcr.io/jogit/gatewyn`, une étiquette par version, jamais `latest`). Les règles de travail sont dans [AGENTS.md](AGENTS.md) (en anglais), les décisions et leurs raisons dans [docs/architecture.md](docs/architecture.md) (en anglais).

## Idée

Des interfaces web pour reverse proxys existent déjà, souvent très complètes. Gatewyn choisit la simplicité : deux champs pour un premier service, des vérifications avant toute publication, des messages d'erreur qui disent quoi faire.

Objectif de simplicité : une personne qui n'a jamais utilisé de reverse proxy publie un service en HTTPS en moins de cinq minutes.

## Ce que fait Gatewyn

- **Hôtes** : services (reverse proxy), redirections et pages 404. Plusieurs noms par hôte, règles par chemin, HSTS, listes d'accès par adresse IP. Le DNS du domaine et la réponse du service sont vérifiés avant publication.
- **HTTPS** : certificat automatique (Let's Encrypt), défi DNS (Cloudflare, OVH, Gandi, Route 53, DigitalOcean, Hetzner, Infomaniak, IONOS), certificat auto-signé de Caddy, ou HTTP seulement.
- **Protection** : CrowdSec (état, nombre de décisions actives, services protégés, lien vers son interface) et son WAF AppSec (règles déclenchées), facultatifs.
- **Statistiques** : journal d'accès de Caddy, activé par défaut pour 30 jours (durée au choix, désactivable dans Réglages), dernières requêtes et résumé dans l'interface, rapport GoAccess facultatif. Avec CrowdSec, le journal sert aussi à repérer les scans.
- **Certificats en clair** : si Let's Encrypt refuse un certificat, la page Hôtes et la vue d'ensemble en donnent la cause et l'action à faire (lue dans les journaux de Caddy), jamais un code ACME brut.
- **Interface en français et en anglais** : la langue suit le navigateur, ou se choisit dans Réglages.
- **Sécurité de l'interface** : compte administrateur créé à la première visite (pas d'identifiant par défaut), limitation des essais, journal d'audit. Gardez l'interface sur un réseau privé : n'exposez jamais son port sur Internet.
- **Installation** : une image Docker (Gatewyn et Caddy), SQLite, aucune autre dépendance. Gatewyn n'accède pas à Docker.

## Essayer

```sh
docker compose -f deploy/compose.yml up -d
```

Puis ouvrir `http://<adresse du serveur>:8088`. Les ports 80 et 443 de la machine doivent être libres. Ne jamais exposer le port 8088 sur Internet (pare-feu) et créer le compte administrateur tout de suite.

CrowdSec et GoAccess sont des services facultatifs du compose, activés par profil (ajoutez la variable à votre fichier `.env` ou à votre stack, puis redéployez) :

```sh
COMPOSE_PROFILES=crowdsec,stats
```

L'interface explique chaque étape (pages Protection et Statistiques). Avec le profil `crowdsec`, CrowdSec crée lui-même les secrets qu'il partage avec Gatewyn et avec sa propre interface : rien à copier à la main.

## Mise à jour

Gatewyn ne se met jamais à jour seul et ne cherche pas de nouvelle version. Pour mettre à jour, changez l'étiquette de l'image dans votre compose (voir les [versions publiées](https://github.com/jogit/gatewyn/releases)) et redéployez. Vos données restent dans les volumes, et la base est copiée avant chaque migration. Pour revenir en arrière, redéployez l'étiquette précédente.

## Développer

```sh
go test ./...                    # tests unitaires
sh scripts/test-caddy.sh         # sur un Caddy réel, dans des conteneurs jetables
sh scripts/test-crowdsec.sh      # avec un CrowdSec jetable (blocage, WAF)
```

Les deux scripts créent leurs propres conteneurs sur 127.0.0.1 et les suppriment en sortant ; ils ne touchent à aucune installation existante. Le premier demande l'image `gatewyn-caddy:dev` (`docker build --target caddy -t gatewyn-caddy:dev .`).

## Feuille de route

Double authentification et écran d'import depuis Nginx Proxy Manager (le lecteur de base existe, en lecture seule, sans interface). Sans échéance.

## Sécurité

Pour signaler une faille, voir [SECURITY.md](SECURITY.md) (en anglais).

## Licence

[MIT](LICENSE). Les composants embarqués gardent leur licence : voir [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Crédits

- Construit sur [Caddy](https://caddyserver.com), [CrowdSec](https://www.crowdsec.net), [GoAccess](https://goaccess.io) et [htmx](https://htmx.org).
