# bouclier-infra

Mod Claude Code pour le travail infra / réseau / sécu :

- **Garde-fou commandes** : bloque la destruction du système (`rm -rf /`, `mkfs`, écriture brute sur un disque…) et demande confirmation pour `rm -rf`, `kubectl delete`, `helm uninstall`, `terraform destroy`, `iptables -F`, `curl | sh`, `docker run --privileged`, `git push --force`, etc. Toute modification d'un cluster dont le contexte contient `prod` / `prd` / `production` est confirmée.
- **Journal d'audit** : panneau listant chaque action de Claude (commandes, écritures, requêtes web, MCP). `/audit export` l'écrit en Markdown dans `~/.claude/audit/`, `/audit clear` le vide.
- **Contexte en status line** : `🔴 PROD · ⎈ cluster/namespace · 🐳 contexte docker · ⎇ branche`. `/contexte` le rafraîchit.
- **Revue sécu des fichiers infra** : après chaque écriture d'un Dockerfile, compose, manifeste K8s / chart Helm ou config nginx, signale root, `:latest`, privileged, hostNetwork, limits / securityContext absents, Secret en clair, TLS obsolète, en-têtes de sécurité manquants…
- **Outils réseau** : `/cidr 10.0.0.0/22 /24` (IPv4/IPv6, découpage), `/port 6379` (service et risques), `/cve nginx 1.25` (dernières CVE NVD ; `NVD_API_KEY` optionnelle).

## Installation

Au prompt d'une session Claude Code dans un terminal :

```
/plugin install bouclier-infra --marketplace Francesco34130/bouclier-infra
```

Répondre `y` pour ajouter la marketplace, puis choisir la portée (user).

Depuis un shell :

```
claude plugin install bouclier-infra --marketplace Francesco34130/bouclier-infra
```

Dans l'application desktop : **+** à côté du prompt → Plugins → Add marketplace `Francesco34130/bouclier-infra` → Add plugin.

## Développement

```
claude plugin validate .
claude plugin test .
```
