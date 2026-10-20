// Commandes à risque : `block` refuse sans discuter, `ask` demande confirmation.

export type Verdict = { level: 'block' | 'ask'; reason: string }

type Rule = { level: Verdict['level']; pattern: RegExp; reason: string }

const RULES: readonly Rule[] = [
  // Destruction irréversible du système
  { level: 'block', pattern: /\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(--no-preserve-root\s+)?(\/|\/\*|~|~\/|\$HOME)(\s|$)/, reason: 'suppression récursive de /, ~ ou $HOME' },
  { level: 'block', pattern: /\bmkfs(\.\w+)?\s/, reason: 'formatage d’un système de fichiers' },
  { level: 'block', pattern: /\bdd\b[^|;&]*\bof=\/dev\/(sd|nvme|hd|vd|xvd|disk)/, reason: 'écriture brute sur un disque' },
  { level: 'block', pattern: />\s*\/dev\/(sd|nvme|hd|vd|xvd)[a-z0-9]*/, reason: 'redirection vers un disque' },
  { level: 'block', pattern: /:\(\)\s*\{\s*:\|:&\s*\};:/, reason: 'fork bomb' },
  { level: 'block', pattern: /\bchmod\s+(-R\s+)?[0-7]?777\s+\/(\s|$)/, reason: 'chmod 777 sur /' },

  // Suppression / données
  { level: 'ask', pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-r\s+-f|-f\s+-r|--recursive\s+--force)\b/, reason: 'rm -rf' },
  { level: 'ask', pattern: /\b(DROP\s+(DATABASE|SCHEMA|TABLE)|TRUNCATE(\s+TABLE)?)\s/i, reason: 'DROP / TRUNCATE SQL' },
  { level: 'ask', pattern: /\bDELETE\s+FROM\s+\w+\s*(;|"|'|$)/i, reason: 'DELETE sans WHERE' },
  { level: 'ask', pattern: /\bdocker\s+(system|volume|image|container|network)\s+prune\b|\bdocker\s+volume\s+rm\b/, reason: 'suppression de ressources Docker' },
  { level: 'ask', pattern: /\bdocker\s+compose\b[^|;&]*\bdown\b[^|;&]*(-v\b|--volumes)/, reason: 'compose down avec suppression des volumes' },
  { level: 'ask', pattern: /\bgit\s+push\b[^|;&]*(\s-f\b|--force(?!-with-lease))/, reason: 'git push --force' },
  { level: 'ask', pattern: /\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f)/, reason: 'git reset --hard / clean -f' },

  // Kubernetes / Helm / IaC
  { level: 'ask', pattern: /\bkubectl\s+(delete|drain|cordon|replace\s+--force)\b/, reason: 'kubectl destructif' },
  { level: 'ask', pattern: /\bkubectl\s+scale\b[^|;&]*--replicas[= ]0\b/, reason: 'scale à 0 réplica' },
  { level: 'ask', pattern: /\bhelm\s+(uninstall|delete|rollback)\b/, reason: 'helm uninstall / rollback' },
  { level: 'ask', pattern: /\bterraform\s+(destroy|apply\b[^|;&]*-auto-approve)|\btofu\s+destroy\b/, reason: 'terraform destroy / apply sans revue' },

  // Réseau / pare-feu / accès
  { level: 'ask', pattern: /\biptables\s+(-[a-zA-Z]*\s+)*(-F|--flush|-X|-P\s+\w+\s+ACCEPT)\b|\bnft\s+flush\b/, reason: 'vidage / ouverture du pare-feu' },
  { level: 'ask', pattern: /\bufw\s+(disable|reset)\b|\bsystemctl\s+(stop|disable|mask)\s+(firewalld|ufw|nftables|iptables)\b/, reason: 'désactivation du pare-feu' },
  { level: 'ask', pattern: /\bsystemctl\s+(stop|disable|mask)\s+ssh(d)?\b/, reason: 'arrêt de SSH (risque de perte d’accès)' },
  { level: 'ask', pattern: /\bip\s+(link\s+set\s+\S+\s+down|route\s+(flush|del\s+default))|\bifdown\b/, reason: 'coupure d’interface / route par défaut' },
  { level: 'ask', pattern: /(>>?|\btee\b(\s+-a)?|\bsed\s+-i\S*[^|;&]*)\s*\/etc\/(sudoers|shadow|passwd|ssh\/sshd_config)\b|>>?\s*~\/\.ssh\/authorized_keys/, reason: 'modification de fichiers d’accès système' },

  // Exécution / durcissement
  { level: 'ask', pattern: /\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/, reason: 'script distant exécuté sans lecture (curl | sh)' },
  { level: 'ask', pattern: /\bchmod\s+(-R\s+)?[0-7]?777\b/, reason: 'chmod 777' },
  { level: 'ask', pattern: /\bdocker\s+run\b[^|;&]*(--privileged|--net(work)?[= ]host|--pid[= ]host|-v\s+\/var\/run\/docker\.sock)/, reason: 'conteneur privilégié / réseau hôte / socket Docker' },
  { level: 'ask', pattern: /\b(curl|wget)\b[^|;&]*(\s-k\b|--insecure|--no-check-certificate)/, reason: 'vérification TLS désactivée' },
]

// Verbes kube/helm qui modifient le cluster : confirmés dès que le contexte est la prod.
const MUTATING = /\b(kubectl\s+(apply|create|delete|patch|edit|replace|rollout|scale|set|label|annotate|drain|cordon|taint|exec)|helm\s+(install|upgrade|uninstall|delete|rollback))\b/

export const PROD = /(^|[-_.:/])(prod|prd|production|live)([-_.:/]|$)/i

// Le corps d'un heredoc est du texte (README, message de commit…), pas une commande —
// sauf quand il alimente un interpréteur (sh, ssh, psql, kubectl exec…).
const HEREDOC = /(^|\n)([^\n]*)<<-?\s*(['"]?)(\w+)\3([^\n]*)\n[\s\S]*?\n\s*\4\s*(?=\n|$)/g
const INTERPRETER = /\b(sh|bash|zsh|dash|ssh|sudo|psql|mysql|sqlite3|kubectl|docker|python3?|node|perl|ruby|xargs|eval|source)\b/

const stripTextHeredocs = (command: string): string =>
  command.replace(HEREDOC, (whole, start: string, before: string, _q, _tag, after: string) =>
    INTERPRETER.test(before) || INTERPRETER.test(after) ? whole : `${start}${before} ${after}`,
  )

export const assess = (raw: string, kubeContext: string | undefined): Verdict | undefined => {
  const command = stripTextHeredocs(raw)
  const blocked = RULES.find(r => r.level === 'block' && r.pattern.test(command))
  if (blocked) return { level: 'block', reason: blocked.reason }

  if (kubeContext && PROD.test(kubeContext) && MUTATING.test(command)) {
    return { level: 'ask', reason: `modification du cluster de PROD « ${kubeContext} »` }
  }

  const asked = RULES.find(r => r.level === 'ask' && r.pattern.test(command))
  return asked ? { level: 'ask', reason: asked.reason } : undefined
}
