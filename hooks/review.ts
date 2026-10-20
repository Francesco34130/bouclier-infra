// Revue sécu statique des fichiers infra que Claude vient d'écrire.

export type Severity = 'haute' | 'moyenne' | 'info'
export type Finding = { severity: Severity; line?: number; message: string }

type Kind = 'dockerfile' | 'compose' | 'kube' | 'nginx'

type LineRule = { severity: Severity; pattern: RegExp; message: string }

export const kindOf = (path: string, text: string): Kind | undefined => {
  const name = path.split('/').pop() ?? path
  if (/^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$/i.test(name)) return 'dockerfile'
  if (/^(docker-)?compose([.-].+)?\.ya?ml$/i.test(name)) return 'compose'
  if (/nginx/i.test(path) && /\.(conf|conf\.template)$/i.test(name)) return 'nginx'
  if (/\.ya?ml$/i.test(name) && (/\/(templates|charts|k8s|kube|manifests|helm|deploy)\//i.test(path) || /^values.*\.ya?ml$/i.test(name) || /^\s*kind:\s*\w+/m.test(text))) return 'kube'
  return undefined
}

const COMMON: readonly LineRule[] = [
  { severity: 'haute', pattern: /-----BEGIN( [A-Z]+)? PRIVATE KEY-----/, message: 'clé privée en clair' },
  { severity: 'haute', pattern: /\bAKIA[0-9A-Z]{16}\b/, message: 'clé d’accès AWS en clair' },
  { severity: 'haute', pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/, message: 'token (GitHub / GitLab / Slack) en clair' },
  { severity: 'moyenne', pattern: /\b\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)\w*\s*[:=]\s*["']?(?!\$|\{\{|<|changeme\b|""|''|$)[^\s"'#]{4,}/i, message: 'secret en dur — préférer un Secret / une variable d’env injectée' },
]

const RULES: Record<Kind, readonly LineRule[]> = {
  dockerfile: [
    { severity: 'haute', pattern: /^\s*USER\s+(root|0)(\s|:|$)/i, message: 'le conteneur tourne explicitement en root' },
    { severity: 'moyenne', pattern: /^\s*ADD\s+https?:\/\//i, message: 'ADD d’une URL — préférer curl + vérification de checksum' },
    { severity: 'haute', pattern: /(curl|wget)\b[^|]*\|\s*(ba)?sh\b/, message: 'script distant exécuté au build (curl | sh)' },
    { severity: 'moyenne', pattern: /^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*/i, message: 'secret en ENV/ARG — visible dans les couches de l’image (utiliser --secret)' },
    { severity: 'info', pattern: /\bchmod\s+(-R\s+)?777\b/, message: 'chmod 777 dans l’image' },
  ],
  compose: [
    { severity: 'haute', pattern: /^\s*privileged:\s*true\b/, message: 'service privileged' },
    { severity: 'haute', pattern: /^\s*network_mode:\s*["']?host\b/, message: 'network_mode: host — plus d’isolation réseau' },
    { severity: 'haute', pattern: /\/var\/run\/docker\.sock/, message: 'socket Docker monté — équivalent root sur l’hôte' },
    { severity: 'haute', pattern: /^\s*-?\s*["']?(SYS_ADMIN|ALL|NET_ADMIN|SYS_PTRACE)["']?\s*$/, message: 'capability dangereuse (vérifier cap_add)' },
    { severity: 'moyenne', pattern: /^\s*-\s*["']?(0\.0\.0\.0:)?(5432|3306|6379|27017|9200|11211|5672|2379)(:\d+)?["']?\s*$/, message: 'port de base / broker publié sur toutes les interfaces — binder sur 127.0.0.1' },
    { severity: 'moyenne', pattern: /^\s*image:\s*[^\s:@]+(:latest)?\s*$/, message: 'image sans tag ou en :latest' },
    { severity: 'info', pattern: /^\s*pid:\s*["']?host\b/, message: 'pid: host' },
  ],
  kube: [
    { severity: 'haute', pattern: /^\s*privileged:\s*true\b/, message: 'conteneur privileged' },
    { severity: 'haute', pattern: /^\s*host(Network|PID|IPC):\s*true\b/, message: 'partage du namespace hôte (hostNetwork/PID/IPC)' },
    { severity: 'haute', pattern: /^\s*allowPrivilegeEscalation:\s*true\b/, message: 'allowPrivilegeEscalation: true' },
    { severity: 'haute', pattern: /^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b/, message: 'exécution en root' },
    { severity: 'haute', pattern: /^\s*-?\s*["']?(SYS_ADMIN|ALL|NET_ADMIN|SYS_PTRACE)["']?\s*$/, message: 'capability dangereuse (vérifier capabilities.add)' },
    { severity: 'moyenne', pattern: /^\s*hostPath:/, message: 'volume hostPath' },
    { severity: 'moyenne', pattern: /^\s*(image|tag):\s*["']?([^\s"']+:)?latest["']?\s*$/, message: 'image en :latest — épingler une version (ou un digest)' },
    { severity: 'moyenne', pattern: /^\s*automountServiceAccountToken:\s*true\b/, message: 'token de service account monté — inutile pour la plupart des pods' },
    { severity: 'info', pattern: /^\s*type:\s*["']?(LoadBalancer|NodePort)\b/, message: 'service exposé hors cluster (LoadBalancer/NodePort)' },
    { severity: 'info', pattern: /^\s*readOnlyRootFilesystem:\s*false\b/, message: 'readOnlyRootFilesystem: false' },
  ],
  nginx: [
    { severity: 'haute', pattern: /^\s*ssl_protocols\b[^;]*\b(SSLv2|SSLv3|TLSv1(\.1)?)(\s|;)/, message: 'protocole TLS obsolète (garder TLSv1.2 TLSv1.3)' },
    { severity: 'moyenne', pattern: /^\s*autoindex\s+on\b/, message: 'autoindex on — listing de répertoires' },
    { severity: 'moyenne', pattern: /^\s*server_tokens\s+on\b/, message: 'server_tokens on — version nginx divulguée' },
    { severity: 'info', pattern: /^\s*proxy_ssl_verify\s+off\b/, message: 'proxy_ssl_verify off' },
  ],
}

const lineRules = (kind: Kind, lines: readonly string[]): Finding[] => {
  const out: Finding[] = []
  lines.forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '')
    if (/^\s*(#|\/\/)/.test(raw)) return
    for (const rule of [...COMMON, ...RULES[kind]]) {
      if (rule.pattern.test(line)) out.push({ severity: rule.severity, line: i + 1, message: rule.message })
    }
  })
  return out
}

const wholeFile = (kind: Kind, text: string): Finding[] => {
  const out: Finding[] = []
  if (kind === 'dockerfile') {
    const users = [...text.matchAll(/^\s*USER\s+(\S+)/gim)].map(m => m[1])
    if (users.length === 0) out.push({ severity: 'moyenne', message: 'aucune instruction USER — le conteneur tourne en root' })
    if (!/^\s*HEALTHCHECK\b/im.test(text)) out.push({ severity: 'info', message: 'pas de HEALTHCHECK' })
    const stages = new Set<string>(['scratch'])
    text.split('\n').forEach((line, i) => {
      const from = /^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(line)
      if (!from?.[1]) return
      const image = from[1]
      if (!stages.has(image.toLowerCase()) && !image.includes('$') && !image.includes('@sha256:')) {
        const tag = /:([^/:]+)$/.exec(image)?.[1]
        if (tag === undefined || tag === 'latest') out.push({ severity: 'moyenne', line: i + 1, message: `image de base ${image} ${tag ? 'en :latest' : 'sans tag'} — épingler une version` })
      }
      if (from[2]) stages.add(from[2].toLowerCase())
    })
  }
  if (kind === 'kube' && /^\s*kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod)\b/m.test(text)) {
    if (!/^\s*limits:/m.test(text)) out.push({ severity: 'moyenne', message: 'pas de resources.limits — un pod peut affamer le nœud' })
    if (!/^\s*securityContext:/m.test(text)) out.push({ severity: 'moyenne', message: 'pas de securityContext (runAsNonRoot, drop ALL, readOnlyRootFilesystem)' })
    if (!/^\s*(readinessProbe|livenessProbe):/m.test(text)) out.push({ severity: 'info', message: 'pas de readiness/liveness probe' })
  }
  if (kind === 'kube' && /^\s*kind:\s*Secret\b/m.test(text) && /^\s*(data|stringData):/m.test(text) && !/\{\{/.test(text)) {
    out.push({ severity: 'haute', message: 'Secret Kubernetes versionné en clair (base64 ≠ chiffrement) — SealedSecrets / SOPS / External Secrets' })
  }
  if (kind === 'nginx' && /^\s*listen\s+[^;]*\b(443|ssl)\b/m.test(text)) {
    const headers: [RegExp, string][] = [
      [/Strict-Transport-Security/i, 'Strict-Transport-Security'],
      [/X-Content-Type-Options/i, 'X-Content-Type-Options'],
      [/X-Frame-Options|frame-ancestors/i, 'X-Frame-Options / frame-ancestors'],
      [/Content-Security-Policy/i, 'Content-Security-Policy'],
    ]
    const missing = headers.filter(([re]) => !re.test(text)).map(([, name]) => name)
    if (missing.length) out.push({ severity: 'moyenne', message: `en-têtes de sécurité absents : ${missing.join(', ')}` })
    if (!/^\s*server_tokens\s+off\b/m.test(text)) out.push({ severity: 'info', message: 'server_tokens off non défini' })
  }
  if (kind === 'nginx') {
    text.split('\n').forEach((line, i) => {
      const ciphers = /^\s*ssl_ciphers\s+["']?([^;"']+)/.exec(line)?.[1]
      const weak = ciphers?.split(':').filter(c => !c.startsWith('!') && !c.startsWith('-') && /RC4|MD5|(^|-)DES|3DES|NULL|EXPORT/i.test(c))
      if (weak?.length) out.push({ severity: 'haute', line: i + 1, message: `suites de chiffrement faibles : ${weak.join(', ')}` })
    })
  }
  return out
}

export const review = (path: string, text: string): { kind: Kind; findings: Finding[] } | undefined => {
  const kind = kindOf(path, text)
  if (!kind) return undefined
  const findings = [...lineRules(kind, text.split('\n')), ...wholeFile(kind, text)]
  const order: Record<Severity, number> = { haute: 0, moyenne: 1, info: 2 }
  findings.sort((a, b) => order[a.severity] - order[b.severity] || (a.line ?? 1e9) - (b.line ?? 1e9))
  return { kind, findings }
}

export const ICON: Record<Severity, string> = { haute: '🔴', moyenne: '🟠', info: '🔵' }

export const formatFindings = (path: string, findings: readonly Finding[]): string =>
  [
    `Revue sécu (bouclier-infra) de ${path} :`,
    ...findings.map(f => `${ICON[f.severity]} ${f.severity}${f.line ? ` L${f.line}` : ''} — ${f.message}`),
  ].join('\n')
