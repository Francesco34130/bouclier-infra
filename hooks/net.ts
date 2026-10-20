// Outils réseau des commandes /cidr, /port et /cve.

// ── /cidr ────────────────────────────────────────────────────────────────

type Ip = { v: 4 | 6; n: bigint }

const parseV4 = (s: string): bigint | undefined => {
  const parts = s.split('.')
  if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return undefined
  return parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n)
}

const parseV6 = (s: string): bigint | undefined => {
  let text = s.toLowerCase()
  // Adresse IPv4 embarquée (::ffff:192.0.2.1) → deux groupes hexadécimaux
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(text)?.[1]
  if (v4) {
    const n = parseV4(v4)
    if (n === undefined) return undefined
    text = `${text.slice(0, -v4.length)}${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return undefined
  const head = halves[0] ? halves[0].split(':') : []
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  if ([...head, ...rest].some(g => !/^[0-9a-f]{1,4}$/.test(g))) return undefined
  const missing = 8 - head.length - rest.length
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest]
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n)
}

const parseIp = (s: string): Ip | undefined => {
  const v4 = parseV4(s)
  if (v4 !== undefined) return { v: 4, n: v4 }
  const v6 = s.includes(':') ? parseV6(s) : undefined
  return v6 !== undefined ? { v: 6, n: v6 } : undefined
}

const formatV4 = (n: bigint): string => [24n, 16n, 8n, 0n].map(s => ((n >> s) & 255n).toString()).join('.')

const formatV6 = (n: bigint): string => {
  const groups = Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(112 - 16 * i)) & 0xffffn))
  let best = { at: -1, len: 0 }
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue }
    let j = i
    while (j < 8 && groups[j] === 0) j++
    if (j - i > best.len && j - i > 1) best = { at: i, len: j - i }
    i = j
  }
  const hex = groups.map(g => g.toString(16))
  if (best.at < 0) return hex.join(':')
  return `${hex.slice(0, best.at).join(':')}::${hex.slice(best.at + best.len).join(':')}`
}

const fmt = (ip: Ip): string => (ip.v === 4 ? formatV4(ip.n) : formatV6(ip.n))
const bits = (v: 4 | 6): bigint => (v === 4 ? 32n : 128n)
const group = (n: bigint): string => n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ' ')

const rangeOf = (v: 4 | 6, n: bigint, prefix: bigint) => {
  const host = bits(v) - prefix
  const mask = ((1n << bits(v)) - 1n) ^ ((1n << host) - 1n)
  const network = n & mask
  return { mask, network, last: network | ((1n << host) - 1n), size: 1n << host }
}

const V4_SCOPES: [string, string][] = [
  ['10.0.0.0/8', 'privée RFC 1918'], ['172.16.0.0/12', 'privée RFC 1918'], ['192.168.0.0/16', 'privée RFC 1918'],
  ['100.64.0.0/10', 'CGNAT RFC 6598'], ['127.0.0.0/8', 'loopback'], ['169.254.0.0/16', 'link-local (APIPA)'],
  ['224.0.0.0/4', 'multicast'], ['240.0.0.0/4', 'réservée'], ['192.0.2.0/24', 'documentation (TEST-NET-1)'],
  ['198.51.100.0/24', 'documentation (TEST-NET-2)'], ['203.0.113.0/24', 'documentation (TEST-NET-3)'], ['198.18.0.0/15', 'tests de performance'],
]
const V6_SCOPES: [string, string][] = [
  ['::1/128', 'loopback'], ['fe80::/10', 'link-local'], ['fc00::/7', 'ULA (privée)'], ['ff00::/8', 'multicast'],
  ['2001:db8::/32', 'documentation'], ['64:ff9b::/96', 'NAT64'], ['2000::/3', 'unicast global'],
]

const scopeOf = (ip: Ip): string => {
  for (const [cidr, label] of ip.v === 4 ? V4_SCOPES : V6_SCOPES) {
    const [base, p] = cidr.split('/')
    const b = base ? parseIp(base) : undefined
    if (!b || !p) continue
    if (rangeOf(ip.v, ip.n, BigInt(p)).network === rangeOf(b.v, b.n, BigInt(p)).network) return label
  }
  return ip.v === 4 ? 'publique' : 'non classée'
}

const parseCidr = (s: string): { ip: Ip; prefix: bigint } | string => {
  const [addr, p, extra] = s.trim().split('/')
  if (!addr || extra !== undefined) return `« ${s} » n’est pas un CIDR (ex. 10.0.0.0/22, 2001:db8::/48).`
  // Masque décimal accepté en IPv4 : 192.168.1.0/255.255.255.0
  const ip = parseIp(addr)
  if (!ip) return `adresse invalide : ${addr}`
  if (p === undefined) return { ip, prefix: bits(ip.v) }
  if (ip.v === 4 && p.includes('.')) {
    const m = parseV4(p)
    const ones = m === undefined ? -1 : m.toString(2).padStart(32, '0').indexOf('0')
    const prefix = ones === -1 ? 32 : ones
    if (m === undefined || rangeOf(4, 0n, BigInt(prefix)).mask !== m) return `masque non contigu : ${p}`
    return { ip, prefix: BigInt(prefix) }
  }
  if (!/^\d{1,3}$/.test(p) || BigInt(p) > bits(ip.v)) return `préfixe invalide : /${p}`
  return { ip, prefix: BigInt(p) }
}

export const cidr = (args: string): string => {
  const [main, sub] = args.trim().split(/\s+/)
  if (!main) return 'Usage : /cidr <réseau/préfixe> [/nouveau-préfixe]\n  ex. /cidr 10.0.0.0/22   ·   /cidr 10.0.0.0/22 /24   ·   /cidr 2001:db8::/48 /64'
  const parsed = parseCidr(main)
  if (typeof parsed === 'string') return parsed
  const { ip, prefix } = parsed
  const r = rangeOf(ip.v, ip.n, prefix)
  const lines: string[] = [`${fmt({ v: ip.v, n: r.network })}/${prefix}  —  IPv${ip.v}, ${scopeOf(ip)}`]
  if (r.network !== ip.n) lines.push(`⚠ ${fmt(ip)} n’est pas l’adresse réseau : réseau = ${fmt({ v: ip.v, n: r.network })}`)

  if (ip.v === 4) {
    const usable = prefix >= 31n ? r.size : r.size - 2n
    const first = prefix >= 31n ? r.network : r.network + 1n
    const last = prefix >= 31n ? r.last : r.last - 1n
    lines.push(
      `Masque      ${formatV4(r.mask)}   (wildcard ${formatV4(r.mask ^ 0xffffffffn)})`,
      `Plage       ${formatV4(first)} → ${formatV4(last)}`,
      `Broadcast   ${prefix >= 31n ? '— (RFC 3021 /31, ou hôte /32)' : formatV4(r.last)}`,
      `Hôtes       ${group(usable)} utilisables sur ${group(r.size)} adresses`,
    )
  } else {
    lines.push(`Plage       ${formatV6(r.network)} → ${formatV6(r.last)}`, `Adresses    2^${bits(6) - prefix} = ${group(r.size)}`)
    if (prefix < 64n) lines.push(`/64 dispo   ${group(1n << (64n - prefix))} sous-réseaux /64`)
  }

  if (sub) {
    const np = /^\/?(\d{1,3})$/.exec(sub)?.[1]
    if (!np || BigInt(np) <= prefix || BigInt(np) > bits(ip.v)) return `${lines.join('\n')}\n\nDécoupage : le nouveau préfixe doit être entre /${prefix + 1n} et /${bits(ip.v)}.`
    const count = 1n << (BigInt(np) - prefix)
    const step = 1n << (bits(ip.v) - BigInt(np))
    const shown = count > 32n ? 32n : count
    lines.push('', `Découpage en /${np} : ${group(count)} sous-réseaux${count > shown ? ` (32 premiers affichés)` : ''}`)
    for (let i = 0n; i < shown; i++) {
      const n = r.network + i * step
      lines.push(`  ${fmt({ v: ip.v, n })}/${np}${ip.v === 4 ? `   ${formatV4(n)} → ${formatV4(n + step - 1n)}` : ''}`)
    }
  }
  return lines.join('\n')
}

// ── /port ────────────────────────────────────────────────────────────────

type Port = { port: number; proto: string; service: string; note?: string }

const PORTS: readonly Port[] = [
  { port: 20, proto: 'tcp', service: 'FTP (données)', note: 'en clair' },
  { port: 21, proto: 'tcp', service: 'FTP (contrôle)', note: 'identifiants en clair — préférer SFTP' },
  { port: 22, proto: 'tcp', service: 'SSH / SFTP', note: 'cible n°1 du brute-force : clés uniquement, fail2ban' },
  { port: 23, proto: 'tcp', service: 'Telnet', note: 'en clair — à proscrire' },
  { port: 25, proto: 'tcp', service: 'SMTP', note: 'relais ouvert = spam ; STARTTLS' },
  { port: 53, proto: 'tcp/udp', service: 'DNS', note: 'résolveur ouvert = amplification DDoS' },
  { port: 67, proto: 'udp', service: 'DHCP serveur', note: 'rogue DHCP → DHCP snooping' },
  { port: 68, proto: 'udp', service: 'DHCP client' },
  { port: 69, proto: 'udp', service: 'TFTP', note: 'sans authentification' },
  { port: 80, proto: 'tcp', service: 'HTTP', note: 'rediriger vers 443' },
  { port: 88, proto: 'tcp/udp', service: 'Kerberos', note: 'Kerberoasting / AS-REP roasting' },
  { port: 110, proto: 'tcp', service: 'POP3', note: 'en clair — 995 en TLS' },
  { port: 111, proto: 'tcp/udp', service: 'rpcbind / portmapper', note: 'énumération NFS' },
  { port: 123, proto: 'udp', service: 'NTP', note: 'monlist → amplification' },
  { port: 135, proto: 'tcp', service: 'MS-RPC endpoint mapper' },
  { port: 137, proto: 'udp', service: 'NetBIOS Name Service', note: 'empoisonnement NBT-NS (Responder)' },
  { port: 139, proto: 'tcp', service: 'NetBIOS Session (SMB)' },
  { port: 143, proto: 'tcp', service: 'IMAP', note: 'en clair — 993 en TLS' },
  { port: 161, proto: 'udp', service: 'SNMP', note: 'communauté « public » / v1-v2c en clair — SNMPv3' },
  { port: 162, proto: 'udp', service: 'SNMP trap' },
  { port: 179, proto: 'tcp', service: 'BGP', note: 'filtrer les pairs, MD5/TCP-AO, RPKI' },
  { port: 389, proto: 'tcp/udp', service: 'LDAP', note: 'bind anonyme, en clair — LDAPS 636' },
  { port: 443, proto: 'tcp', service: 'HTTPS' },
  { port: 443, proto: 'udp', service: 'HTTP/3 (QUIC)' },
  { port: 445, proto: 'tcp', service: 'SMB', note: 'EternalBlue / ransomware — jamais exposé sur Internet' },
  { port: 465, proto: 'tcp', service: 'SMTPS (soumission TLS)' },
  { port: 500, proto: 'udp', service: 'IKE (IPsec)', note: 'aggressive mode → fuite PSK' },
  { port: 514, proto: 'udp', service: 'Syslog', note: 'en clair et non authentifié' },
  { port: 520, proto: 'udp', service: 'RIP' },
  { port: 587, proto: 'tcp', service: 'SMTP soumission (STARTTLS)' },
  { port: 636, proto: 'tcp', service: 'LDAPS' },
  { port: 853, proto: 'tcp', service: 'DNS over TLS' },
  { port: 873, proto: 'tcp', service: 'rsync', note: 'modules souvent sans auth' },
  { port: 993, proto: 'tcp', service: 'IMAPS' },
  { port: 995, proto: 'tcp', service: 'POP3S' },
  { port: 1194, proto: 'udp', service: 'OpenVPN' },
  { port: 1433, proto: 'tcp', service: 'MS SQL Server', note: 'ne pas exposer' },
  { port: 1521, proto: 'tcp', service: 'Oracle DB' },
  { port: 1701, proto: 'udp', service: 'L2TP' },
  { port: 1812, proto: 'udp', service: 'RADIUS auth' },
  { port: 1813, proto: 'udp', service: 'RADIUS accounting' },
  { port: 1883, proto: 'tcp', service: 'MQTT', note: 'souvent sans auth — 8883 en TLS' },
  { port: 2049, proto: 'tcp/udp', service: 'NFS', note: 'exports trop larges, no_root_squash' },
  { port: 2375, proto: 'tcp', service: 'Docker API (sans TLS)', note: '⚠ root distant sur l’hôte — jamais exposé' },
  { port: 2376, proto: 'tcp', service: 'Docker API (TLS)' },
  { port: 2379, proto: 'tcp', service: 'etcd client', note: 'contient les Secrets k8s — mTLS obligatoire' },
  { port: 2380, proto: 'tcp', service: 'etcd peer' },
  { port: 3000, proto: 'tcp', service: 'Grafana / apps Node (dev)' },
  { port: 3128, proto: 'tcp', service: 'Squid proxy', note: 'proxy ouvert' },
  { port: 3306, proto: 'tcp', service: 'MySQL / MariaDB', note: 'ne pas exposer' },
  { port: 3389, proto: 'tcp/udp', service: 'RDP', note: 'BlueKeep, brute-force — derrière VPN + NLA' },
  { port: 4500, proto: 'udp', service: 'IPsec NAT-T' },
  { port: 5000, proto: 'tcp', service: 'Docker Registry / Flask (dev)' },
  { port: 5060, proto: 'tcp/udp', service: 'SIP', note: 'fraude téléphonique' },
  { port: 5061, proto: 'tcp', service: 'SIP TLS' },
  { port: 5353, proto: 'udp', service: 'mDNS' },
  { port: 5432, proto: 'tcp', service: 'PostgreSQL', note: 'ne pas exposer ; pg_hba.conf strict' },
  { port: 5601, proto: 'tcp', service: 'Kibana' },
  { port: 5672, proto: 'tcp', service: 'RabbitMQ (AMQP)', note: 'guest/guest par défaut' },
  { port: 5900, proto: 'tcp', service: 'VNC', note: 'souvent sans mot de passe fort' },
  { port: 5985, proto: 'tcp', service: 'WinRM HTTP' },
  { port: 5986, proto: 'tcp', service: 'WinRM HTTPS' },
  { port: 6379, proto: 'tcp', service: 'Redis', note: 'sans auth par défaut → RCE (CONFIG SET)' },
  { port: 6443, proto: 'tcp', service: 'Kubernetes API server', note: 'RBAC, pas d’anonymous-auth' },
  { port: 6432, proto: 'tcp', service: 'PgBouncer' },
  { port: 8000, proto: 'tcp', service: 'Centrifugo / apps HTTP (dev)' },
  { port: 8080, proto: 'tcp', service: 'HTTP alternatif / proxy / Tomcat' },
  { port: 8443, proto: 'tcp', service: 'HTTPS alternatif' },
  { port: 8500, proto: 'tcp', service: 'Consul' },
  { port: 9000, proto: 'tcp', service: 'PHP-FPM / MinIO / Portainer', note: 'PHP-FPM exposé = RCE' },
  { port: 9090, proto: 'tcp', service: 'Prometheus', note: 'fuite de métriques / cibles' },
  { port: 9093, proto: 'tcp', service: 'Alertmanager' },
  { port: 9100, proto: 'tcp', service: 'node_exporter' },
  { port: 9200, proto: 'tcp', service: 'Elasticsearch HTTP', note: 'souvent sans auth → fuite de données' },
  { port: 9300, proto: 'tcp', service: 'Elasticsearch transport' },
  { port: 9092, proto: 'tcp', service: 'Kafka' },
  { port: 10250, proto: 'tcp', service: 'kubelet API', note: 'anonymous → exec dans les pods' },
  { port: 11211, proto: 'tcp/udp', service: 'Memcached', note: 'UDP → amplification x50 000' },
  { port: 27017, proto: 'tcp', service: 'MongoDB', note: 'sans auth historiquement → fuites massives' },
  { port: 51820, proto: 'udp', service: 'WireGuard' },
]

export const port = (args: string): string => {
  const q = args.trim().toLowerCase()
  if (!q) return 'Usage : /port <numéro | nom>   ex. /port 6379   ·   /port ldap'
  const hits = /^\d+$/.test(q)
    ? PORTS.filter(p => p.port === Number(q))
    : PORTS.filter(p => p.service.toLowerCase().includes(q) || (p.note?.toLowerCase().includes(q) ?? false))
  if (!hits.length) {
    const n = Number(q)
    if (Number.isInteger(n) && n >= 0 && n <= 65535) {
      const range = n < 1024 ? 'bien connu (0-1023, root requis pour écouter)' : n < 49152 ? 'enregistré (1024-49151)' : 'dynamique / éphémère (49152-65535)'
      return `${n} : pas dans ma table. Port ${range}. Vérifier : ss -tulpn | grep :${n}`
    }
    return `Aucun service connu pour « ${args.trim()} ».`
  }
  return hits.map(p => `${String(p.port).padStart(5)}/${p.proto.padEnd(7)} ${p.service}${p.note ? `\n${' '.repeat(14)}⚠ ${p.note}` : ''}`).join('\n')
}

// ── /cve ─────────────────────────────────────────────────────────────────

type Metric = { cvssData?: { baseScore?: number; baseSeverity?: string }; baseSeverity?: string }
type NvdVuln = {
  cve?: {
    id?: string
    published?: string
    descriptions?: { lang?: string; value?: string }[]
    metrics?: Record<string, Metric[] | undefined>
  }
}
type NvdPage = { totalResults?: number; vulnerabilities?: NvdVuln[] }

export const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

export const nvdUrl = (query: string, start: number, count: number): string =>
  `${NVD}?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=${count}&startIndex=${start}`

export const parseNvd = (text: string): NvdPage | undefined => {
  try {
    return JSON.parse(text) as NvdPage
  } catch {
    return undefined
  }
}

const SEV_ICON: Record<string, string> = { CRITICAL: '🟣', HIGH: '🔴', MEDIUM: '🟠', LOW: '🟢' }

export const formatCves = (query: string, page: NvdPage): string => {
  const list = [...(page.vulnerabilities ?? [])].reverse()
  if (!list.length) return `Aucune CVE trouvée dans la NVD pour « ${query} ».`
  const rows = list.map(v => {
    const c = v.cve ?? {}
    const m = c.metrics ?? {}
    const metric = (m.cvssMetricV40 ?? m.cvssMetricV31 ?? m.cvssMetricV30 ?? m.cvssMetricV2)?.[0]
    const score = metric?.cvssData?.baseScore
    const sev = (metric?.cvssData?.baseSeverity ?? metric?.baseSeverity ?? '').toUpperCase()
    const desc = (c.descriptions?.find(d => d.lang === 'en')?.value ?? '').replace(/\s+/g, ' ')
    return [
      `${SEV_ICON[sev] ?? '⚪'} ${c.id ?? '?'}  ${score !== undefined ? `${score} ${sev}` : 'non noté'}  (${(c.published ?? '').slice(0, 10)})`,
      `   ${desc.length > 180 ? `${desc.slice(0, 177)}…` : desc}`,
      `   https://nvd.nist.gov/vuln/detail/${c.id ?? ''}`,
    ].join('\n')
  })
  return [`${page.totalResults ?? list.length} CVE pour « ${query} » — les ${list.length} plus récentes :`, '', ...rows].join('\n')
}
