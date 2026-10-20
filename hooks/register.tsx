import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { AuditEntry, AuditStatus } from '../types'
import { PROD, assess } from './danger'
import { cidr, formatCves, nvdUrl, parseNvd, port } from './net'
import { ICON, formatFindings, review } from './review'

const PANE = 'audit'
const audit = atom({ plugin: 'bouclier-infra', key: 'audit' } as const, [])

const AUDITED = new Set(['Bash', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'WebFetch', 'WebSearch'])
const WRITES = new Set(['Write', 'Edit', 'MultiEdit'])
const CONTEXT_CHANGERS = /\b(kubectl\s+config|kubectx|kubens|docker\s+context|git\s+(checkout|switch)|KUBECONFIG=|aws\s+eks\s+update-kubeconfig|az\s+aks\s+get-credentials|gcloud\s+container\s+clusters\s+get-credentials)\b/

// ── Contexte kube / docker / git ─────────────────────────────────────────

let kubeContext: string | undefined

const output = async ($: EngineInterface, argv: string[]): Promise<string | undefined> => {
  try {
    const { exitCode, stdout } = await $.process.run(argv, { timeoutMs: 5000 })
    const text = stdout.trim()
    return exitCode === 0 && text ? text : undefined
  } catch {
    return undefined // outil absent
  }
}

const refreshContext = async ($: EngineInterface): Promise<void> => {
  const [kube, ns, docker, branch] = await Promise.all([
    output($, ['kubectl', 'config', 'current-context']),
    output($, ['kubectl', 'config', 'view', '--minify', '-o', 'jsonpath={..namespace}']),
    output($, ['docker', 'context', 'show']),
    output($, ['git', 'branch', '--show-current']),
  ])
  kubeContext = kube
  const isProd = [kube, docker].some(c => c !== undefined && PROD.test(c))
  const parts = [
    kube && `⎈ ${kube}/${ns ?? 'default'}`,
    docker && docker !== 'default' && `🐳 ${docker}`,
    branch && `⎇ ${branch}`,
  ].filter(Boolean)
  $.ui.status(parts.length ? `${isProd ? '🔴 PROD · ' : ''}${parts.join(' · ')}` : undefined)
}

// ── Journal d'audit ──────────────────────────────────────────────────────

const summarize = (tool: string, input: Record<string, unknown>): string => {
  const pick = (k: string): string | undefined => (typeof input[k] === 'string' ? (input[k] as string) : undefined)
  const text = pick('command') ?? pick('file_path') ?? pick('notebook_path') ?? pick('url') ?? pick('query') ?? JSON.stringify(input)
  return text.split('\n')[0] ?? tool
}

const setStatus = ($: EngineInterface, id: string, status: AuditStatus, note?: string) =>
  update($, audit, list => list.map(one => (one.id === id ? { ...one, status, ...(note ? { note } : {}) } : one)))

const hhmmss = (at: number): string => new Date(at).toISOString().slice(11, 19)

const STATUS_LABEL: Record<AuditStatus, string> = { runs: '…', ok: '✓', error: '✗', denied: '⛔', flagged: '⚠' }

const toMarkdown = (list: readonly AuditEntry[]): string =>
  [
    `# Journal d'audit Claude — ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
    '',
    '| Heure (UTC) | Statut | Outil | Action | Note |',
    '| --- | --- | --- | --- | --- |',
    ...list.map(a => `| ${hhmmss(a.at)} | ${STATUS_LABEL[a.status]} ${a.status} | ${a.tool} | \`${a.summary.replace(/[|`]/g, '\\$&')}\` | ${(a.note ?? '').replace(/\|/g, '\\|').replace(/\n/g, '<br>')} |`),
    '',
  ].join('\n')

// ── Commandes ────────────────────────────────────────────────────────────

const COMMANDS = [
  { name: 'audit', description: 'Journal des actions de Claude (ouvre le panneau, ou « export » en Markdown)', argumentHint: '[export|clear]' },
  { name: 'cidr', description: 'Calcul de sous-réseau IPv4/IPv6, avec découpage optionnel', argumentHint: '<réseau/préfixe> [/nouveau-préfixe]' },
  { name: 'port', description: 'Service et risques connus d’un port (ou recherche par nom)', argumentHint: '<numéro|nom>' },
  { name: 'cve', description: 'Dernières CVE de la NVD pour un produit et une version', argumentHint: '<produit> [version]' },
  { name: 'contexte', description: 'Rafraîchit le contexte kube / docker / git de la status line' },
] as const

const cve = async ($: EngineInterface, args: string): Promise<string> => {
  const query = args.trim()
  if (!query) return 'Usage : /cve <produit> [version]   ex. /cve nginx 1.25   ·   /cve centrifugo'
  const key = await $.env.get('NVD_API_KEY')
  const headers: Record<string, string> = key ? { apiKey: key } : {}
  try {
    const first = await $.http.fetch(nvdUrl(query, 0, 1), { headers })
    if (!first.ok) return `NVD a répondu ${first.status}${first.status === 403 || first.status === 429 ? ' (limite de débit — réessayer dans 30 s, ou définir NVD_API_KEY)' : ''}.`
    const total = parseNvd(first.text)?.totalResults ?? 0
    if (total === 0) return `Aucune CVE trouvée dans la NVD pour « ${query} ».`
    // La NVD trie par date de publication croissante : on lit la dernière page.
    const count = Math.min(10, total)
    const last = await $.http.fetch(nvdUrl(query, total - count, count), { headers })
    const page = last.ok ? parseNvd(last.text) : undefined
    return page ? formatCves(query, page) : `Réponse NVD illisible (${last.status}).`
  } catch (err) {
    return `NVD injoignable : ${err instanceof Error ? err.message : String(err)}`
  }
}

// ── Hooks ────────────────────────────────────────────────────────────────

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const ran = await next(e)
    for (const command of COMMANDS) await $.command.register(command)
    void refreshContext($)
    void $.ui.open({ id: PANE, title: 'Journal d’audit' })
    return ran
  })

  on('command.run', { command: 'audit' }, async ($, e) => {
    const arg = e.args.trim()
    if (arg === 'clear') {
      await update($, audit, () => [])
      return { text: 'Journal d’audit vidé.' }
    }
    if (arg === 'export') {
      const list = await read($, audit)
      const home = (await $.env.get('HOME')) ?? '.'
      const path = `${home}/.claude/audit/claude-audit-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.md`
      await $.fs.write(path, toMarkdown(list))
      return { text: `${list.length} action(s) exportée(s) dans ${path}` }
    }
    const { isPlaced } = await $.ui.open({ id: PANE, title: 'Journal d’audit' })
    return { text: isPlaced ? 'Panneau « Journal d’audit » ouvert.' : 'Panneau ouvert (non affiché sur cette surface) — /audit export pour le lire en Markdown.' }
  })

  on('command.run', { command: 'cidr' }, (_$, e) => ({ text: cidr(e.args) }))
  on('command.run', { command: 'port' }, (_$, e) => ({ text: port(e.args) }))
  on('command.run', { command: 'cve' }, async ($, e) => ({ text: await cve($, e.args) }))
  on('command.run', { command: 'contexte' }, async $ => {
    await refreshContext($)
    return { text: kubeContext ? `Contexte kube : ${kubeContext}${PROD.test(kubeContext) ? ' — 🔴 PROD, les commandes qui modifient le cluster seront confirmées' : ''}` : 'Pas de contexte kube actif.' }
  })

  on('tool.call', async ($, e, next) => {
    if (!AUDITED.has(e.tool) && !e.tool.startsWith('mcp__')) return next(e)

    const input = e as unknown as Record<string, unknown>
    const entry: AuditEntry = { id: e.tool_use_id, at: Date.now(), tool: e.tool, summary: summarize(e.tool, input), status: 'runs' }
    await update($, audit, list => [...list, entry].slice(-500))

    // 2. Garde-fou commandes à risque
    if (e.tool === 'Bash' && typeof input.command === 'string') {
      const verdict = assess(input.command, kubeContext)
      if (verdict?.level === 'block') {
        await setStatus($, entry.id, 'denied', verdict.reason)
        return { deny: `bouclier-infra : commande bloquée (${verdict.reason}). Elle n’est pas exécutable via Claude ; si elle est vraiment voulue, l’utilisateur la lance lui-même.` }
      }
      if (verdict?.level === 'ask') {
        let answer = 'Refuser'
        try {
          answer = await $.ui.ask(`⚠ Commande à risque (${verdict.reason}). L’exécuter ?`, ['Refuser', 'Autoriser'])
        } catch {
          // personne pour répondre : on refuse
        }
        if (answer !== 'Autoriser') {
          await setStatus($, entry.id, 'denied', verdict.reason)
          return { deny: `bouclier-infra : l’utilisateur a refusé cette commande (${verdict.reason}).` }
        }
        await setStatus($, entry.id, 'runs', `autorisée : ${verdict.reason}`)
      }
    }

    const ran = await next(e)
    if (ran.deny !== undefined) {
      await setStatus($, entry.id, 'denied', ran.deny.slice(0, 200))
      return ran
    }
    if (ran.isError) {
      await setStatus($, entry.id, 'error')
      return ran
    }
    await setStatus($, entry.id, 'ok')

    // 5. Le contexte a peut-être changé
    if (e.tool === 'Bash' && typeof input.command === 'string' && CONTEXT_CHANGERS.test(input.command)) void refreshContext($)

    // 6. Revue sécu des fichiers infra
    if (WRITES.has(e.tool) && typeof input.file_path === 'string') {
      let text: string | undefined
      try {
        text = await $.fs.read(input.file_path)
      } catch {
        text = undefined
      }
      const found = text === undefined ? undefined : review(input.file_path, text)
      if (found?.findings.length) {
        const serious = found.findings.filter(f => f.severity !== 'info')
        const report = formatFindings(input.file_path, found.findings)
        if (serious.length) {
          await setStatus($, entry.id, 'flagged', serious.map(f => `${ICON[f.severity]} ${f.message}`).join('\n'))
          $.ui.toast(`${serious.length} point(s) sécu dans ${input.file_path.split('/').pop()}`)
        }
        return {
          ...ran,
          context: [...(ran.context ?? []), `${report}\nSignale ces points à l’utilisateur et corrige ceux qui sont dans le périmètre de la demande.`],
        }
      }
    }
    return ran
    // Un bug du mod ne doit jamais bloquer Claude : on laisse passer l'appel
  }).catch(($, e, next) => next(e))

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const list = await read($, audit)
    const room = Math.max(1, (e.viewport?.rows ?? 24) - 5)
    const width = Math.max(20, (e.props.bodyColumns ?? 60) - 16)
    const count = (s: AuditStatus) => list.filter(a => a.status === s).length
    const color = (s: AuditStatus) => (s === 'error' ? 'error' : s === 'denied' || s === 'flagged' ? 'warning' : s === 'ok' ? 'success' : 'inactive')

    return (
      <Box flexDirection="column">
        <Text dimColor>
          {list.length} action(s) · ⛔ {count('denied')} refusée(s) · ⚠ {count('flagged')} signalée(s) · ✗ {count('error')} erreur(s)
        </Text>
        {list.length === 0 && <Text dimColor>Aucune action pour l’instant.</Text>}
        {list.slice(-room).map(a => (
          <Box flexDirection="column">
            <Text color={color(a.status)}>
              {hhmmss(a.at)} {STATUS_LABEL[a.status]} {a.tool.padEnd(5)} {a.summary.length > width ? `${a.summary.slice(0, width - 1)}…` : a.summary}
            </Text>
            {a.note !== undefined && a.status !== 'ok' && <Text dimColor>{'          '}{a.note.split('\n')[0]}</Text>}
          </Box>
        ))}
      </Box>
    )
  })
}
