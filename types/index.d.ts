export type AuditStatus = 'runs' | 'ok' | 'error' | 'denied' | 'flagged'

export type AuditEntry = {
  id: string
  at: number
  tool: string
  summary: string
  status: AuditStatus
  note?: string
}

declare module 'claude-code' {
  interface PluginState {
    'bouclier-infra': { audit: AuditEntry[] }
  }
}
