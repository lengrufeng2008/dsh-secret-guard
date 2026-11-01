// DSH host plugin: local secret scan/redact. Never returns the full secret.
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scanText, redactText, renderMarkdown } from '../src/guard.mjs'
const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url))
const SKILL_PATH = join(PLUGIN_DIR, '..', 'skills', 'secret-guard', 'SKILL.md')
const PROVIDER = 'dsh-secret-guard'
export const name = 'secret-guard'
export const inject = ['tools', 'skills']
function stripFrontmatter(text) { if (!text.startsWith('---\n')) return text; const end = text.indexOf('\n---\n', 4); return end === -1 ? text : text.slice(end + 5) }
const summary = {
  name: 'secret-guard', description: 'Local secret scan and redaction for prompts, logs, and files. Findings are redacted; never sends data anywhere.',
  whenToUse: 'Before sharing a prompt, log, diff, or file that may contain credentials, or when a redaction step is needed.',
  invocation: { modelInvocable: true, userInvocable: true }, source: 'bundled', provider: PROVIDER,
  resourceBase: { kind: 'directory', path: join(PLUGIN_DIR, '..', 'skills', 'secret-guard') },
  rank: 600, locator: 'secret-guard', metadata: { domain: 'security', version: '0.1.0' },
}
export function apply(ctx) {
  ctx.tools.register({
    name: 'secret_scan', description: 'Scan text or a local file for credentials and return redacted findings. No network; never returns the full secret. Not a guarantee that a document is secret-free.',
    parameters: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' }, file: { type: 'string' } } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { markdown: { type: 'string' }, count: { type: 'integer' }, findings: { type: 'string' } }, required: ['markdown', 'count', 'findings'] }, render: (_a, v) => [{ type: 'text', text: v.markdown }] },
    timeoutMs: 15_000,
    async execute(args = {}) {
      let text = args.text
      if (!text && args.file) text = await readFile(args.file, 'utf8')
      if (typeof text !== 'string') throw new Error('text or file is required')
      const findings = scanText(text)
      return { markdown: renderMarkdown(findings), count: findings.length, findings: JSON.stringify(findings) }
    },
  })
  ctx.tools.register({
    name: 'secret_redact', description: 'Return text with detected credentials replaced by rule markers. No network; the original secret is not echoed.',
    parameters: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' }, file: { type: 'string' } } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { markdown: { type: 'string' }, redacted: { type: 'string' } }, required: ['markdown', 'redacted'] }, render: (_a, v) => [{ type: 'text', text: v.markdown }] },
    timeoutMs: 15_000,
    async execute(args = {}) {
      let text = args.text
      if (!text && args.file) text = await readFile(args.file, 'utf8')
      if (typeof text !== 'string') throw new Error('text or file is required')
      const redacted = redactText(text)
      return { markdown: redacted, redacted }
    },
  })
  ctx.skills.registerProvider(() => ({ name: PROVIDER, async list() { return [summary] }, async get(candidate) { if (candidate?.name !== 'secret-guard') return undefined; return { ...summary, content: stripFrontmatter(await readFile(SKILL_PATH, 'utf8')) } } }))
}
