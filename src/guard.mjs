// Local-only secret detection and redaction. Findings never include the full secret.
const RULES = [
  { id: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, label: 'GitHub token' },
  { id: 'aws-key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, label: 'AWS access key' },
  { id: 'openai-key', pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b/, label: 'API key' },
  { id: 'private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, label: 'Private key block' },
  { id: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, label: 'JWT-like token' },
  { id: 'assigned-secret', pattern: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_./+=-]{20,}['"]/i, label: 'Assigned credential' },
]

function lineOf(text, index) { return text.slice(0, index).split('\n').length }
export function scanText(text) {
  if (typeof text !== 'string') throw new Error('text must be a string')
  const findings = []
  for (const rule of RULES) {
    const global = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g')
    let match
    while ((match = global.exec(text)) !== null) {
      findings.push({ rule: rule.id, label: rule.label, line: lineOf(text, match.index), preview: match[0].slice(0, 4) + '…' + `(${match[0].length} chars)` })
      if (match.index === global.lastIndex) global.lastIndex += 1
    }
  }
  return findings
}
export function redactText(text) {
  let out = String(text)
  for (const rule of RULES) {
    out = out.replace(new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g'), `[REDACTED:${rule.id}]`)
  }
  return out
}
export function renderMarkdown(findings) {
  if (!findings.length) return 'No secrets found under these patterns. This is not a guarantee.'
  return `${findings.length} finding${findings.length === 1 ? '' : 's'}:\n` + findings.map((f) => `- ${f.label} (${f.rule}) line ${f.line} — ${f.preview}`).join('\n')
}
