#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { scanText, redactText, renderMarkdown } from '../src/guard.mjs'
const args = process.argv.slice(2)
if (args.includes('--help') || args.includes('-h')) {
  console.log('dsh-secret-guard [--file FILE] [--redact] [--json]\n\nScan stdin/file for credentials, or print a redacted copy. Exit 1 if findings.')
  process.exit(0)
}
const value = (name) => { const i = args.indexOf(name); return i === -1 ? undefined : args[i + 1] }
try {
  const file = value('--file')
  const text = file ? await readFile(file, 'utf8') : await new Promise((resolve) => { let data = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', (c) => { data += c }); process.stdin.on('end', () => resolve(data)) })
  if (args.includes('--redact')) { process.stdout.write(redactText(text)); process.exitCode = 0 }
  else {
    const findings = scanText(text)
    if (args.includes('--json')) console.log(JSON.stringify({ findings, count: findings.length }, null, 2))
    else console.log(renderMarkdown(findings))
    process.exitCode = findings.length ? 1 : 0
  }
} catch (error) { console.error(`dsh-secret-guard: ${error.message}`); process.exitCode = 2 }
