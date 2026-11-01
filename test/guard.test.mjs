import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scanText, redactText } from '../src/guard.mjs'
import { apply } from '../plugin/index.js'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const GH = 'ghp_' + 'A'.repeat(36)
const AWS = 'AKIA' + 'B'.repeat(16)
const ASSIGNED = 'api_key = "' + 'C'.repeat(24) + '"'
const TEXT = `hello\n${GH}\n${AWS}\n${ASSIGNED}\n`

test('scan finds credentials but never returns the full secret', () => {
  const findings = scanText(TEXT)
  const rules = new Set(findings.map((f) => f.rule))
  assert.ok(rules.has('github-token'))
  assert.ok(rules.has('aws-key'))
  assert.ok(rules.has('assigned-secret'))
  const dump = JSON.stringify(findings)
  assert.ok(!dump.includes(GH))
  assert.ok(!dump.includes(AWS))
})

test('redaction removes the credential', () => {
  const out = redactText(TEXT)
  assert.ok(!out.includes(GH))
  assert.ok(!out.includes(AWS))
  assert.match(out, /\[REDACTED:github-token\]/)
})

test('CLI and plugin expose scan and redact', () => {
  const scan = spawnSync(process.execPath, [join(ROOT, 'bin/dsh-secret-guard.mjs')], { input: TEXT, encoding: 'utf8' })
  assert.equal(scan.status, 1)
  assert.match(scan.stdout, /GitHub token/)
  const redact = spawnSync(process.execPath, [join(ROOT, 'bin/dsh-secret-guard.mjs'), '--redact'], { input: TEXT, encoding: 'utf8' })
  assert.equal(redact.status, 0)
  assert.ok(!redact.stdout.includes(GH))
  const tools = []
  let factory
  apply({ tools: { register: (tool) => tools.push(tool) }, skills: { registerProvider: (fn) => { factory = fn } } })
  assert.deepEqual(tools.map((t) => t.name), ['secret_scan', 'secret_redact'])
  const found = tools[0].execute({ text: TEXT })
  assert.ok(found instanceof Promise)
  return found.then(async (result) => {
    assert.equal(result.count, 3)
    const provider = factory()
    assert.equal((await provider.list())[0].name, 'secret-guard')
  })
})
