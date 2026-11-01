# Secret Guard for DSH

> Local-only credential scan and redaction for prompts, logs, diffs, and files. Findings are
> redacted; the full secret is never returned.

## Use

```bash
node bin/dsh-secret-guard.mjs --file notes.txt
cat notes.txt | node bin/dsh-secret-guard.mjs --redact
```

In DSH:

```text
Use secret_scan on this text.
Use secret_redact before sharing this file.
```

## Rules

GitHub tokens, AWS keys, OpenAI-style keys, private-key blocks, JWT-like tokens, and assigned
credential values.

## Limits

- Pattern-based, not entropy/AST/secret-manager integration.
- A clean scan is not proof that a document is secret-free.
- Redaction can break syntax; review the result.
- No network, no telemetry, no write to disk.

## Tests

```bash
npm test
```

Test tokens are constructed at runtime; no real credential is committed.

## Provenance

A small independent scanner. Inspired by common secret-scanning practice; no source copied.
License: MIT.
