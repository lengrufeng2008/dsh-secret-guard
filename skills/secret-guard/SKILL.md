---
name: secret-guard
description: Scan or redact credentials in text or a local file before sharing. Use secret_scan for redacted findings and secret_redact for a redacted copy. Local-only; not a guarantee that a document is secret-free.
whenToUse: "A prompt, log, diff, or file may contain an API key, token, private key, or credential assignment and must be shared or stored."
---

# Secret guard

```text
Use secret_scan on this text/file.
Use secret_redact on this text/file before sharing.
```

## Rules

GitHub tokens, AWS access keys, OpenAI-style keys, private-key blocks, JWT-like tokens, and long
assigned credential values.

## Limits

- Pattern-based; an unlisted provider or a split/encoded secret may be missed.
- It cannot prove a document has no secrets.
- Do not paste real secrets into a model prompt just to test the scanner; use a disposable fake.
- Redaction changes the text; verify the result before sharing.
