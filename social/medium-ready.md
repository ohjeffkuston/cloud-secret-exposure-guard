# Building a Redaction-First Cloud Secret Exposure Guard

Credentials can leak into `.env` files, deployment configuration, CI artifacts, and infrastructure repositories. The obvious response is to scan for them. The less obvious risk is that the scanner may repeat the matched value into logs, tickets, notifications, or AI prompts—creating several new copies of the secret while reporting the first one.

That failure mode shaped the design of Cloud Secret Exposure Guard: a deterministic DevSecOps gate that reports enough evidence to act, without returning the exposed value.

![Cloud Secret Exposure Guard architecture](https://raw.githubusercontent.com/ohjeffkuston/cloud-secret-exposure-guard/main/docs/architecture.png)

## What the project does

The evaluator accepts a JSON bundle containing file paths and text content. It validates the evidence, checks high-confidence credential assignments and private-key headers, and returns a `PASS` or `BLOCK` decision.

Each finding contains a file, line number, rule, severity, stable identifier, and remediation guidance. Evidence is always `[REDACTED]`. The raw value is never returned, logged, hashed, or copied to an external system.

Explicit managed-secret placeholders such as `${SECRET}` are ignored. That matters because a reference to a secret store is fundamentally different from embedding a credential value in the file.

## Architecture and safety boundary

The architecture separates four responsibilities:

1. A CI job or approved workflow supplies a configuration bundle.
2. Schema validation and deterministic rules evaluate it.
3. A redacted report presents severity and location evidence.
4. A human controls credential rotation, revocation, and repository-history cleanup.

The project never performs those remediation actions automatically. Rotation and history rewriting can affect production availability and auditability, so the evaluator deliberately stops at a reviewable decision.

## Why deterministic rules still matter in an AI-first workflow

AI can summarize findings, explain remediation, and help an engineer navigate a large repository. It should not decide whether a raw secret value is safe to expose in another system. The detection and redaction contract is deterministic and testable; AI remains downstream of sanitized evidence.

The repository includes eight unit tests, a GitHub Actions workflow, synthetic sample data, a committed architecture image, and an inactive n8n example that preserves the human-review boundary.

## Run it

```bash
PYTHONPATH=src python -m cloud_secret_exposure_guard examples/config-bundle.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

The broader lesson is simple: a security automation should be evaluated not only on what it detects, but also on what sensitive data it creates, stores, and forwards during detection.

Project repository: https://github.com/ohjeffkuston/cloud-secret-exposure-guard

