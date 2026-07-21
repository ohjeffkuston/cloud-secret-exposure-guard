To: ohjeffkuston@yahoo.ca
Subject: Day 5 Cloud + AI Project — Cloud Secret Exposure Guard

Hello Jeffrey,

Today’s portfolio project is Cloud Secret Exposure Guard, a deterministic, redaction-first DevSecOps gate for cloud configuration bundles.

Problem and design

Credentials sometimes appear in environment files, CI artifacts, deployment configuration, and infrastructure repositories. A poorly designed scanner can make the incident worse by copying the value into logs, tickets, notifications, or AI prompts. This project detects high-confidence secret assignments and private-key headers while ensuring that reports contain only location, rule, severity, a stable finding ID, and remediation guidance.

Architecture

1. An approved CI or workflow supplies a JSON configuration bundle.
2. Input validation fails closed when evidence is malformed.
3. Deterministic rules scan each line and distinguish placeholders from embedded values.
4. The evaluator returns a redacted PASS/BLOCK report.
5. A human approves rotation, revocation, or repository-history cleanup.

How to deploy safely

- Use a read-only CI checkout and restrict access to the scan job.
- Keep raw files inside the job boundary; publish only the redacted JSON report.
- Protect the blocking workflow with branch rules and reviewed exceptions.
- Integrate a cloud secret manager instead of embedding values in configuration.
- Do not send raw configuration to chat, ticketing, analytics, or an LLM.
- Require human approval for rotation, deletion, history rewriting, and production changes.

How to run

PYTHONPATH=src python -m cloud_secret_exposure_guard examples/config-bundle.json
PYTHONPATH=src python -m unittest discover -s tests -v

What to learn

- How regex-based policy controls create deterministic CI gates.
- Why output redaction is part of the security boundary.
- How placeholder handling reduces false positives.
- Why stable finding IDs should not derive from secret material.
- How to combine deterministic controls with AI summaries safely.

Interview positioning

Use this project to explain that you design automation around both the primary failure and second-order failure modes. A strong interview answer is: “I separated detection from remediation, prevented raw secrets from entering the evidence plane, tested the redaction contract, and kept production-impacting actions behind approval.” Connect that decision to your AWS, Terraform, CI/CD, Python, security, monitoring, and workflow-orchestration experience.

Repository: https://github.com/ohjeffkuston/cloud-secret-exposure-guard
Architecture: https://raw.githubusercontent.com/ohjeffkuston/cloud-secret-exposure-guard/main/docs/architecture.png

Regards,
Jeffrey Ikuoyemwen
