# Architecture

## Objective

Evaluate planned infrastructure against deterministic security controls before deployment, while keeping the lab isolated from real cloud accounts.

## Flow

1. A normalized JSON plan contains resource type, name, tags, and security-relevant configuration.
2. The analyzer dispatches type-specific controls.
3. Each control emits a finding containing control ID, severity, resource, message, and remediation.
4. Findings are sorted by severity and control ID.
5. The CLI can optionally fail a pipeline when findings meet or exceed a configured threshold.

## Design choices

- **Normalized schema:** keeps the project readable and provider-neutral.
- **Deterministic controls:** every finding can be reproduced from input data.
- **Explicit remediation:** findings are actionable rather than merely descriptive.
- **No cloud SDK:** prevents accidental dependency on credentials or live infrastructure.
- **CI-first testing:** policy changes are unit tested before they influence a security gate.

## Production extensions

A production implementation should support native Terraform plan JSON, provider-specific schemas, exception metadata, signed policy releases, SARIF or equivalent findings export, module/source provenance, secret detection, state-file handling controls, and runtime drift correlation.
