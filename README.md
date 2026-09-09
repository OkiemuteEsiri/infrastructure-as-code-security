# Infrastructure as Code Security

A defensive DevSecOps lab for reviewing infrastructure-as-code plans before deployment. The project demonstrates policy-driven detection of common cloud configuration risks using synthetic Terraform-like plan data, explainable findings, remediation guidance, unit tests, and CI validation.

## Problem

Cloud misconfigurations are cheaper and safer to prevent before deployment than to discover after infrastructure is live. IaC security controls should therefore be deterministic, reviewable, version controlled, and integrated into CI/CD.

This repository implements a lightweight policy engine over a normalized JSON representation of planned infrastructure. It does **not** provision resources or connect to cloud accounts.

## Security controls

The analyzer currently evaluates:

- public object-storage exposure;
- storage encryption at rest;
- unrestricted administrative ingress;
- database public accessibility;
- database encryption;
- overly broad IAM actions/resources;
- mandatory resource tags;
- audit/logging configuration.

## Architecture

```text
Synthetic IaC plan
      |
      v
Schema validation --> Policy Engine --> Findings --> Severity Gate --> Report
                           |                               |
                           +--> control IDs                +--> remediation guidance
```

## Repository structure

```text
.
├── .github/workflows/security.yml
├── data/sample_plan.json
├── docs/
│   ├── architecture.md
│   ├── control-catalog.md
│   └── remediation-validation.md
├── reports/example-assessment.md
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
├── tests/test_analyzer.py
└── README.md
```

## Usage

```bash
python -m src.cli --plan data/sample_plan.json
```

Use a CI severity gate:

```bash
python -m src.cli --plan data/sample_plan.json --fail-on high
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Example finding

```text
HIGH IAC-NET-001 admin-sg: Administrative port exposed to 0.0.0.0/0
```

## Risk classification

| Severity | Typical meaning |
|---|---|
| Critical | Direct material exposure requiring immediate prevention |
| High | Significant security weakness that should block deployment |
| Medium | Important hardening gap requiring remediation or governed exception |
| Low | Defense-in-depth or hygiene improvement |

The included CI example fails on high-or-higher findings in the deliberately insecure synthetic sample only when the CLI is invoked with that threshold. Unit tests validate the policy logic separately.

## Remediation and validation

IaC remediation should be performed in source, reviewed, re-planned, re-scanned, and only then promoted. Production programs should also combine static IaC policy with cloud-native posture validation because runtime drift can invalidate pre-deployment assumptions.

## Security engineering principles

- Shift security controls left without replacing runtime assurance.
- Use explicit control IDs and deterministic policy behavior.
- Treat policy exceptions as governed, expiring risk decisions.
- Avoid hard-coded secrets and sensitive values in IaC.
- Apply least privilege to both deployed resources and CI identities.
- Keep security validation reproducible through automated tests.

## Security and ethics

- Synthetic infrastructure only
- No cloud credentials or tenant identifiers
- No production provisioning
- No destructive actions
- No confidential employer/client data
- No claims of production deployment

## Skills demonstrated

DevSecOps · Infrastructure as Code · Cloud Security · Policy as Code · Python · CI/CD Security · IAM · Network Security · Data Protection · Security Testing

## Limitations

This lab analyzes a deliberately small normalized schema rather than the complete Terraform plan format. Enterprise tools should parse provider schemas, support policy packs, track justified exceptions, validate module provenance, scan state safely, and correlate runtime configuration.

## Roadmap

- Add normalized Kubernetes manifest controls
- Add YAML control configuration
- Add SARIF-style export
- Add exception-expiry workflow
- Add drift-comparison examples

## License

Educational defensive-security portfolio project. See repository license if present.
