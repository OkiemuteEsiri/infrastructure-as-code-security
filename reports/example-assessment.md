# Example IaC Security Assessment

Synthetic demonstration only.

## Summary

The sample plan intentionally contains multiple policy failures so the analyzer and remediation workflow can be demonstrated safely.

| Severity | Control | Resource | Finding |
|---|---|---|---|
| Critical | IAC-DB-001 | orders-db | Database configured as publicly accessible |
| High | IAC-STO-001 | public-artifacts | Public object-storage access enabled |
| High | IAC-STO-002 | public-artifacts | Storage encryption disabled |
| High | IAC-NET-001 | admin-sg | SSH exposed to the internet |
| High | IAC-DB-002 | orders-db | Database encryption disabled |
| High | IAC-IAM-001 | build-role-policy | Wildcard IAM scope |
| High | IAC-LOG-001 | central-audit | Audit logging disabled |

## Risk interpretation

The database exposure is the strongest deployment-blocking condition because it creates a direct externally reachable data-service path in the synthetic design. Broad administrative ingress and wildcard IAM materially increase attack surface and privilege risk. Encryption and logging gaps reduce data-protection and investigation capability.

## Recommended validation sequence

1. Correct the IaC source.
2. Generate a new plan.
3. Re-run the analyzer and unit tests.
4. Review the plan diff.
5. Deploy only after policy requirements are met or a governed exception exists.
6. Verify the resulting runtime configuration and audit telemetry.

No finding in this report refers to a real cloud environment.
