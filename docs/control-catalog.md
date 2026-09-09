# Control Catalog

| Control ID | Severity | Scope | Condition | Expected remediation |
|---|---|---|---|---|
| IAC-GOV-001 | Medium | All resources | Required `owner` or `environment` tag missing | Add governed ownership and environment metadata |
| IAC-STO-001 | High | Object storage | Public access enabled | Disable public access and require authenticated paths |
| IAC-STO-002 | High | Object storage | Encryption disabled | Enable encryption at rest with governed keys |
| IAC-NET-001 | High | Security groups | SSH/RDP open to the internet | Restrict administration to approved private management paths |
| IAC-DB-001 | Critical | Databases | Public accessibility enabled | Place database on private network paths |
| IAC-DB-002 | High | Databases | Encryption disabled | Enable encryption at rest |
| IAC-IAM-001 | High | IAM policies | Wildcard action or resource | Scope policy to minimum required actions/resources |
| IAC-LOG-001 | High | Audit logging | Logging disabled | Enable protected centralized audit logging |

## Control lifecycle

A mature policy program should assign an owner to each control, version control its logic, document false-positive considerations, test expected pass/fail fixtures, review changes, and define an exception process with expiration.

## Severity philosophy

Severity represents the materiality of the configuration weakness in this lab's synthetic model. It is not a universal rating. Actual severity should account for cloud provider behavior, surrounding controls, data sensitivity, network paths, identity boundaries, and business impact.
