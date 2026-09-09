# Remediation and Validation

## Secure change workflow

1. Identify the failing control and affected resource in the plan.
2. Modify the IaC source, not only the deployed resource.
3. Re-run formatting, validation, plan generation, and security analysis.
4. Review the resulting diff and security findings.
5. Obtain normal code-review approval.
6. Promote only after required security gates pass.
7. Validate the deployed runtime state using cloud-native or posture-management controls.

## Examples

- **Public storage:** disable public access, apply authenticated access policy, re-plan, re-scan, then verify runtime public-access blocks.
- **Open administrative ingress:** remove internet-wide CIDRs and route administration through approved management paths; validate effective network policy after deployment.
- **Wildcard IAM:** enumerate required actions/resources and re-test the workload under least privilege.
- **Public database:** move to private connectivity and verify no public endpoint or broad network route remains.
- **Disabled audit logging:** enable logging, protect destination storage, and confirm events are actually received.

## Exception governance

A deployment exception should include the control ID, resource, risk statement, accountable owner, compensating controls, approval, expiry date, and re-review trigger. Exceptions should be represented as data and should never silently suppress findings forever.

## Validation principle

A successful static scan proves only that the analyzed source/plan satisfies the implemented controls. It does not prove that runtime infrastructure is secure or drift-free. Production assurance requires both pre-deployment and post-deployment validation.
