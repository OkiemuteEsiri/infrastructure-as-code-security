from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable, Mapping


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    resource: str
    message: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _tags_present(resource: Mapping) -> bool:
    tags = resource.get("tags") or {}
    return all(str(tags.get(key, "")).strip() for key in ("owner", "environment"))


def analyze(resources: Iterable[Mapping]) -> list[Finding]:
    findings: list[Finding] = []

    for resource in resources:
        rtype = str(resource.get("type", "unknown"))
        name = str(resource.get("name", "unnamed"))
        config = resource.get("config") or {}

        if not _tags_present(resource):
            findings.append(Finding(
                "IAC-GOV-001", "medium", name,
                "Required ownership/environment tags are missing",
                "Add non-empty owner and environment tags in source code.",
            ))

        if rtype == "object_storage":
            if bool(config.get("public", False)):
                findings.append(Finding(
                    "IAC-STO-001", "high", name,
                    "Object storage is configured for public access",
                    "Disable public access and use explicit authenticated access paths.",
                ))
            if not bool(config.get("encrypted", False)):
                findings.append(Finding(
                    "IAC-STO-002", "high", name,
                    "Object storage encryption at rest is disabled",
                    "Enable provider-supported encryption using governed key management.",
                ))

        elif rtype == "security_group":
            for rule in config.get("ingress", []):
                port = int(rule.get("port", -1))
                cidr = str(rule.get("cidr", ""))
                if port in {22, 3389} and cidr in {"0.0.0.0/0", "::/0"}:
                    findings.append(Finding(
                        "IAC-NET-001", "high", name,
                        f"Administrative port {port} is exposed to {cidr}",
                        "Restrict administrative access to approved private management paths.",
                    ))

        elif rtype == "database":
            if bool(config.get("publicly_accessible", False)):
                findings.append(Finding(
                    "IAC-DB-001", "critical", name,
                    "Database is configured as publicly accessible",
                    "Place the database on private networks and use controlled application connectivity.",
                ))
            if not bool(config.get("encrypted", False)):
                findings.append(Finding(
                    "IAC-DB-002", "high", name,
                    "Database encryption at rest is disabled",
                    "Enable encryption at rest with governed key management.",
                ))

        elif rtype == "iam_policy":
            actions = {str(v) for v in config.get("actions", [])}
            resources_allowed = {str(v) for v in config.get("resources", [])}
            if "*" in actions or "*" in resources_allowed:
                findings.append(Finding(
                    "IAC-IAM-001", "high", name,
                    "IAM policy contains wildcard action or resource scope",
                    "Replace wildcards with the minimum required actions and resource identifiers.",
                ))

        elif rtype == "audit_logging":
            if not bool(config.get("enabled", False)):
                findings.append(Finding(
                    "IAC-LOG-001", "high", name,
                    "Audit logging is disabled",
                    "Enable audit logging and route logs to a protected central destination.",
                ))

    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.control_id, f.resource))


def should_fail(findings: Iterable[Finding], threshold: str) -> bool:
    threshold_value = SEVERITY_ORDER[threshold.lower()]
    return any(SEVERITY_ORDER[f.severity] >= threshold_value for f in findings)
