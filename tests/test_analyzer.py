import unittest

from src.analyzer import analyze, should_fail


class IaCAnalyzerTests(unittest.TestCase):
    def test_public_unencrypted_storage_generates_findings(self):
        resources = [{
            "type": "object_storage",
            "name": "bucket",
            "tags": {"owner": "platform", "environment": "lab"},
            "config": {"public": True, "encrypted": False},
        }]
        findings = analyze(resources)
        control_ids = {f.control_id for f in findings}
        self.assertIn("IAC-STO-001", control_ids)
        self.assertIn("IAC-STO-002", control_ids)

    def test_open_admin_port_is_high(self):
        resources = [{
            "type": "security_group",
            "name": "admin",
            "tags": {"owner": "ops", "environment": "lab"},
            "config": {"ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]},
        }]
        findings = analyze(resources)
        finding = next(f for f in findings if f.control_id == "IAC-NET-001")
        self.assertEqual(finding.severity, "high")

    def test_private_encrypted_storage_is_clean(self):
        resources = [{
            "type": "object_storage",
            "name": "private",
            "tags": {"owner": "ops", "environment": "lab"},
            "config": {"public": False, "encrypted": True},
        }]
        self.assertEqual(analyze(resources), [])

    def test_missing_tags_are_reported(self):
        resources = [{"type": "audit_logging", "name": "audit", "config": {"enabled": True}}]
        findings = analyze(resources)
        self.assertTrue(any(f.control_id == "IAC-GOV-001" for f in findings))

    def test_high_threshold_gate(self):
        resources = [{
            "type": "iam_policy",
            "name": "wide",
            "tags": {"owner": "devops", "environment": "lab"},
            "config": {"actions": ["*"], "resources": ["resource-1"]},
        }]
        findings = analyze(resources)
        self.assertTrue(should_fail(findings, "high"))
        self.assertFalse(should_fail(findings, "critical"))

    def test_public_database_is_critical(self):
        resources = [{
            "type": "database",
            "name": "db",
            "tags": {"owner": "data", "environment": "lab"},
            "config": {"publicly_accessible": True, "encrypted": True},
        }]
        findings = analyze(resources)
        finding = next(f for f in findings if f.control_id == "IAC-DB-001")
        self.assertEqual(finding.severity, "critical")


if __name__ == "__main__":
    unittest.main()
