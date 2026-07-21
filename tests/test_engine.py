import unittest

from cloud_secret_exposure_guard import audit_bundle


class GuardTests(unittest.TestCase):
    def test_clean_bundle_passes(self):
        result = audit_bundle({"files": [{"path": "app.env", "content": "LOG_LEVEL=INFO"}]})
        self.assertEqual(result["decision"], "PASS")

    def test_aws_secret_is_critical(self):
        result = audit_bundle({"files": [{"path": "app.env", "content": "AWS_SECRET_ACCESS_KEY=not-a-real-secret-value"}]})
        self.assertEqual(result["highest_severity"], "CRITICAL")

    def test_password_is_high(self):
        result = audit_bundle({"files": [{"path": "db.conf", "content": "password=unsafe-demo-value"}]})
        self.assertEqual(result["highest_severity"], "HIGH")

    def test_placeholder_is_ignored(self):
        result = audit_bundle({"files": [{"path": "template.env", "content": "PASSWORD=${SECRET}"}]})
        self.assertEqual(result["finding_count"], 0)

    def test_private_key_header_is_detected(self):
        result = audit_bundle({"files": [{"path": "key.pem", "content": "-----BEGIN PRIVATE KEY-----"}]})
        self.assertEqual(result["findings"][0]["rule"], "PRIVATE_KEY")

    def test_output_never_contains_secret_value(self):
        secret = "unsafe-demo-password-value"
        result = audit_bundle({"files": [{"path": "db.conf", "content": f"password={secret}"}]})
        self.assertNotIn(secret, str(result))
        self.assertEqual(result["findings"][0]["evidence"], "[REDACTED]")

    def test_fingerprint_is_deterministic(self):
        payload = {"files": [{"path": "app.env", "content": "api_token=unsafe-demo-token"}]}
        self.assertEqual(audit_bundle(payload)["findings"][0]["id"], audit_bundle(payload)["findings"][0]["id"])

    def test_invalid_input_fails_closed(self):
        with self.assertRaises(ValueError):
            audit_bundle({"files": []})


if __name__ == "__main__":
    unittest.main()

