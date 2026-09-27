import unittest
from types import SimpleNamespace

from network.analyzer import analyze_request_details, mask_evidence_value


def request(body: str, content_type: str = "application/x-www-form-urlencoded"):
    return SimpleNamespace(
        headers={"content-type": content_type},
        content=body.encode("utf-8"),
    )


class AnalyzerTests(unittest.TestCase):
    def test_phone_field_is_detected_and_masked(self):
        findings, evidence = analyze_request_details(request("name=test&phone=%2B31%206%2012345678"))

        self.assertIn("PHONE", findings)
        phone = next(item for item in evidence if item["type"] == "PHONE")
        self.assertNotIn("12345678", phone["value"])
        self.assertTrue(phone["value"].endswith("78"))

    def test_ordinary_telemetry_does_not_look_like_phone(self):
        findings, _ = analyze_request_details(
            request("event=application_started&version=1.0&session=123456")
        )

        self.assertNotIn("PHONE", findings)

    def test_password_and_email_evidence_are_redacted(self):
        self.assertEqual(mask_evidence_value("PASSWORD", "super-secret"), "[скрыто]")
        self.assertEqual(mask_evidence_value("EMAIL", "alice@example.org"), "a••••@example.org")


if __name__ == "__main__":
    unittest.main()
