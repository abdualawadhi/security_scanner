import unittest
from unittest.mock import patch

from website_security_scanner.main import LowCodeSecurityScanner


class FakeElapsed:
    def __init__(self, seconds=0.1):
        self._seconds = seconds

    def total_seconds(self):
        return self._seconds


class FakeResponse:
    def __init__(self, status_code=200, headers=None, content=b"", text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.text = text
        self.elapsed = FakeElapsed(0.1)
        self.request = type("Req", (), {"method": "GET", "url": "https://example.com", "path_url": "/", "headers": {}})()


class TestLowCodeSecurityScanner(unittest.TestCase):
    def test_normalize_and_dedupe(self):
        scanner = LowCodeSecurityScanner()
        raw = [
            {"type": "XSS", "severity": "high", "evidence": "a"},
            {"type": "XSS", "severity": "high", "evidence": "a"},
        ]
        normalized = scanner._normalize_vulnerabilities(raw, "https://example.com")
        deduped = scanner._dedupe_vulnerabilities(normalized)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["severity"], "High")

    def test_scan_target_skips_non_scannable(self):
        scanner = LowCodeSecurityScanner()
        fake_response = FakeResponse(status_code=500, headers={"Content-Type": "text/html"})

        with patch.object(scanner, "identify_platform", return_value="generic"), \
             patch.object(scanner, "analyze_security_headers", return_value={"security_score": "0/8"}), \
             patch.object(scanner, "analyze_ssl", return_value={"error": "Not using HTTPS"}), \
             patch.object(scanner, "_is_scannable_response", return_value=False), \
             patch.object(scanner.session, "get", return_value=fake_response):
            result = scanner.scan_target("https://example.com")

        self.assertTrue(result.get("analysis_skipped"))
        self.assertTrue(result.get("verification_summary", {}).get("disabled"))


if __name__ == "__main__":
    unittest.main()
