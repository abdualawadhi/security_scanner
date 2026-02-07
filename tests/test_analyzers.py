import unittest
import requests

from website_security_scanner.analyzers.factory import (
    get_analyzer_for_platform,
    validate_platform_type,
)
from website_security_scanner.analyzers.generic import GenericWebAnalyzer
from website_security_scanner.analyzers.bubble import BubbleAnalyzer


class TestAnalyzerFactory(unittest.TestCase):
    def test_get_analyzer_for_platform(self):
        session = requests.Session()
        analyzer = get_analyzer_for_platform("bubble", session)
        self.assertIsInstance(analyzer, BubbleAnalyzer)

        analyzer = get_analyzer_for_platform("unknown-platform", session)
        self.assertIsInstance(analyzer, GenericWebAnalyzer)

    def test_validate_platform_type(self):
        self.assertTrue(validate_platform_type("bubble.io"))
        self.assertFalse(validate_platform_type("unknown"))


if __name__ == "__main__":
    unittest.main()
