import unittest
from unittest.mock import patch
import tempfile
import yaml

from website_security_scanner.cli.cli import SecurityScannerCLI, main


class TestCLI(unittest.TestCase):
    def test_load_config(self):
        config_data = {"scanner": {"timeout": 5}, "targets": {"custom": ["https://example.com"]}}
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as tmp:
            yaml.safe_dump(config_data, tmp)
            tmp.flush()

            cli = SecurityScannerCLI()
            loaded = cli.load_config(tmp.name)

        self.assertEqual(loaded.get("scanner", {}).get("timeout"), 5)

    def test_main_single_url(self):
        with patch("website_security_scanner.cli.cli.SecurityScannerCLI.scan_single_url") as scan_single, \
             patch("website_security_scanner.cli.cli.SecurityScannerCLI.save_results") as save_results, \
             patch("website_security_scanner.cli.cli.SecurityScannerCLI.print_banner"):
            scan_single.return_value = {"url": "https://example.com", "vulnerabilities": []}

            test_argv = ["wss", "--url", "https://example.com", "--output", "report.json"]
            with patch("sys.argv", test_argv):
                main()

            scan_single.assert_called_once()
            save_results.assert_called_once()


if __name__ == "__main__":
    unittest.main()
