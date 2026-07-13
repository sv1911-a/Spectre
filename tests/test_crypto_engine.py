import unittest

from spectre.crypto_engine import SmartCryptoEngine


class SmartCryptoEngineTests(unittest.TestCase):
    def test_base64_decode(self):
        report = SmartCryptoEngine().run("SGVsbG8=")
        best = report.results[0].raw["best"]
        self.assertEqual(best["value"], "Hello")
        self.assertEqual(best["path"], ["base64_decoder"])

    def test_nested_hex_base64_decode(self):
        report = SmartCryptoEngine().run("534756736247383d")
        best = report.results[0].raw["best"]
        self.assertEqual(best["value"], "Hello")
        self.assertEqual(best["path"], ["hex_decoder", "base64_decoder"])

    def test_base32_decode(self):
        report = SmartCryptoEngine().run("JBSWY3DP")
        best = report.results[0].raw["best"]
        self.assertEqual(best["value"], "Hello")
        self.assertEqual(best["path"], ["base32_decoder"])


if __name__ == "__main__":
    unittest.main()
