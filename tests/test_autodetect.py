import tempfile
import unittest
from pathlib import Path

from spectre.core.autodetect import plan_analysis
from spectre.core.models import Category


class AutoDetectTests(unittest.TestCase):
    def test_file_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"hello")
            plan = plan_analysis(str(path))
            self.assertEqual(plan.category, Category.FILE)
            self.assertEqual(plan.plugins, ["file_analysis"])

    def test_domain_plan(self):
        plan = plan_analysis("example.com")
        self.assertEqual(plan.target_type, "domain")
        self.assertEqual(plan.category, Category.TECHNICAL)

    def test_ip_plan(self):
        plan = plan_analysis("8.8.8.8")
        self.assertEqual(plan.target_type, "ip_address")
        self.assertEqual(plan.category, Category.TECHNICAL)

    def test_hash_plan(self):
        plan = plan_analysis("5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(plan.target_type, "hash")
        self.assertEqual(plan.plugins, ["hash_identifier"])

    def test_github_repo_plan(self):
        plan = plan_analysis("https://github.com/python/cpython")
        self.assertEqual(plan.target_type, "github_repository")
        self.assertEqual(plan.plugins, ["github_repo_analysis"])

    def test_ambiguous_username_rot13_has_alternatives(self):
        plan = plan_analysis("uryyb")
        self.assertEqual(plan.target_type, "username")
        alternative_types = {item["target_type"] for item in plan.alternatives}
        self.assertIn("rot13_text", alternative_types)

    def test_base32_like_text_prefers_crypto(self):
        plan = plan_analysis("JBSWY3DP")
        self.assertEqual(plan.target_type, "encoded_or_ciphertext")
        alternative_types = {item["target_type"] for item in plan.alternatives}
        self.assertIn("username", alternative_types)


if __name__ == "__main__":
    unittest.main()
