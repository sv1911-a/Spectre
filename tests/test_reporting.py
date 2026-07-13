import unittest

from spectre.core.models import Category, Evidence, Finding, InvestigationReport, PluginResult
from spectre.core.reporting import render_report


class ReportingTests(unittest.TestCase):
    def test_terminal_hides_confidence_by_default(self):
        report = InvestigationReport(
            target="example.com",
            category=Category.TECHNICAL,
            results=[
                PluginResult(
                    plugin="dns_lookup",
                    category=Category.TECHNICAL,
                    target="example.com",
                    status="ok",
                    findings=[
                        Finding(
                            title="DNS intelligence",
                            description="DNS records were found.",
                            category=Category.TECHNICAL,
                            plugin="dns_lookup",
                            confidence=0.93,
                            evidence=[Evidence(source="dns.address", value="1.1.1.1")],
                        )
                    ],
                )
            ],
            metadata={
                "analysis_plan": {
                    "target_type": "domain",
                    "confidence": 0.91,
                    "alternatives": [{"target_type": "plain_text", "confidence": 0.2}],
                }
            },
        )
        rendered = render_report(report, "terminal")
        self.assertIn("Detected:\n  domain", rendered)
        self.assertIn("Other possible interpretations:\n  - plain_text", rendered)
        self.assertNotIn("91%", rendered)
        self.assertNotIn("93%", rendered)


if __name__ == "__main__":
    unittest.main()
