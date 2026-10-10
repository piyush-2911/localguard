import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from click.testing import CliRunner
from scan.cli import main
from scan.hybrid import run_hybrid
from scan.merge import merge_findings
from scan.models import Finding, Severity
from scan.report import render_json, render_markdown, render_text
from scan.scanner import ScanError


def static(line=10, **kwargs):
    return replace(Finding("app.py", line, Severity.MEDIUM, "command-injection",
                           "Static explanation", "Static fix", "B602", code_snippet="call(cmd)"), **kwargs)


def llm(line=10, **kwargs):
    return replace(Finding("app.py", line, Severity.HIGH, "command-injection",
                           "LLM explanation", "LLM fix", "LLM", source="llm"), **kwargs)


class MergeTests(unittest.TestCase):
    def test_exact_and_severity(self):
        a, b = static(), llm()
        result = merge_findings([a], [b])
        self.assertEqual(len(result), 1)
        f = result[0]
        self.assertEqual((f.source, f.confidence), ("static+llm", "confirmed"))
        self.assertEqual((f.rule_id, f.code_snippet), ("B602", "call(cmd)"))
        self.assertEqual((f.description, f.recommendation), ("LLM explanation", "LLM fix"))
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.original_severities, {"static": "medium", "llm": "high"})
        self.assertEqual(a.description, "Static explanation")

    def test_tolerance_boundary(self):
        self.assertEqual(len(merge_findings([static()], [llm(13)])), 1)
        self.assertEqual(len(merge_findings([static()], [llm(14)])), 2)
        self.assertEqual(len(merge_findings([static()], [llm(11)], 0)), 2)

    def test_ranges(self):
        self.assertEqual(len(merge_findings([static(end_line=20)], [llm(23)])), 1)
        self.assertEqual(len(merge_findings([static(end_line=20)], [llm(24)])), 2)

    def test_different_categories_and_files(self):
        self.assertEqual(len(merge_findings([static()], [llm(category="sql-injection")])), 2)
        self.assertEqual(len(merge_findings([static()], [llm(file="other.py")])), 2)

    def test_overlap_duplicates(self):
        self.assertEqual(len(merge_findings([], [llm(), llm(description="Reworded finding")])) , 1)
        self.assertEqual(len(merge_findings([static(), static()], [])), 1)
        self.assertEqual(len(merge_findings([static(), static(11)], [])), 2)

    def test_no_transitive_matching(self):
        self.assertEqual(len(merge_findings([static(10), static(16)], [llm(13)])), 2)

    def test_higher_static_severity(self):
        f = merge_findings([static(severity=Severity.CRITICAL)], [llm()])[0]
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.original_severities["llm"], "high")

    def test_normalization_and_sorting(self):
        result = merge_findings([static()], [llm(), llm(50), llm(90, category="invented")])
        self.assertEqual(result[0].confidence, "confirmed")
        self.assertEqual(result[-1].category, "other")
        self.assertEqual(result[-1].confidence, "needs-review")

    def test_reports(self):
        findings = merge_findings([static()], [llm()])
        metadata = {"analyzers": {"llm": "LLM analysis unavailable"},
                    "analyzer_contributions": {"static": 1, "llm": 1}}
        for rendered in (render_text(findings, 1, "app.py", True, metadata),
                         render_markdown(findings, 1, "app.py", True, metadata)):
            self.assertIn("Static explanation", rendered)
            self.assertIn("LLM explanation", rendered)
            self.assertIn("confirmed", rendered)
            self.assertIn("LLM analysis unavailable", rendered)
        data = json.loads(render_json(findings, 1, "app.py", metadata))
        self.assertEqual(data["counts_by_confidence"]["confirmed"], 1)

    def test_fallback_and_both_failed(self):
        def fail():
            raise ScanError("Unavailable")
        findings, _, meta = run_hybrid(lambda: ([static()], 1), fail)
        self.assertEqual(findings[0].confidence, "likely")
        self.assertEqual(meta["analyzers"]["llm"], "LLM analysis unavailable")
        findings, _, meta = run_hybrid(fail, lambda: ([llm()], 1))
        self.assertEqual(findings[0].confidence, "needs-review")
        with self.assertRaises(ScanError):
            run_hybrid(fail, fail)

    def test_cli_default_and_filter_exit(self):
        with patch("scan.cli.scan", return_value=([static()], 1)), \
             patch("scan.llm.ReviewClient"), patch("scan.llm.scan_llm", return_value=([llm()], 1)):
            result = CliRunner().invoke(main, ["scan", "app.py", "--format", "json"])
            self.assertEqual(result.exit_code, 1, result.output)
            self.assertEqual(json.loads(result.stdout)["findings"][0]["source"], "static+llm")
        with patch("scan.cli.scan", return_value=([], 1)), \
             patch("scan.llm.ReviewClient"), patch("scan.llm.scan_llm", return_value=([llm()], 1)):
            result = CliRunner().invoke(main, ["scan", "app.py", "--min-confidence", "likely", "--format", "json"])
            self.assertEqual(result.exit_code, 0, result.output)

    def test_cli_conflicting_modes(self):
        result = CliRunner().invoke(main, ["scan", "app.py", "--static-only", "--llm-only"])
        self.assertEqual(result.exit_code, 2)

    def test_cli_fallback_in_all_formats(self):
        for format_name in ("json", "text", "markdown"):
            with patch("scan.cli.scan", return_value=([static()], 1)), \
                 patch("scan.llm.ReviewClient"), patch("scan.llm.scan_llm", side_effect=ScanError("Connection lost mid-scan")):
                result = CliRunner().invoke(main, ["scan", "app.py", "--format", format_name])
            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("LLM analysis unavailable", result.stdout)
            self.assertIn("Connection lost mid-scan", result.stderr)
            self.assertIn("likely", result.stdout)

    def test_cli_reverse_fallback_and_both_failed(self):
        with patch("scan.cli.scan", side_effect=ScanError("Bandit missing")), \
             patch("scan.llm.ReviewClient"), patch("scan.llm.scan_llm", return_value=([llm()], 1)):
            result = CliRunner().invoke(main, ["scan", "app.py", "--format", "json"])
            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("Static analysis unavailable", result.stdout)
            self.assertEqual(json.loads(result.stdout)["findings"][0]["confidence"], "needs-review")
        with patch("scan.cli.scan", side_effect=ScanError("Bandit missing")), \
             patch("scan.llm.ReviewClient", side_effect=ScanError("LLM down")):
            result = CliRunner().invoke(main, ["scan", "app.py", "--format", "json"])
            self.assertEqual(result.exit_code, 2)
            self.assertNotIn('"findings"', result.stdout)

    def test_confidence_and_severity_filters(self):
        with patch("scan.cli.scan", return_value=([static()], 1)), \
             patch("scan.llm.ReviewClient"), patch("scan.llm.scan_llm", return_value=([llm()], 1)):
            result = CliRunner().invoke(main, ["scan", "app.py", "--format", "json",
                                              "--min-confidence", "confirmed", "--severity-threshold", "critical"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(json.loads(result.stdout)["total_findings"], 0)

    def test_static_taxonomy(self):
        expected = {"B102": "code-injection", "B301": "insecure-deserialization",
                    "B602": "command-injection", "B105": "hardcoded-secret", "B324": "weak-crypto"}
        for rule, category in expected.items():
            self.assertEqual(merge_findings([static(rule_id=rule)], [])[0].category, category)


if __name__ == "__main__":
    unittest.main()
