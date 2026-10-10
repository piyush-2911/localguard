import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock
import httpx
from openai import APIConnectionError, APITimeoutError

from click.testing import CliRunner

from scan.cli import main
from scan.llm import Chunk, ReviewClient, code_chunks, parse_review, python_files, scan_llm
from scan.scanner import ScanError


def finding(line=1):
    return {"line": line, "severity": "high", "category": "access_control",
            "description": "User-supplied owner is trusted", "recommendation": "Check authenticated ownership",
            "evidence": "x"}


class ReviewerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                cls.request_path = self.path
                cls.auth = self.headers.get("Authorization")
                cls.payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(cls.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(cls.response).encode())

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        type(self).status = 200
        self.set_content(json.dumps([finding()]))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "app.py"
        self.path.write_text("x\n", encoding="utf-8")

    def set_content(self, content, finish="stop"):
        type(self).response = {"choices": [{"finish_reason": finish, "message": {"content": content}}]}

    def invoke(self, *args):
        return CliRunner().invoke(main, ["scan", str(self.path), "--llm-only", "--model",
                                        "test-model", "--base-url", self.url, *args])

    def test_real_http_cli_without_bandit(self):
        with patch("scan.cli.scan", side_effect=AssertionError("Bandit invoked")):
            result = self.invoke("--format", "json", "--api-key", "test-secret")
        self.assertEqual(result.exit_code, 1, result.output)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings"][0]["source"], "llm")
        self.assertEqual(report["findings"][0]["recommendation"], finding()["recommendation"])
        self.assertEqual(self.request_path, "/v1/chat/completions")
        self.assertEqual(self.auth, "Bearer test-secret")
        self.assertNotIn("response_format", self.payload)
        self.assertEqual(self.payload["max_tokens"], 1024)
        self.assertIn("at most 10 highest-impact findings", self.payload["messages"][1]["content"])
        self.assertIn("1: x", self.payload["messages"][1]["content"])
        self.assertIn("Reviewing", result.stderr)
        self.assertIn("Request finished", result.stderr)

    def test_clean_threshold_and_no_json_mode(self):
        result = self.invoke("--severity-threshold", "critical", "--format", "json")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("response_format", self.payload)
        self.set_content('[]')
        self.assertEqual(self.invoke().exit_code, 0)

    def test_bad_response_warns_and_continues(self):
        for content in ("not JSON", "{}", '{"findings": null}', '{"findings": [null]}'):
            with self.subTest(content=content):
                self.set_content(content)
                result = self.invoke("--format", "json")
                self.assertEqual(result.exit_code, 2 if content == '{"findings": [null]}' else 0, result.output)
                self.assertIn("Skipping ", result.stderr)
                if result.exit_code == 0:
                    self.assertEqual(json.loads(result.stdout)["total_findings"], 0)

    def test_http_and_truncation_errors(self):
        for status in (401, 404, 429, 500, 302):
            type(self).status = status
            result = self.invoke("--api-key", "private-value")
            self.assertEqual(result.exit_code, 2)
            self.assertIn(f"HTTP {status}", result.output)
            self.assertNotIn("private-value", result.output)
        type(self).status = 200
        self.set_content('[]', finish="length")
        self.assertEqual(self.invoke().exit_code, 0)

    def test_missing_model_and_invalid_url(self):
        result = CliRunner().invoke(main, ["scan", str(self.path), "--llm-only"], env={"SCAN_MODEL": ""})
        self.assertEqual(result.exit_code, 2)
        for url in ("file:///tmp", "http://user:secret@localhost/v1", "http://localhost:bad/v1"):
            with self.assertRaises(ScanError):
                ReviewClient(url, "model")

    def test_environment_and_file_output(self):
        output = Path(self.temp.name) / "report.md"
        result = CliRunner().invoke(main, ["scan", str(self.path), "--llm-only", "--format", "markdown",
                                         "--output", str(output)], env={"SCAN_MODEL": "env-model",
                                         "SCAN_BASE_URL": self.url, "SCAN_API_KEY": "env-key"})
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("access-control", output.read_text(encoding="utf-8"))
        self.assertEqual(self.payload["model"], "env-model")
        self.assertEqual(self.auth, "Bearer env-key")

    def test_static_only(self):
        with patch("scan.cli.scan", return_value=([], 1)) as static:
            result = CliRunner().invoke(main, ["scan", str(self.path), "--static-only"], env={"SCAN_MODEL": ""})
        self.assertEqual(result.exit_code, 0, result.output)
        static.assert_called_once()

    def test_line_chunks_and_continuation(self):
        self.path.write_text("x = 1\n" * 520)
        chunks = code_chunks(["x = 1"] * 520)
        self.assertEqual([(c.start, c.end) for c in chunks], [(1, 250), (231, 480), (461, 520)])
        client = Mock()
        client.review.side_effect = ["[partial", json.dumps([dict(finding(240), evidence="x = 1")]), "[]"]
        with self.assertLogs("scan.llm", level="WARNING"):
            findings, count = scan_llm(self.path, client)
        self.assertEqual(count, 1)
        self.assertEqual([f.line for f in findings], [240])
        self.assertEqual(client.review.call_count, 3)

    def test_end_line_and_valid_siblings(self):
        valid = dict(finding(235), end_line=240, evidence="\n".join(["x"] * 6))
        invalid = dict(finding(235), evidence="invented code")
        with self.assertLogs("scan.llm", level="WARNING"):
            result = parse_review(json.dumps([invalid, valid]), self.path, Chunk(231, ["x"] * 250))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].to_dict()["end_line"], 240)

    def test_connection_and_timeout_errors(self):
        request = httpx.Request("POST", self.url)
        for exc, message in ((APIConnectionError(request=request), "is your local server running"),
                             (APITimeoutError(request=request), "timed out")):
            with patch("scan.llm.OpenAI") as sdk:
                sdk.return_value.chat.completions.create.side_effect = exc
                result = self.invoke()
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn(message, " ".join(result.output.split()))
                sdk.return_value.close.assert_called_once()

    def test_config_precedence_and_placeholder(self):
        with patch("scan.llm.OpenAI") as sdk:
            sdk.return_value.chat.completions.create.return_value = Mock(
                choices=[Mock(finish_reason="stop", message=Mock(content="[]"))])
            result = CliRunner().invoke(main, ["scan", str(self.path), "--llm-only", "--timeout", "17"],
                                       env={"SCAN_MODEL": "env-model", "SCAN_BASE_URL": self.url,
                                            "SCAN_TIMEOUT": "23", "SCAN_API_KEY": "",
                                            "SCAN_MAX_TOKENS": "700", "SCAN_MAX_FINDINGS": "4"})
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(sdk.call_args.kwargs["timeout"], 17)
            self.assertEqual(sdk.return_value.chat.completions.create.call_args.kwargs["max_tokens"], 700)
            self.assertIn("at most 4 highest-impact findings",
                          sdk.return_value.chat.completions.create.call_args.kwargs["messages"][1]["content"])
            self.assertEqual(sdk.call_args.kwargs["api_key"], "not-needed")
            result = CliRunner().invoke(main, ["scan", str(self.path), "--llm-only"],
                                       env={"SCAN_MODEL": "env-model", "SCAN_TIMEOUT": "23"})
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(sdk.call_args.kwargs["timeout"], 23)

    def test_dotenv_configuration_is_loaded(self):
        runner = CliRunner()
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            try:
                os.chdir(directory)
                Path(".env").write_text(
                    f"SCAN_BASE_URL={self.url}\n"
                    "SCAN_MODEL=dotenv-model\n"
                    "SCAN_API_KEY=dotenv-key\n"
                    "SCAN_TIMEOUT=41\n"
                    "SCAN_MAX_TOKENS=640\n"
                    "SCAN_MAX_FINDINGS=3\n",
                    encoding="utf-8",
                )
                source = Path("app.py")
                source.write_text("x = 1\n", encoding="utf-8")
                with patch("scan.llm.OpenAI") as sdk:
                    sdk.return_value.chat.completions.create.return_value = Mock(
                        choices=[Mock(finish_reason="stop", message=Mock(content="[]"))]
                    )
                    result = runner.invoke(main, ["scan", str(source), "--llm-only"])
            finally:
                os.chdir(original_cwd)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(sdk.call_args.kwargs["base_url"], self.url)
            self.assertEqual(sdk.call_args.kwargs["api_key"], "dotenv-key")
            self.assertEqual(sdk.call_args.kwargs["timeout"], 41)
            self.assertEqual(sdk.return_value.chat.completions.create.call_args.kwargs["max_tokens"], 640)
            self.assertIn("at most 3 highest-impact findings",
                          sdk.return_value.chat.completions.create.call_args.kwargs["messages"][1]["content"])
            self.assertEqual(sdk.return_value.chat.completions.create.call_args.kwargs["model"],
                             "dotenv-model")

    def test_source_visible_in_reports(self):
        for format_name in ("text", "markdown", "json"):
            result = self.invoke("--format", format_name)
            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("llm", result.stdout)

    def test_chunk_bounds_and_absolute_lines(self):
        lines = ["x = 1 # " + "a" * 30 for _ in range(100)]
        chunks = code_chunks(lines, 256)
        covered = set()
        for chunk in chunks:
            self.assertLessEqual(len(chunk.numbered()), 256)
            covered.update(range(chunk.start, chunk.end + 1))
        self.assertEqual(covered, set(range(1, 101)))
        chunk = chunks[-1]
        items = parse_review(json.dumps([dict(finding(chunk.start), evidence=chunk.lines[0])]), self.path, chunk)
        self.assertEqual(items[0].line, chunk.start)
        with self.assertRaises(ScanError):
            code_chunks(["x" * 300], 256)

    def test_schema_validation(self):
        for field, value in (("line", True), ("line", 0), ("severity", "urgent"),
                             ("description", ""), ("recommendation", None), ("category", 42)):
            item = finding()
            item[field] = value
            with self.subTest(field=field, value=value), self.assertLogs("scan.llm", level="WARNING"):
                self.assertEqual(parse_review(json.dumps([item]), self.path, Chunk(1, ["x"])), [])
        result = parse_review('```json\n' + json.dumps([finding()]) + '\n```',
                              self.path, Chunk(1, ["x"]))
        self.assertEqual(len(result), 1)

    def test_common_local_model_json_wrappers(self):
        item = finding()
        wrapped = "Here is the result:\n```json\n" + json.dumps({"findings": [item]}) + "\n```\nDone."
        result = parse_review(wrapped, self.path, Chunk(1, ["x"]))
        self.assertEqual(len(result), 1)

        legacy = dict(item)
        legacy["line"] = "1"
        legacy["fix"] = legacy.pop("recommendation")
        result = parse_review("Security review: " + json.dumps([legacy]) + " End.",
                              self.path, Chunk(1, ["x"]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].recommendation, "Check authenticated ownership")

    def test_recovers_complete_findings_from_truncated_array(self):
        first = finding()
        partial = "[" + json.dumps(first) + ', {"line": 1, "severity": "high"'
        with self.assertLogs("scan.llm", level="WARNING") as logs:
            result = parse_review(partial, self.path, Chunk(1, ["x"]))
        self.assertEqual(len(result), 1)
        self.assertIn("Recovered 1 complete", " ".join(logs.output))

        wrapped = '{"findings": [' + json.dumps(first) + ', {"line": 1'
        with self.assertLogs("scan.llm", level="WARNING"):
            result = parse_review(wrapped, self.path, Chunk(1, ["x"]))
        self.assertEqual(len(result), 1)

    def test_discovery_encoding_and_empty_file(self):
        root = Path(self.temp.name)
        (root / ".venv").mkdir()
        (root / ".venv" / "ignored.py").write_text("x=1")
        self.assertEqual(python_files(root), [self.path])
        self.path.write_bytes(b"# coding: latin-1\nx = '\xe9'\n")
        self.set_content('[]')
        self.assertEqual(scan_llm(root, ReviewClient(self.url, "test")), ([], 1))
        self.path.write_text("")
        with patch.object(ReviewClient, "review", side_effect=AssertionError):
            self.assertEqual(scan_llm(root, ReviewClient(self.url, "test")), ([], 1))

    def test_wrong_line_is_relocated_by_exact_evidence(self):
        chunk = Chunk(40, ["# hash password", "", "    return hashlib.md5(password).hexdigest()"])
        item = dict(finding(999), evidence="return hashlib.md5(password).hexdigest()", end_line=1000)
        with self.assertLogs("scan.llm", level="WARNING"):
            result = parse_review(json.dumps([item]), self.path, chunk)
        self.assertEqual(result[0].line, 42)
        self.assertIsNone(result[0].end_line)
        self.assertIn("hashlib.md5", result[0].code_snippet)

    def test_missing_invented_and_comment_evidence_rejected(self):
        for evidence in (None, "", "eval(other)", "# eval(user)"):
            with self.subTest(evidence=evidence), self.assertLogs("scan.llm", level="WARNING"):
                result = parse_review(json.dumps([dict(finding(), evidence=evidence)]),
                                      self.path, Chunk(1, ["# eval(user)", "eval(user)"]))
                self.assertEqual(result, [])

    def test_all_ungrounded_findings_do_not_report_clean_scan(self):
        self.set_content(json.dumps([dict(finding(), evidence="invented code")]))
        result = self.invoke("--format", "json")
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("analysis is incomplete, not clean", " ".join(result.stderr.split()))
        self.assertNotIn('"total_findings"', result.stdout)

    def test_ambiguous_evidence_is_not_guessed(self):
        chunk = Chunk(10, ["eval(user)", "pass", "eval(user)"])
        with self.assertLogs("scan.llm", level="WARNING"):
            self.assertEqual(parse_review(json.dumps([dict(finding(11), evidence="eval(user)")]),
                                          self.path, chunk), [])
        result = parse_review(json.dumps([dict(finding(12), evidence="eval(user)")]), self.path, chunk)
        self.assertEqual(result[0].line, 12)

    def test_multiline_evidence_derives_range(self):
        chunk = Chunk(100, ["if admin:", "    eval(user)", "else:", "    eval(user)"])
        item = dict(finding(1), evidence="else:\n    eval(user)", end_line=400)
        with self.assertLogs("scan.llm", level="WARNING"):
            result = parse_review(json.dumps([item]), self.path, chunk)
        self.assertEqual((result[0].line, result[0].end_line), (102, 103))

    def test_exact_expression_token_match(self):
        chunk = Chunk(51, ["# eval(expression)", "    return eval(expression)"])
        with self.assertLogs("scan.llm", level="WARNING"):
            result = parse_review(json.dumps([dict(finding(51), evidence="eval( expression )")]),
                                  self.path, chunk)
        self.assertEqual(result[0].line, 52)
        with self.assertLogs("scan.llm", level="WARNING"):
            self.assertEqual(parse_review(json.dumps([dict(finding(52), evidence="expression")]),
                                          self.path, Chunk(52, ["return eval(other_expression)"])), [])

    def test_live_ollama_expression_regressions(self):
        lines = ["x"] * 78
        lines[13] = 'DB_PASSWORD = "SuperSecret123!"  # noqa: hardcoded password'
        lines[34] = "    return eval(expression)"
        lines[51] = '    query = "SELECT * FROM users WHERE username = \'%s\'" % username'
        items = [dict(finding(14), evidence=lines[13]),
                 dict(finding(53), evidence='"SELECT * FROM users WHERE username = \'%s\'"'),
                 dict(finding(33), evidence="return eval(expression)")]
        with self.assertLogs("scan.llm", level="WARNING"):
            results = parse_review(json.dumps(items), self.path, Chunk(1, lines))
        self.assertEqual([f.line for f in results], [14, 52, 35])


if __name__ == "__main__":
    unittest.main()
