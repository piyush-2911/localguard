import json
import unittest
from unittest.mock import Mock, patch

import httpx
from openai import APIStatusError

from scan.llm import Chunk, ReviewClient
from scan.scanner import ScanError
from scan.structured import FIELDS, validate_response
from test_llm import finding


def completion(content='{"findings": []}', finish="stop", refusal=None):
    return Mock(choices=[Mock(finish_reason=finish,
                             message=Mock(content=content, refusal=refusal))])


def error(status=400, message="response_format json_schema is not supported"):
    return APIStatusError("request failed", response=httpx.Response(
        status, request=httpx.Request("POST", "http://localhost/v1/chat/completions")),
        body={"message": message})


class StructuredTests(unittest.TestCase):
    def setUp(self):
        patcher = patch("scan.llm.OpenAI")
        self.sdk = patcher.start()
        self.addCleanup(patcher.stop)
        self.create = self.sdk.return_value.chat.completions.create
        self.create.return_value = completion()

    def client(self, mode="auto"):
        client = ReviewClient("http://localhost/v1", "test", structured_output=mode)
        self.addCleanup(client.close)
        return client

    def test_default_schema_and_required_fields(self):
        self.client().review(Chunk(1, ["x"]))
        payload = self.create.call_args.kwargs
        schema = payload["response_format"]["json_schema"]
        self.assertTrue(schema["strict"])
        item = schema["schema"]["properties"]["findings"]["items"]
        self.assertEqual(set(item["required"]), set(FIELDS))
        self.assertFalse(item["additionalProperties"])
        self.assertIn('"end_line": null', payload["messages"][0]["content"])

    def test_fallback_once_and_cached_across_chunks(self):
        self.create.side_effect = [error(), completion("[]"), completion("[]")]
        client = self.client()
        with self.assertLogs("scan.llm", level="WARNING") as logs:
            client.review(Chunk(1, ["x"]))
        client.review(Chunk(2, ["y"]))
        self.assertIn("Schema enforcement is unavailable", logs.output[0])
        self.assertEqual(["response_format" in call.kwargs for call in self.create.call_args_list],
                         [True, False, False])

    def test_no_fallback_for_required_or_unrelated_errors(self):
        for mode, exc in [("required", error()), ("auto", error(401)),
                          ("auto", error(429)), ("auto", error(500)),
                          ("auto", error(400, "Invalid schema")),
                          ("auto", error(400, "Model not found"))]:
            with self.subTest(mode=mode, error=exc):
                self.create.reset_mock()
                self.create.side_effect = exc
                with self.assertRaises(ScanError):
                    self.client(mode).review(Chunk(1, ["x"]))
                self.assertEqual(self.create.call_count, 1)

    def test_fallback_error_is_clear(self):
        self.create.side_effect = [error(422), error(500)]
        with self.assertLogs("scan.llm"), self.assertRaisesRegex(ScanError, "HTTP 500"):
            self.client().review(Chunk(1, ["x"]))

    def test_off_preserves_legacy_response(self):
        self.create.return_value = completion("```json\n[]\n```")
        self.assertIn("```", self.client("off").review(Chunk(1, ["x"])))
        self.assertNotIn("response_format", self.create.call_args.kwargs)

    def test_ignored_schema_truncation_and_refusal_fail_without_retry(self):
        for response in [completion("[]"), completion('```json\n{"findings": []}\n```'),
                         completion('{"findings": ['), completion(finish="length"),
                         completion(refusal="cannot review")]:
            self.create.reset_mock()
            self.create.return_value = response
            with self.assertRaisesRegex(ScanError, "incomplete"):
                self.client().review(Chunk(1, ["x"]))
            self.assertEqual(self.create.call_count, 1)

    def test_validation_rejects_invalid_fields(self):
        valid = dict(finding(), category="access-control", end_line=None)
        validate_response(json.dumps({"findings": [valid]}), 1)
        for name in FIELDS:
            invalid = dict(valid)
            del invalid[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                validate_response(json.dumps({"findings": [invalid]}), 1)
        for name, value in [("line", True), ("line", 0), ("end_line", 0),
                            ("category", "access_control"), ("severity", "urgent"),
                            ("evidence", " "), ("description", 42), ("extra", "x")]:
            with self.subTest(field=name), self.assertRaises(ValueError):
                validate_response(json.dumps({"findings": [dict(valid, **{name: value})]}), 1)
        for content in ['{"findings": [], "findings": []}', '{"findings": null}',
                        json.dumps({"findings": [valid, valid]})]:
            with self.assertRaises(ValueError):
                validate_response(content, 1)


