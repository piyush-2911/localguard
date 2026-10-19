"""Portable strict response schema and local validation for compatible servers."""
import json
from copy import deepcopy

from .categories import CATEGORIES

FIELDS = {
    "line": {"type": "integer"},
    "end_line": {"type": ["integer", "null"]},
    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
    "category": {"type": "string", "enum": list(CATEGORIES)},
    "description": {"type": "string"},
    "recommendation": {"type": "string"},
    "evidence": {"type": "string"},
}
RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "security_review", "strict": True,
        "schema": {
            "type": "object", "additionalProperties": False,
            "required": ["findings"],
            "properties": {"findings": {
                "type": "array", "items": {
                    "type": "object", "additionalProperties": False,
                    "required": list(FIELDS), "properties": FIELDS,
                },
            }},
        },
    },
}


def response_format(file_ids=None):
    if file_ids is None:
        return RESPONSE_FORMAT
    result = deepcopy(RESPONSE_FORMAT)
    item = result["json_schema"]["schema"]["properties"]["findings"]["items"]
    item["required"].append("file")
    item["properties"]["file"] = {"type": "string", "enum": list(file_ids)}
    return result


def validate_response(content: str, max_findings: int, file_ids=None) -> None:
    """Do not trust servers to enforce response_format; fail closed locally."""
    def unique_keys(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj

    data = json.loads(content, object_pairs_hook=unique_keys)
    if not isinstance(data, dict) or set(data) != {"findings"}:
        raise ValueError("Expected a findings object")
    findings = data["findings"]
    if not isinstance(findings, list) or len(findings) > max_findings:
        raise ValueError("Invalid findings array or exceeded finding limit")
    for item in findings:
        expected = set(FIELDS) | ({"file"} if file_ids is not None else set())
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError("Missing or unexpected finding fields")
        if file_ids is not None and item["file"] not in file_ids:
            raise ValueError("File was not provided for review")
        if type(item["line"]) is not int or item["line"] < 1:
            raise ValueError("Invalid line")
        end = item["end_line"]
        if end is not None and (type(end) is not int or end < item["line"]):
            raise ValueError("Invalid end_line")
        for name in ("severity", "category", "description", "recommendation", "evidence"):
            if not isinstance(item[name], str) or not item[name].strip():
                raise ValueError("Invalid string field")
            if "enum" in FIELDS[name] and item[name] not in FIELDS[name]["enum"]:
                raise ValueError("Invalid enum value")


def unsupported_format(exc) -> bool:
    """Only downgrade on explicit format-capability errors, never generic failures."""
    if exc.status_code not in (400, 422):
        return False
    body = exc.body
    if not isinstance(body, (dict, str)):
        return False
    text = json.dumps(body).lower() if isinstance(body, dict) else body.lower()
    return (any(key in text for key in ("response_format", "json_schema", "structured output"))
            and any(word in text for word in ("not supported", "unsupported", "not implemented",
                                               "unknown parameter", "unrecognized", "extra inputs are not permitted")))
