"""Shared, closed vulnerability taxonomy."""

CATEGORIES = (
    "command-injection", "sql-injection", "code-injection", "hardcoded-secret",
    "insecure-deserialization", "weak-crypto", "path-traversal",
    "insecure-network-config", "unsafe-input-handling", "access-control",
    "race-condition", "other",
)

BANDIT_CATEGORIES = {
    **dict.fromkeys(("B102", "B307"), "code-injection"),
    **dict.fromkeys(("B105", "B106", "B107"), "hardcoded-secret"),
    **dict.fromkeys(("B301", "B302", "B403", "B506"), "insecure-deserialization"),
    **dict.fromkeys(("B303", "B304", "B305", "B311", "B324", "B413", "B505"), "weak-crypto"),
    **dict.fromkeys(("B601", "B602", "B603", "B604", "B605", "B606", "B607", "B609"), "command-injection"),
    **dict.fromkeys(("B608", "B610", "B611"), "sql-injection"),
    **dict.fromkeys(("B108", "B306"), "race-condition"),
    **dict.fromkeys(("B103",), "access-control"),
    **dict.fromkeys(("B104", "B201", "B312", "B321", "B401", "B402", "B501", "B502", "B503", "B504", "B507"), "insecure-network-config"),
    **dict.fromkeys(("B308", "B310", "B313", "B314", "B318", "B320", "B701", "B702", "B703"), "unsafe-input-handling"),
}


def normalize_category(value: str) -> str:
    value = value.strip().lower().replace("_", "-")
    return value if value in CATEGORIES else "other"
