import json

from darthscanner.sigma_audit import audit_log_file


def test_sigma_style_log_rules_detect_traversal_and_debug(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '192.0.2.10 GET /download?file=..%2f..%2fetc%2fpasswd 400\n'
        'Traceback (most recent call last): RuntimeError\n',
        encoding="utf-8",
    )
    result = audit_log_file(log)
    ids = {item["rule_id"] for item in result["matches"]}
    assert "web-path-traversal-probe" in ids
    assert "web-debug-or-stacktrace" in ids
    assert result["lines_reviewed"] == 2


def test_sigma_style_log_rules_accept_jsonl(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_text(json.dumps({"status": 401, "path": "/login", "message": "invalid password"}) + "\n")
    result = audit_log_file(log)
    assert any(item["rule_id"] == "web-auth-failure-burst" for item in result["matches"])


def test_log_size_limit_is_enforced(tmp_path):
    log = tmp_path / "large.log"
    log.write_text("x" * 20)
    try:
        audit_log_file(log, max_bytes=10)
    except ValueError as exc:
        assert "exceeds" in str(exc)
    else:
        raise AssertionError("expected size limit")
