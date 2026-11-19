from types import SimpleNamespace

from darthscanner.server_side_audit import (
    inspect_server_fuzz_observations,
    inspect_server_response,
)


def response(body: bytes = b"", status: int = 500, headers=None):
    return SimpleNamespace(
        status=status,
        body=body,
        headers=headers or {},
        url="https://app.example.test/api/item",
    )


def test_detects_database_diagnostic_without_claiming_injection():
    findings = inspect_server_response(response(b"SQLSTATE[42000]: syntax error near SELECT"))
    assert len(findings) == 1
    assert findings[0].kind == "database-error"
    assert findings[0].cwe_ids == ["CWE-209"]
    assert "not established" in findings[0].impact


def test_detects_stack_trace_and_internal_path():
    findings = inspect_server_response(
        response(b'Traceback (most recent call last): File "/srv/app/main.py", line 42')
    )
    assert {item.kind for item in findings} >= {"stack-trace", "local-path"}


def test_detects_framework_debug_page():
    findings = inspect_server_response(response(b"Werkzeug Debugger is active"))
    assert any(item.kind == "debug-page" and item.cwe_ids == ["CWE-489"] for item in findings)


def test_detects_debug_headers_and_version_banner():
    findings = inspect_server_response(response(
        headers={
            "x-debug-token": "abc123",
            "server": "nginx/1.24.0",
            "x-powered-by": "PHP/8.2",
        },
        status=200,
    ))
    assert any(item.kind == "debug-header" for item in findings)
    assert sum(item.kind == "server-banner" for item in findings) == 1


def test_ignores_ordinary_response():
    assert inspect_server_response(response(b"Everything is fine", 200)) == []


def test_5xx_fuzz_signal_is_low_confidence_and_deduplicated():
    observations = [
        {"server_error": True, "endpoint_url": "https://app.example.test/x?id=1",
         "parameter": "id", "case": "negative-one", "baseline_status": 200,
         "status": 500, "response_sha256": "abc"},
        {"server_error": True, "endpoint_url": "https://app.example.test/x?id=1",
         "parameter": "id", "case": "empty", "baseline_status": 200,
         "status": 500, "response_sha256": "def"},
    ]
    findings = inspect_server_fuzz_observations(observations)
    assert len(findings) == 1
    assert findings[0].confidence == "low"
    assert findings[0].severity == "info"
