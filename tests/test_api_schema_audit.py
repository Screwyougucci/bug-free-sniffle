from darthscanner.api_schema_audit import inspect_openapi_schema


def test_sensitive_operation_without_security_is_flagged():
    findings = inspect_openapi_schema({
        "openapi": "3.0.0",
        "paths": {"/v1/admin/users": {"get": {}, "post": {"security": [{"bearer": []}]}}},
    }, "https://app.example/openapi.json")
    assert len(findings) == 1
    assert findings[0].title == "Sensitive-looking API operation has no declared security requirement"
    assert "GET /v1/admin/users" in findings[0].evidence


def test_operation_empty_security_overrides_global_security():
    findings = inspect_openapi_schema({
        "security": [{"bearer": []}],
        "paths": {"/v1/account/profile": {"get": {"security": []}}},
    }, "https://app.example/openapi.json")
    assert len(findings) == 1
    assert "overrides inherited security" in findings[0].evidence


def test_api_key_in_query_and_plaintext_server_are_reported_without_secrets():
    findings = inspect_openapi_schema({
        "servers": [{"url": "http://api.example.test"}],
        "components": {"securitySchemes": {
            "queryKey": {"type": "apiKey", "in": "query", "name": "api_key"}
        }},
        "paths": {},
    }, "https://app.example/openapi.json")
    assert len(findings) == 2
    assert all("secret-value" not in item.evidence for item in findings)


def test_public_non_sensitive_operation_is_not_flagged():
    findings = inspect_openapi_schema({
        "paths": {"/v1/status": {"get": {}}},
    }, "https://app.example/openapi.json")
    assert findings == []
