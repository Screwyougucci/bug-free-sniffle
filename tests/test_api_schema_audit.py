from darthscanner.api_schema_audit import inspect_openapi_schema


def test_sensitive_operation_without_security_is_flagged():
    findings=inspect_openapi_schema({"openapi":"3.0.0","paths":{"/v1/admin/users":{"get":{},"post":{"security":[{"bearer":[]}]}}}},"https://app.example/openapi.json")
    assert len(findings)==1
    assert "GET /v1/admin/users" in findings[0].evidence


def test_empty_operation_security_overrides_global_security():
    findings=inspect_openapi_schema({"security":[{"bearer":[]}],"paths":{"/v1/account/profile":{"get":{"security":[]}}}},"https://app.example/openapi.json")
    assert len(findings)==1
    assert "overrides inherited security" in findings[0].evidence


def test_query_api_key_and_plaintext_server_report_without_values():
    findings=inspect_openapi_schema({"servers":[{"url":"http://api.example.test"}],"components":{"securitySchemes":{"queryKey":{"type":"apiKey","in":"query","name":"api_key"}}},"paths":{}},"https://app.example/openapi.json")
    assert len(findings)==2
    assert all("secret-value" not in item.evidence for item in findings)


def test_public_status_operation_not_flagged():
    assert inspect_openapi_schema({"paths":{"/v1/status":{"get":{}}}},"https://app.example/openapi.json")==[]


def test_identifier_route_without_security_is_flagged():
    findings = inspect_openapi_schema({
        "paths": {"/v2/orders/{orderId}": {"get": {}, "patch": {"security": [{"bearer": []}]}}}
    }, "https://app.example/openapi.json")
    assert len(findings) == 1
    assert findings[0].title == "Object-identifier API route has no declared security requirement"


def test_write_schema_with_privilege_fields_is_flagged_through_local_ref():
    findings = inspect_openapi_schema({
        "paths": {
            "/v1/users/{userId}": {
                "patch": {
                    "security": [{"bearer": []}],
                    "requestBody": {
                        "content": {"application/json": {
                            "schema": {"$ref": "#/components/schemas/UserUpdate"}
                        }}
                    }
                }
            }
        },
        "components": {"schemas": {
            "UserUpdate": {"type": "object", "properties": {
                "displayName": {"type": "string"},
                "role": {"type": "string"},
                "isAdmin": {"type": "boolean"},
                "serverCalculated": {"type": "boolean", "readOnly": True}
            }}
        }}
    }, "https://app.example/openapi.json")
    finding = next(item for item in findings if "privilege-sensitive" in item.title)
    assert "role" in finding.evidence
    assert "isAdmin" in finding.evidence
    assert "serverCalculated" not in finding.evidence


def test_safe_write_schema_does_not_flag_readonly_sensitive_field():
    findings = inspect_openapi_schema({
        "paths": {"/v1/profile": {"patch": {"requestBody": {"content": {
            "application/json": {"schema": {"type": "object", "properties": {
                "role": {"type": "string", "readOnly": True},
                "displayName": {"type": "string"}
            }}}
        }}}}}
    }, "https://app.example/openapi.json")
    assert not any("privilege-sensitive" in item.title for item in findings)


def test_recursive_schema_reference_is_bounded():
    findings = inspect_openapi_schema({
        "paths": {"/v1/tree": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}
        }}}}},
        "components": {"schemas": {"Node": {"type": "object", "properties": {
            "child": {"$ref": "#/components/schemas/Node"},
            "ownerId": {"type": "string"}
        }}}}
    }, "https://app.example/openapi.json")
    assert any("privilege-sensitive" in item.title for item in findings)
