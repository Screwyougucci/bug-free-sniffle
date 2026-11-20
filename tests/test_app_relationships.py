import unittest

from darthscanner.app_relationships import build_app_api_relationships


class AppApiRelationshipTests(unittest.TestCase):
    def test_matches_html_form_to_openapi_template(self):
        result = build_app_api_relationships(
            [{
                "page_url": "https://example.test/profile",
                "forms": [{
                    "action": "https://example.test/api/users/42",
                    "same_origin_action": True,
                    "method": "POST",
                }],
            }],
            [],
            [{"path": "/api/users/{userId}", "methods_documented": ["POST", "GET"]}],
        )
        self.assertEqual(result["relationship_count"], 1)
        relation = result["relationships"][0]
        self.assertEqual(relation["path_match"], "path-template")
        self.assertTrue(relation["method_documented"])
        self.assertTrue(relation["sensitive_path_hint"])

    def test_matches_static_javascript_route_exactly(self):
        result = build_app_api_relationships(
            [],
            [{
                "endpoint": "https://example.test/api/catalog",
                "method": "GET",
                "discovered_from": "https://example.test/assets/app.js",
            }],
            [{"path": "/api/catalog", "methods_documented": ["GET"]}],
        )
        self.assertEqual(result["relationships"][0]["path_match"], "exact")
        self.assertEqual(result["relationships"][0]["client_type"], "javascript-route")

    def test_reports_method_mismatch_without_calling_it_a_vulnerability(self):
        result = build_app_api_relationships(
            [],
            [{
                "endpoint": "https://example.test/api/orders",
                "method": "GET",
                "discovered_from": "https://example.test/app.js",
            }],
            [{"path": "/api/orders", "methods_documented": ["POST"]}],
        )
        relation = result["relationships"][0]
        self.assertFalse(relation["method_documented"])
        self.assertNotIn("findings", result)

    def test_external_forms_and_unmatched_routes_are_not_promoted_to_findings(self):
        result = build_app_api_relationships(
            [{
                "page_url": "https://example.test/",
                "forms": [{
                    "action": "https://outside.test/submit",
                    "same_origin_action": False,
                    "method": "POST",
                }],
            }],
            [{
                "endpoint": "https://example.test/api/internal/42",
                "method": "GET",
                "discovered_from": "https://example.test/app.js",
            }],
            [],
        )
        self.assertEqual(result["relationship_count"], 0)
        self.assertEqual(result["unmatched_client_route_count"], 1)
        self.assertTrue(result["unmatched_client_routes"][0]["sensitive_path_hint"])

    def test_graphql_metadata_is_redacted_to_inventory_fields(self):
        result = build_app_api_relationships(
            [], [], [],
            [{
                "source_url": "https://example.test/app.js",
                "operation_type": "mutation",
                "operation_name": "UpdateProfile",
                "root_field_names": ["updateProfile"],
                "source_line": 22,
                "query_body": "must not be copied",
            }],
        )
        self.assertEqual(result["graphql_operation_count"], 1)
        self.assertNotIn("query_body", str(result))


if __name__ == "__main__":
    unittest.main()
