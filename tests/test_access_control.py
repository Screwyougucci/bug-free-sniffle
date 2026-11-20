import unittest
from unittest.mock import Mock

from darthscanner.access_control import verify_object_access
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope


class DifferentialAccessControlTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(True, ("owned.example",), max_requests=10, request_delay_seconds=0.5)

    def test_second_identity_access_candidate_uses_two_gets_and_redacts_tokens(self):
        client = Mock()
        client.max_requests = 2
        client.get.side_effect = [
            HttpResponse("https://owned.example/api/items/42", 200, {}, b'{"id":42,"name":"private item"}', 0.1),
            HttpResponse("https://owned.example/api/items/42", 200, {}, b'{"id":42,"name":"private item"}', 0.1),
        ]
        result = verify_object_access(
            "https://owned.example/api/items/42", "owner-secret", "other-secret",
            self.scope, client,
        )
        self.assertIsNotNone(result["finding"])
        self.assertEqual(result["finding"].cwe_ids, ["CWE-862", "CWE-639"])
        self.assertEqual(client.get.call_count, 2)
        calls = client.get.call_args_list
        self.assertEqual(calls[0].kwargs["headers"]["Authorization"], "Bearer owner-secret")
        self.assertEqual(calls[1].kwargs["headers"]["Authorization"], "Bearer other-secret")
        self.assertNotIn("owner-secret", repr(result))
        self.assertNotIn("other-secret", repr(result))
        self.assertNotIn("private item", repr(result))

    def test_denied_second_identity_is_not_reported(self):
        client = Mock()
        client.max_requests = 2
        client.get.side_effect = [
            HttpResponse("https://owned.example/api/items/42", 200, {}, b'{"id":42}', 0.1),
            HttpResponse("https://owned.example/api/items/42", 403, {}, b"forbidden", 0.1),
        ]
        result = verify_object_access("https://owned.example/api/items/42", "a", "b", self.scope, client)
        self.assertIsNone(result["finding"])
        self.assertIn("did not receive a successful", result["note"])

    def test_owner_must_be_able_to_access_object_first(self):
        client = Mock()
        client.max_requests = 2
        client.get.return_value = HttpResponse("https://owned.example/api/items/42", 404, {}, b"", 0.1)
        result = verify_object_access("https://owned.example/api/items/42", "a", "b", self.scope, client)
        self.assertIsNone(result["finding"])
        self.assertEqual(client.get.call_count, 1)

    def test_rejects_same_token_and_out_of_scope(self):
        client = Mock()
        client.max_requests = 2
        with self.assertRaises(ValueError):
            verify_object_access("https://owned.example/item", "same", "same", self.scope, client)
        with self.assertRaises(ValueError):
            verify_object_access("https://outside.example/item", "a", "b", self.scope, client)
        client.get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
