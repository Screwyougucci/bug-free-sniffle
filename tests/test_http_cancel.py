import threading
import unittest

from darthscanner.http_client import SafeHttpClient
from darthscanner.scope import Scope


class HttpCancellationTests(unittest.TestCase):
    def test_cancelled_client_refuses_to_start_another_request(self):
        scope = Scope(
            authorized=True,
            allowed_hosts=("owned.example",),
            max_pages=10,
            max_requests=10,
            request_delay_seconds=0.5,
            timeout_seconds=2,
        )
        stop = threading.Event()
        client = SafeHttpClient(scope, stop_event=stop)
        stop.set()
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            client.get("https://owned.example/")


if __name__ == "__main__":
    unittest.main()
