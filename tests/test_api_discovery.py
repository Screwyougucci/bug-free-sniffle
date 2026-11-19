from darthscanner.api_discovery import discover_api_resources
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.max_requests = 50
        self.requests_made = 0

    def get(self, url):
        self.requests_made += 1
        status, content_type, body = self.responses.get(url, (404, "text/plain", b""))
        return HttpResponse(url, status, {"content-type": content_type}, body, 0.01)


def test_api_discovery_inventories_openapi_paths_without_calling_operations():
    base = "https://app.example/"
    root = "https://app.example"
    spec = b'{"openapi":"3.0.0","info":{"title":"Example API","version":"1"},"paths":{"/v1/users":{"get":{},"post":{}},"/v1/orders/{id}":{"get":{}}}}'
    client = FakeClient({
        root + "/openapi.json": (200, "application/json", spec),
    })
    scope = Scope(True, ("app.example",), max_requests=50)
    result = discover_api_resources(base, scope, client)
    assert {item["path"] for item in result["api_endpoints"]} == {"/v1/users", "/v1/orders/{id}"}
    users = next(item for item in result["api_endpoints"] if item["path"] == "/v1/users")
    assert users["methods_documented"] == ["GET", "POST"]
    assert client.requests_made == 7
    assert all("/v1/" not in url for url in client.responses)


def test_discovery_rejects_external_sitemap_urls():
    base = "https://app.example/"
    root = "https://app.example"
    sitemap = b'<urlset><url><loc>https://app.example/public</loc></url><url><loc>https://other.example/private</loc></url></urlset>'
    client = FakeClient({root + "/sitemap.xml": (200, "application/xml", sitemap)})
    scope = Scope(True, ("app.example",))
    result = discover_api_resources(base, scope, client)
    assert result["sitemap_urls_discovered"] == ["https://app.example/public"]


def test_robots_sitemap_must_remain_same_origin():
    base = "https://app.example/"
    root = "https://app.example"
    robots = b"User-agent: *\nSitemap: https://app.example/sitemap.xml\nSitemap: https://evil.example/map.xml\n"
    client = FakeClient({root + "/robots.txt": (200, "text/plain", robots)})
    scope = Scope(True, ("app.example",))
    result = discover_api_resources(base, scope, client)
    assert result["robots_sitemaps_discovered"] == ["https://app.example/sitemap.xml"]


def test_discovery_respects_request_budget():
    base = "https://app.example/"
    client = FakeClient({})
    client.max_requests = 2
    scope = Scope(True, ("app.example",))
    result = discover_api_resources(base, scope, client, max_resources=7)
    assert client.requests_made == 2
    assert len(result["resources"]) == 2
