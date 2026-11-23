import unittest

from darthscanner.crawler import crawl
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope


class FakeClient:
    def __init__(self, pages, max_requests=30):
        self.pages = pages
        self.max_requests = max_requests
        self.requests_made = 0
        self.requested = []
        self.cancelled = False

    def get(self, url):
        self.requests_made += 1
        self.requested.append(url)
        status, content_type, body = self.pages.get(url, (404, "text/plain", ""))
        return HttpResponse(url, status, {"content-type": content_type}, body.encode(), 0.01)


class DeepCrawlerTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(
            authorized=True,
            allowed_hosts=("owned.example",),
            max_pages=30,
            max_requests=40,
            request_delay_seconds=0.5,
            timeout_seconds=2,
        )

    def test_follows_nested_links_and_same_origin_script_assets(self):
        pages = {
            "https://owned.example/": (
                200, "text/html",
                '<a href="/account/profile">Profile</a>'
                '<script src="/assets/app.js"></script>'
                '<a href="https://outside.example/steal">external</a>'
                '<a href="/logout">logout</a>',
            ),
            "https://owned.example/robots.txt": (200, "text/plain", "User-agent: *\nDisallow:"),
            "https://owned.example/sitemap.xml": (404, "text/plain", ""),
            "https://owned.example/account/profile": (200, "text/html", "<p>profile</p>"),
            "https://owned.example/assets/app.js": (
                200, "application/javascript",
                "fetch('/api/v2/profile'); const route = '/settings/security';",
            ),
            "https://owned.example/api/v2/profile": (200, "application/json", '{"ok":true}'),
            "https://owned.example/settings/security": (200, "text/html", "<p>settings</p>"),
        }
        client = FakeClient(pages)
        responses = crawl("https://owned.example/", self.scope, client)
        requested = set(client.requested)
        for expected in (
            "https://owned.example/account/profile",
            "https://owned.example/assets/app.js",
            "https://owned.example/api/v2/profile",
            "https://owned.example/settings/security",
        ):
            self.assertIn(expected, requested)
        self.assertNotIn("https://owned.example/logout", requested)
        self.assertNotIn("https://outside.example/steal", requested)
        self.assertEqual(len(responses), len(requested))

    def test_discovers_urls_from_sitemap_index_and_respects_same_origin(self):
        pages = {
            "https://owned.example/": (200, "text/html", "<p>home</p>"),
            "https://owned.example/robots.txt": (
                200, "text/plain",
                "User-agent: *\nSitemap: https://owned.example/sitemap-index.xml",
            ),
            "https://owned.example/sitemap-index.xml": (
                200, "application/xml",
                '<sitemapindex><sitemap><loc>https://owned.example/maps/pages.xml</loc></sitemap>'
                '<sitemap><loc>https://outside.example/private.xml</loc></sitemap></sitemapindex>',
            ),
            "https://owned.example/maps/pages.xml": (
                200, "application/xml",
                '<urlset><url><loc>https://owned.example/products/one</loc></url>'
                '<url><loc>https://owned.example/products/two</loc></url></urlset>',
            ),
            "https://owned.example/products/one": (200, "text/html", "<p>one</p>"),
            "https://owned.example/products/two": (200, "text/html", "<p>two</p>"),
        }
        client = FakeClient(pages)
        crawl("https://owned.example/", self.scope, client)
        self.assertIn("https://owned.example/maps/pages.xml", client.requested)
        self.assertIn("https://owned.example/products/one", client.requested)
        self.assertIn("https://owned.example/products/two", client.requested)
        self.assertNotIn("https://outside.example/private.xml", client.requested)

    def test_follows_iframes_and_respects_base_href(self):
        pages = {
            "https://owned.example/": (
                200, "text/html",
                '<base href="https://owned.example/app/">'
                '<a href="account">account</a><iframe src="embedded"></iframe>',
            ),
            "https://owned.example/robots.txt": (404, "text/plain", ""),
            "https://owned.example/sitemap.xml": (404, "text/plain", ""),
            "https://owned.example/app/account": (200, "text/html", "<p>account</p>"),
            "https://owned.example/app/embedded": (200, "text/html", "<p>frame</p>"),
        }
        client = FakeClient(pages)
        crawl("https://owned.example/", self.scope, client)
        self.assertIn("https://owned.example/app/account", client.requested)
        self.assertIn("https://owned.example/app/embedded", client.requested)

    def test_honors_page_and_request_budgets(self):
        pages = {
            "https://owned.example/": (200, "text/html", '<a href="/a">a</a><a href="/b">b</a>'),
            "https://owned.example/robots.txt": (404, "text/plain", ""),
            "https://owned.example/a": (200, "text/html", "<p>a</p>"),
            "https://owned.example/b": (200, "text/html", "<p>b</p>"),
        }
        client = FakeClient(pages, max_requests=2)
        responses = crawl("https://owned.example/", self.scope, client, max_pages=2)
        self.assertEqual(len(responses), 2)
        self.assertEqual(client.requests_made, 2)

    def test_deduplicates_query_routes_but_drops_fragments(self):
        pages = {
            "https://owned.example/": (
                200, "text/html",
                '<a href="/search?q=one#top">one</a>'
                '<a href="/search?q=one#bottom">same</a>'
                '<a href="/search?q=two">two</a>',
            ),
            "https://owned.example/robots.txt": (404, "text/plain", ""),
            "https://owned.example/sitemap.xml": (404, "text/plain", ""),
            "https://owned.example/search?q=one": (200, "text/html", "<p>one</p>"),
            "https://owned.example/search?q=two": (200, "text/html", "<p>two</p>"),
        }
        client = FakeClient(pages)
        crawl("https://owned.example/", self.scope, client)
        self.assertEqual(client.requested.count("https://owned.example/search?q=one"), 1)
        self.assertEqual(client.requested.count("https://owned.example/search?q=two"), 1)
        self.assertEqual(len(client.requested), len(set(client.requested)))


if __name__ == "__main__":
    unittest.main()
