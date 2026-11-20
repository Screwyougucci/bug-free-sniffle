import unittest
from darthscanner.checks import inspect_http

class Response:
    def __init__(self,url,headers,status=200,body=b""):
        self.url=url; self.headers={k.lower():v for k,v in headers.items()}
        self.status=status; self.body=body; self.elapsed_seconds=0.01
    @property
    def text(self): return self.body.decode("utf-8",errors="replace")

class MicroHttpAuditTests(unittest.TestCase):
    def test_flags_shared_cache_on_sensitive_route(self):
        r=Response("https://app.example/account/profile",{"content-type":"application/json","cache-control":"public, s-maxage=600"})
        findings=inspect_http(r)
        item=next(x for x in findings if x.title=="Sensitive-looking route permits shared caching")
        self.assertEqual(item.severity,"medium"); self.assertIn("s-maxage",item.evidence)
    def test_does_not_flag_private_or_no_store(self):
        for policy in ("private, max-age=60","no-store"):
            findings=inspect_http(Response("https://app.example/account/profile",{"cache-control":policy}))
            self.assertFalse(any(x.title=="Sensitive-looking route permits shared caching" for x in findings))
    def test_does_not_flag_public_cache_on_public_route(self):
        findings=inspect_http(Response("https://app.example/catalog",{"cache-control":"public, s-maxage=600"}))
        self.assertFalse(any(x.title=="Sensitive-looking route permits shared caching" for x in findings))
    def test_flags_concrete_cors_origin_without_vary(self):
        findings=inspect_http(Response("https://app.example/api/profile",{"access-control-allow-origin":"https://portal.example"}))
        self.assertTrue(any(x.title=="Origin-specific CORS response does not declare Vary: Origin" for x in findings))
    def test_accepts_vary_origin_case_insensitively(self):
        findings=inspect_http(Response("https://app.example/api/profile",{"access-control-allow-origin":"https://portal.example","vary":"Accept-Encoding, ORIGIN"}))
        self.assertFalse(any(x.title=="Origin-specific CORS response does not declare Vary: Origin" for x in findings))
    def test_ignores_wildcard_cors_without_vary(self):
        findings=inspect_http(Response("https://app.example/public-data",{"access-control-allow-origin":"*"}))
        self.assertFalse(any(x.title=="Origin-specific CORS response does not declare Vary: Origin" for x in findings))

if __name__=="__main__": unittest.main()
