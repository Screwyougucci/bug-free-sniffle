from darthscanner.metadata_discovery import discover_api_resources
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope

class FakeClient:
    def __init__(self,responses):
        self.responses=responses; self.max_requests=50; self.requests_made=0; self.requested_urls=[]
    def get(self,url):
        self.requests_made+=1; self.requested_urls.append(url)
        status,ctype,body=self.responses.get(url,(404,"text/plain",b""))
        return HttpResponse(url,status,{"content-type":ctype},body,0.01)

def test_openapi_inventory_does_not_fetch_operations():
    root="https://app.example"
    spec=b'{"openapi":"3.0.0","info":{"title":"Example","version":"1"},"paths":{"/v1/users":{"get":{},"post":{}}}}'
    client=FakeClient({root+"/openapi.json":(200,"application/json",spec)})
    result=discover_api_resources(root+"/",Scope(True,("app.example",),max_requests=50),client)
    assert result["api_endpoints"][0]["methods_documented"]==["GET","POST"]
    assert client.requests_made==7
    assert all("/v1/" not in u for u in client.requested_urls)

def test_sitemap_external_urls_are_rejected():
    root="https://app.example"
    xml=b'<urlset><url><loc>https://app.example/public</loc></url><url><loc>https://evil.example/x</loc></url></urlset>'
    result=discover_api_resources(root+"/",Scope(True,("app.example",)),FakeClient({root+"/sitemap.xml":(200,"application/xml",xml)}))
    assert result["sitemap_urls_discovered"]==["https://app.example/public"]

def test_robots_sitemap_external_urls_are_rejected():
    root="https://app.example"; body=b"User-agent: *\nSitemap: https://app.example/sitemap.xml\nSitemap: https://evil.example/map.xml\n"
    result=discover_api_resources(root+"/",Scope(True,("app.example",)),FakeClient({root+"/robots.txt":(200,"text/plain",body)}))
    assert result["robots_sitemaps_discovered"]==["https://app.example/sitemap.xml"]

def test_request_budget_is_respected():
    client=FakeClient({}); client.max_requests=2
    result=discover_api_resources("https://app.example/",Scope(True,("app.example",)),client)
    assert client.requests_made==2 and len(result["resources"])==2
