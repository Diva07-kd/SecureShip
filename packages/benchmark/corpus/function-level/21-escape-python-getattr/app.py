import requests
attr_name = 'get'
fn = getattr(requests, attr_name)
fn('http://example.com')
