import requests

def fetch_status(target_url):
    response = requests.get(target_url)
    return response.status_code

print(fetch_status('https://example.com'))
