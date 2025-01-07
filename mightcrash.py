import requests

# Base URL of the server
base_url = "http://192.168.1.1"

# Headers for all requests
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": f"{base_url}/login_security.html",
}

# GET request 1
url1 = f"{base_url}/Forms/login_security_1"
params1 = {".classLoader.DefaultAssertionStatus": "ronbub"}
response1 = requests.get(url1, headers=headers, params=params1)
print(f"Response 1 Status: {response1.status_code}")
print(response1.text)


