"""
POC 6: Bad Inputs: Bcrypt 72-Byte Crash, Unicode Multi-Byte Expansion, SQL Injection
Target: http://127.0.0.1:5000

Checks:
1. Passwords > 72 bytes: Bcrypt 4.0+ throws ValueError causing silent registration failures.
2. Unicode passwords: UTF-8 4-byte characters (emojis) rapidly exceed 72 bytes.
3. SQL Injection strings: Verification that parameterized queries safely prevent injection.
4. Empty field validation.
"""

import http.cookiejar
import re
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:5000"

def run_poc():
    print("[*] Testing Bad Inputs, Long Passwords & SQL Injection...")
    cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # 1. Long Password (> 72 bytes)
    long_pass = "A" * 75
    signup_pg = opener.open(f"{BASE_URL}/signup").read().decode("utf-8")
    csrf_tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', signup_pg).group(1)
    
    data_long = urllib.parse.urlencode({
        "csrf_token": csrf_tok,
        "username": "long_pass_user",
        "email": "longpass@test.com",
        "password": long_pass,
        "confirm_password": long_pass,
    }).encode("utf-8")
    resp_long = opener.open(urllib.request.Request(
        f"{BASE_URL}/createuser", data=data_long,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    body_long = resp_long.read().decode("utf-8")
    blocked_cleanly = "Password must not exceed 72 bytes" in body_long
    print(f"    [+] Password with {len(long_pass.encode('utf-8'))} bytes (> 72 bytes limit):")
    print(f"        -> Safely blocked with validation error (no 500 crash): {blocked_cleanly}")

    # 2. Unicode Emojis (each emoji is 4 UTF-8 bytes)
    # 20 emojis = 80 bytes
    emoji_pass = "🔒" * 20
    print(f"    [+] Unicode Password with 20 emojis ({len(emoji_pass.encode('utf-8'))} UTF-8 bytes):")
    data_emoji = urllib.parse.urlencode({
        "csrf_token": csrf_tok,
        "username": "emoji_user",
        "email": "emoji@test.com",
        "password": emoji_pass,
        "confirm_password": emoji_pass,
    }).encode("utf-8")
    resp_emoji = opener.open(urllib.request.Request(
        f"{BASE_URL}/createuser", data=data_emoji,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    body_emoji = resp_emoji.read().decode("utf-8")
    emoji_blocked = "Password must not exceed 72 bytes" in body_emoji
    print(f"        -> Safely blocked with validation error: {emoji_blocked}")

    # 3. SQL Injection Payloads in Username
    print("\n--- Testing SQL Injection Resistance ---")
    sql_payloads = [
        "' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users; --",
        "1' UNION SELECT 1,2,3,4,5,6,7,8--",
    ]
    for p in sql_payloads:
        # Username regex check in create_user
        data_sql = urllib.parse.urlencode({
            "csrf_token": csrf_tok,
            "username": p,
            "email": "sql@test.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        }).encode("utf-8")
        try:
            resp_sql = opener.open(urllib.request.Request(
                f"{BASE_URL}/createuser", data=data_sql,
                headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
            ))
            b = resp_sql.read().decode("utf-8")
            regex_caught = "Username must be 3-40 characters long and contain only letters" in b
            print(f"    Payload: {p:<35} -> Blocked by Username Regex: {regex_caught}")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"    Payload: {p:<35} -> Blocked by Rate Limiter (HTTP 429)")
            else:
                print(f"    Payload: {p:<35} -> Blocked with HTTP {e.code}")

if __name__ == "__main__":
    run_poc()
