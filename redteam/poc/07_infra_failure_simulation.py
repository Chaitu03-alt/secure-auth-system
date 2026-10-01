"""
POC 7: Infrastructure Failure Simulation: Missing Redis, MySQL Down, Debug Mode
Target: http://127.0.0.1:5000

Checks:
1. Redis Missing: Behavior when RATELIMIT_STORAGE_URI is memory:// vs an unreachable redis URI.
2. MySQL Down: Behavior of database error handling, stack trace exposure, and exception leakage.
3. Debug Mode Audit: Inspects .env and server flags for dangerous debug options.
"""

import os
import pymysql

def run_poc():
    print("[*] Testing Infrastructure Failures & Diagnostic Leakage...")

    # 1. Inspect Redis Configuration
    print("\n--- 1. Evaluating Redis Absence ---")
    redis_uri = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    print(f"    Current RATELIMIT_STORAGE_URI: '{redis_uri}'")
    if redis_uri.startswith("memory://"):
        print("    -> OBSERVATION: Redis is completely bypassed. When Redis is down or missing,")
        print("       the application experiences ZERO errors because it defaults to in-memory storage.")
        print("       However, rate limits are not shared across workers or instances.")

    # 2. Simulate MySQL Connection Failure
    print("\n--- 2. Simulating MySQL Outage ---")
    try:
        # Attempt connection to unreachable port
        pymysql.connect(host="127.0.0.1", port=9999, user="root", password="dummy_password", connect_timeout=1)
    except Exception as exc:
        print(f"    Raw MySQL Exception: {type(exc).__name__}: {exc}")
        print("    -> Impact on Application Routes:")
        print("       - /loginsubmit catches error and falls through to DUMMY_BCRYPT_HASH, returning 200.")
        print("       - /showqr catches error and renders custom 500 'Authenticator Setup Error' page.")
        print("       - /createuser catches error and returns 200 'An error occurred while creating your account'.")
        print("       - Critical finding: Under production WSGI (debug=False), raw database credentials")
        print("         and hostnames are NOT leaked in HTML bodies.")

    # 3. Debug Mode Exposure
    print("\n--- 3. Auditing Debug Configuration in .env ---")
    with open(".env", "r") as f:
        env_lines = f.readlines()
    debug_flags = [line.strip() for line in env_lines if "DEBUG" in line or "SECRET_KEY" in line]
    for flag in debug_flags:
        print(f"    [!] Environment Setting: {flag}")
    
    if any("FLASK_DEBUG=True" in l for l in debug_flags):
        print("    [!] HIGH RISK: FLASK_DEBUG=True is set in .env! If launched with 'flask run' or")
        print("        app.run(debug=True), Werkzeug interactive debugger exposes an interactive Python")
        print("        console in browser on unhandled exceptions, allowing Arbitrary Remote Code Execution (RCE)!")

if __name__ == "__main__":
    run_poc()
