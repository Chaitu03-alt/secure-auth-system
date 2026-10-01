import subprocess
import re

commits = subprocess.check_output(['git', 'rev-list', '--reverse', 'HEAD'], text=True).strip().split('\n')

patterns = [
    (r'BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? PRIVATE KEY', 'Private Key Header'),
    (r'Chaitanyaraut03', 'Plaintext DB Password'),
    (r'SecureAuthDbPass2026!', 'Docker DB Password'),
    (r'RootSecurePassword2026!', 'Docker Root Password'),
    (r'dev_secure_auth_system_secret_key_[a-f0-9]+', 'Hardcoded Secret Key'),
    (r'secure-auth-system-dev-insecure-key-[a-z0-9\-]+', 'Hardcoded Secret Key'),
    (r'dev_insecure_secret_key_[a-z0-9_]+', 'Example Secret Key'),
]

found = []
for c in commits:
    commit_msg = subprocess.check_output(['git', 'log', '-1', '--format=%s', c], text=True).strip()
    diff = subprocess.check_output(['git', 'show', c, '--unified=0'], text=True, errors='replace')
    curr_file = None
    curr_line = 0
    for line in diff.split('\n'):
        if line.startswith('+++ b/'):
            curr_file = line[6:]
        elif line.startswith('@@'):
            m = re.search(r'\+(\d+)', line)
            if m:
                curr_line = int(m.group(1))
        elif line.startswith('+') and not line.startswith('+++'):
            for pat, desc in patterns:
                if re.search(pat, line):
                    found.append({
                        "commit_short": c[:7],
                        "commit_full": c,
                        "commit_msg": commit_msg,
                        "file": curr_file,
                        "line": curr_line,
                        "type": desc,
                        "snippet": line[1:].strip()
                    })
            curr_line += 1

print(f"Total secret occurrences in history: {len(found)}")
for item in found:
    print(f"[{item['commit_short']}] {item['file']}:{item['line']} | {item['type']} -> {item['snippet']}")
