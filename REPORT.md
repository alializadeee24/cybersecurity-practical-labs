# Task 3 - Secure Coding Review Report
**Target:** `vulnerable_app.py` (Python 3 / Flask) | **Method:** manual review + static analysis (Bandit, Semgrep) | **Standards:** OWASP Top 10 2021, CWE

## Executive summary
8 findings: 3 Critical, 3 High, 2 Medium. Two allow remote code execution (command injection, pickle). All are remediated in `secure_app.py`.

| ID | Finding | Location | CWE / OWASP | Severity |
|----|---------|----------|-------------|----------|
| V5 | OS command injection | `/ping` | CWE-78 / A03 | Critical |
| V7 | Insecure deserialization (pickle) -> RCE | `/load` | CWE-502 / A08 | Critical |
| V3 | SQL injection (auth bypass, data theft) | `/login` | CWE-89 / A03 | Critical |
| V6 | Path traversal | `/file` | CWE-22 / A01 | High |
| V1 | Hardcoded secret key | config | CWE-798 / A02 | High |
| V8 | Debug mode (Werkzeug console) + bind 0.0.0.0 | `app.run` | CWE-489 / A05 | High |
| V4 | Reflected XSS | `/search` | CWE-79 / A03 | Medium |
| V2 | Weak unsalted MD5 hashing | `/login` | CWE-327 / A02 | Medium (High with V3) |

## Findings and fixes
- **V3 SQLi** - `user=admin'--` bypasses the password check. *Fix:* parameterised queries.
- **V5 Command injection** - `/ping?host=8.8.8.8;id` runs `id`. *Fix:* validate as IP, argument list, `shell=False`, timeout.
- **V6 Path traversal** - `/file?name=../../etc/passwd`. *Fix:* `resolve()` and confirm the path is inside the uploads directory.
- **V7 Pickle** - crafted `__reduce__` payload executes code. *Fix:* JSON; never unpickle untrusted data.
- **V4 XSS** - `/search?q=<script>alert(1)</script>`. *Fix:* contextual output encoding + CSP header.
- **V2 MD5** - fast and unsalted. *Fix:* scrypt/Argon2/PBKDF2.
- **V1 Secret** - key in source control. *Fix:* env var / secrets manager; rotate the leaked key.
- **V8 Debug** - *Fix:* `debug=False`, bind 127.0.0.1 behind gunicorn + nginx with TLS.

## Secure-coding best practices
1. Allow-list input validation; encode output by context.
2. Least privilege (DB account, OS user, file access).
3. Framework protections: CSRF tokens, secure cookies, login rate limiting.
4. Never build commands/queries by string concatenation.
5. Keep secrets out of code; scan repos (gitleaks).
6. Update dependencies (`pip-audit`, Dependabot).
7. Security headers (CSP, HSTS, nosniff); generic error messages.
8. Automate Bandit/Semgrep in CI plus peer review.

## Reproduce the scan
```
pip install bandit semgrep flask
bandit -r vulnerable_app.py
semgrep --config p/python vulnerable_app.py
bandit -r secure_app.py   # compare after fixes
```
