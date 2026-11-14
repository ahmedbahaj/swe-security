# Secure Student Notes
CECY 482 Phase 1 educational implementation. Python 3.10+.

Run locally:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000. Register two accounts to demonstrate isolation.
Run tests: `python -m unittest -v`.

Security: salted PBKDF2-SHA256 password hashes through Werkzeug, ownership checks on every note operation, parameterized SQL, Jinja HTML escaping, CSRF tokens, HttpOnly/SameSite cookies, persistent five-attempt login throttling over five minutes, response security headers, and security event logging. Notes are plaintext in the local database. Password recovery, MFA, shared notes and deployment are outside Phase 1 scope.

For HTTPS deployment set a persistent random SECRET_KEY and HTTPS=1 and use a production WSGI server behind TLS. The built-in server is for local demonstration. Login throttling is an educational implementation; distributed deployments need a shared rate limiter and broader abuse controls.

Demo: register Alice and Bob; create and edit a note as Alice; log in as Bob and verify Alice's notes are absent; test direct modification with Alice's note ID; submit a form without CSRF; enter HTML as a note and verify literal display; try five wrong passwords and observe throttling.
