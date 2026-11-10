#!/usr/bin/env python3
"""E2E HUD harness for Manas Aegis v2.6.4-alpha.

Real HTTP against a test HUD server (ephemeral port on 127.0.0.1):
Host allow/deny, login flow, CSRF enforcement, rate limit,
/api/search, /api/stix, version string, Posture.

Usage: python3 e2e-hud.py   (run from the repo root)
Exit 0 = all checks pass, 1 = any failure.
"""
import http.client
import json
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hermes_manas_aegis as pkg
from hermes_manas_aegis import _ManasHUDHandler, _effective_hud_token

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    state = Path(tempfile.mkdtemp()) / "state"
    core = pkg.ManasAegisCore(state_dir=state)
    pkg._CORE = core
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ManasHUDHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)

    def req(method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        hdrs = dict(r.getheaders())
        conn.close()
        return r.status, hdrs, data

    host = {"Host": f"127.0.0.1:{port}"}
    try:
        # 1. Evil Host -> 403
        st, _, _ = req("GET", "/", {"Host": f"evil.example:{port}"})
        check("evil Host rejected (403)", st == 403, f"status={st}")

        # 2. Missing Host -> 403
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("GET", "/", skip_host=True)
        conn.putheader("Accept", "*/*")
        conn.endheaders()
        r = conn.getresponse()
        r.read()
        conn.close()
        check("missing Host rejected (403)", r.status == 403, f"status={r.status}")

        # 3. Loopback Host, no session -> 200 login page
        st, _, body = req("GET", "/", host)
        text = body.decode("utf-8", "replace")
        check("unauthenticated GET shows login (200)", st == 200, f"status={st}")
        check("login page names token file", "hud_auth_token.txt" in text)
        check("no dashboard content before login", "MANAS-AEGIS CORE" not in text)

        # 4. Wrong token -> 401
        st, _, _ = req(
            "POST",
            "/api/login",
            {**host, "Content-Type": "application/x-www-form-urlencoded"},
            body="token=wrong-token",
        )
        check("wrong token rejected (401)", st == 401, f"status={st}")

        # 5. Right token -> 302 + session cookie
        token = _effective_hud_token(core)
        st, hdrs, _ = req(
            "POST",
            "/api/login",
            {**host, "Content-Type": "application/x-www-form-urlencoded"},
            body=f"token={token}",
        )
        cookie = hdrs.get("Set-Cookie", "")
        check("login with token (302)", st == 302, f"status={st}")
        check("session cookie set", "manas_session=" in cookie)
        sess = cookie.split(";")[0]
        auth = {**host, "Cookie": sess}

        # 6. Authed GET -> 200, version + Posture visible
        st, _, body = req("GET", "/", auth)
        text = body.decode("utf-8", "replace")
        check("authed GET (200)", st == 200, f"status={st}")
        check("version string 2.6.4-alpha", "MANAS-AEGIS CORE v2.6.4-alpha" in text)
        check("Posture shown", "Posture" in text)
        pscore = core.compute_posture_score()
        exact = f">{pscore['score']} <span class=\"grade\">{pscore['grade']}</span>"
        check("Posture score+grade exact value", exact in text, f"score={pscore['score']} grade={pscore['grade']}")

        # 7. POST without CSRF -> 403 (shared guard, before dispatch)
        st, _, _ = req(
            "POST",
            "/api/scan",
            {**auth, "Content-Type": "application/json"},
            body='{"scope": "quick"}',
        )
        check("POST without CSRF rejected (403)", st == 403, f"status={st}")

        # 8. POST with CSRF -> 200 with real scan data
        st, _, body = req(
            "POST",
            "/api/scan",
            {
                **auth,
                "Content-Type": "application/json",
                "X-CSRF-Token": pkg._CSRF_TOKEN,
            },
            body='{"scope": "quick"}',
        )
        try:
            scan = json.loads(body)
            ok = st == 200 and scan.get("status") == "ok" and "scan" in scan
        except json.JSONDecodeError:
            ok = False
        check("POST with CSRF returns scan (200)", ok, f"status={st}")

        # 9. /api/search (GET) -> 200 JSON
        st, _, body = req("GET", "/api/search?q=test", auth)
        try:
            srch = json.loads(body)
            ok = st == 200 and srch.get("status") == "ok" and "results" in srch
        except json.JSONDecodeError:
            ok = False
        check("/api/search returns JSON (200)", ok, f"status={st}")

        # 10. /api/stix -> 200 JSON list
        st, _, body = req("GET", "/api/stix", auth)
        try:
            stix = json.loads(body)
            ok = st == 200 and isinstance(stix, list)
        except json.JSONDecodeError:
            ok = False
        check("/api/stix returns JSON list (200)", ok, f"status={st}")

        # 11. Rate limit: flood POSTs -> some 429
        seen_429 = False
        for _ in range(35):
            st, _, _ = req(
                "POST",
                "/api/scan",
                {
                    **auth,
                    "Content-Type": "application/json",
                    "X-CSRF-Token": pkg._CSRF_TOKEN,
                },
                body='{"scope": "quick"}',
            )
            if st == 429:
                seen_429 = True
                break
        check("rate limit trips (429)", seen_429)

        passed = sum(1 for _, ok, _ in CHECKS if ok)
        print(f"\n{passed}/{len(CHECKS)} E2E checks passed")
        return 0 if passed == len(CHECKS) else 1
    finally:
        server.shutdown()
        server.server_close()
        pkg._CORE = None


if __name__ == "__main__":
    raise SystemExit(main())
