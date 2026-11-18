# Deployment status: local-only

Deployment is paused by user instruction. **No Git remote, push, GitHub repo or
Render service has been created.** The third-pass hardening is local-only too; the app runs locally and in the
workspace live preview only.

## Prepared but inactive

- `render.yaml` — Render Blueprint using `type: web`, `runtime: python`, free
  plan, health check `/api/health`.
- `requirements.txt` — intentionally empty; the service uses the Python stdlib.
- `.python-version` — Python 3.13.
- `Dockerfile` — optional container build.
- `obf/fetch_tools.py` — downloads official Luau 0.747 at build time; `tools/`
  is gitignored.
- `push_to_github.sh` — helper script only; it has not been run.

## Local run

```bash
PORT=8000 OBF_TIMEOUT=60 python3 -m obf.web
```

Bind to `0.0.0.0` for the workspace preview. The service parses and
compile-checks untrusted Luau; it never executes user Luau. Body/source caps,
rate limits, concurrency limits, CORS, CSP, `no-store` and `nosniff` are
enabled. Temp files are deleted.

## If deployment is explicitly resumed

1. Confirm the user wants a remote and hosting account.
2. Create a GitHub repository and add the origin.
3. Push the local `main` branch.
4. Create the Render Blueprint from `render.yaml`.
5. Smoke-test `/api/health`, `/api/meta` and `/api/obfuscate`.
6. Expect a Render free-tier cold start of roughly 30–60 seconds.

GitHub Pages alone is insufficient: the UI calls same-origin API endpoints and
the backend is a Python web service, not a static site.

## Security caveat

The API does not execute user Luau, but generated output is still client-side
obfuscation. It is not real security. Roblox scripts need server-side authority.
