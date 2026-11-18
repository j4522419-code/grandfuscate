# Grandfuscate: GitHub → Render deployment guide

Prepared 2026-11-18 (Pacific/Auckland). **No push, GitHub repository, remote, or Render service has been created.** Arena’s GitHub and Render connectors are currently unsupported, so this is a manual guide plus downloadable bundles.

**Windows users:** use `WINDOWS-STEP-BY-STEP.md` and `grandfuscate-windows.zip`. `unzip`, `./setup-local.sh`, and `PORT=8000 ...` are Bash/Linux commands and will not work in Windows CMD.

The partial “uncap” edits were reverted. The app is back to its verified third-pass state: `OBF_MAX_SOURCE=262144`, `OBF_MAX_BODY=16777216`, `MAX_IDENTIFY=8388608` (hard-coded), and `OBF_TIMEOUT=60` by default. Small CLI builds and the 67-check third-pass probe were verified unchanged after the revert.

---

## 1. Downloads

### From this workspace

| File | What it is | Use it for |
|---|---|---|
| `grandfuscate-github-repo.zip` | Clean source bundle: no `.git`, no `tools/`, no caches/zip files | Uploading to GitHub |
| `grandfuscate-windows.zip` | Source bundle plus official Luau 0.747 **Windows** tools and `.bat`/`.ps1` scripts | Native Windows 10/11 local testing |
| `grandfuscate-local-with-tools.zip` | Same source bundle plus the official **Linux** `tools/` Luau binaries | Linux or WSL local testing only |
| `WINDOWS-STEP-BY-STEP.md` | Exact PowerShell and CMD commands | Windows users |
| `DOWNLOADS-AND-DEPLOY.md` | This guide | Instructions |
| `render-large-source.env.example` | Environment-variable template | Copy into Render’s Environment panel |
| `setup-local.sh` | Recreates the baseline `tools` symlink and optionally runs the self-test | Local testing |
| `SHA256SUMS.txt` | SHA-256 checksums for the two zip files | Verifying downloads |

In the Arena workspace, open the file list, click a file, and use the download control. The Markdown guide previews in-app; the `.zip` files are downloads.

### External tools you may want

| Tool | Link | Needed for |
|---|---|---|
| Git | https://git-scm.com/downloads | Pushing from a terminal |
| GitHub CLI (`gh`) | https://cli.github.com/ | Option A below |
| GitHub Desktop | https://desktop.github.com/ | GUI alternative |
| Python 3.13 | https://www.python.org/downloads/windows/ | Local run / Render build |
| Luau releases | https://github.com/luau-lang/luau/releases | Optional manual toolchain download |
| Render | https://dashboard.render.com/ | Deployment |
| Render Blueprint docs | https://render.com/docs/blueprint-spec | `render.yaml` reference |

`render.yaml` already runs `python3 obf/fetch_tools.py` during the build, so you normally do **not** need to download Luau manually for Render. `tools/` is gitignored. `fetch_tools_windows.py` is included only for native Windows local runs; Render is Linux and uses the normal Linux asset.

---

## 2. Current local state

- Git remotes: `0`
- HEAD: `68592e7 Grandfuscate: single VM runtime with light/medium/heavy presets`
- Changed/untracked entries after the revert and guide files: see `git status --short`
- No commit, push, GitHub repo, or Render service created here
- Local preview is still available on port 8000 only

The full CLI self-test was previously `ALL GREEN, 0 failures`. After the revert, `python3 -m compileall -q obf tests`, the three example builds, and `tests/anti_analysis_v3.py` (67 checks) were rechecked OK. The 15-minute full suite was not rerun for this guide.

---

## 3. Test locally first

### Option A: Windows, exact steps

See `WINDOWS-STEP-BY-STEP.md`. In short, open PowerShell and use:

```powershell
cd $env:USERPROFILE\Downloads
Expand-Archive -Path .\grandfuscate-windows.zip -DestinationPath $env:USERPROFILE\grandfuscate-windows -Force
cd $env:USERPROFILE\grandfuscate-windows\grandfuscate
powershell -ExecutionPolicy Bypass -File .\setup-local.ps1
powershell -ExecutionPolicy Bypass -File .\start-local.ps1
```

Or use `setup-local.bat` and `start-local.bat` from CMD.

### Option B: Linux / WSL bundle with tools

```bash
unzip grandfuscate-local-with-tools.zip
cd grandfuscate
./setup-local.sh
PORT=8000 OBF_MAX_SOURCE=10485760 OBF_TIMEOUT=300 python3 -m obf.web
```

Then open `http://127.0.0.1:8000/` or check:

```bash
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/meta
```

`setup-local.sh` recreates `tests/baseline/tools -> ../../tools` if the symlink was not preserved by unzip. It does not push or deploy anything.

### Option C: clean GitHub bundle without tools

```bash
unzip grandfuscate-github-repo.zip
cd grandfuscate
python3 obf/fetch_tools.py
PORT=8000 OBF_MAX_SOURCE=10485760 OBF_TIMEOUT=300 python3 -m obf.web
```

If you want the full verification suite:

```bash
PYTHONPATH=. python3 -m obf.cli --self-test
```

Expect roughly 15 minutes. Do not run it on Render’s build step; it is a local verification command.

---

## 4. Push to GitHub

### Option A: GitHub CLI, recommended

Install Git and GitHub CLI, then:

```bash
unzip grandfuscate-github-repo.zip
cd grandfuscate

git init -b main
git add .
git commit -m "Grandfuscate: third-pass hardening and deployment files"

gh auth login
gh repo create grandfuscate --public --source=. --remote=origin --push
```

Use `--private` instead of `--public` if you want a private repo. If the repository already exists, create it empty at https://github.com/new first, then:

```bash
git remote add origin https://github.com/<your-username>/grandfuscate.git
git push -u origin main
```

### Option B: use the included helper

After creating an empty GitHub repository:

```bash
unzip grandfuscate-github-repo.zip
cd grandfuscate
chmod +x push_to_github.sh
./push_to_github.sh https://github.com/<your-username>/grandfuscate.git
```

The helper sets a repo-local Git identity, commits the current tree, adds `origin`, and pushes `main`. It will refuse to push if `origin` is already set.

### Before pushing

- Do not add real secrets to the repo. Set `OBF_API_KEY` only in Render’s Environment panel.
- `tools/` is gitignored; Render downloads it during the build.
- `*.keys.json` is ignored except the bundled `examples/keys*.json`; those example keys are not production secrets.
- GitHub Pages alone is not enough: the UI calls same-origin `/api/*` endpoints and the backend is Python.

---

## 5. Deploy on Render

### Blueprint path, recommended

1. Go to https://dashboard.render.com/.
2. Click **New → Blueprint**.
3. Connect your GitHub account and select the `grandfuscate` repo, branch `main`.
4. Render reads `render.yaml`:
   - `type: web`, `runtime: python`, free plan
   - build: `pip install -r requirements.txt && python3 obf/fetch_tools.py`
   - start: `python3 -m obf.web`
   - health check: `/api/health`
5. Set environment variables before applying, or edit them after creation under **Environment**.
6. Click **Apply** / **Create Resources**.
7. Wait for the first deploy. Free-tier cold starts can take roughly 30–60 seconds.

Render supplies `PORT`; do not set it manually. The app binds to `0.0.0.0`.

### Environment variables

| Key | Value currently in `render.yaml` | Suggested value if you need the 1,463,380-byte source | Notes |
|---|---:|---:|---|
| `OBF_MAX_SOURCE` | `262144` | `10485760` | Must be larger than your source. This is the error you hit. |
| `OBF_MAX_BODY` | `16777216` | `16777216` or higher | JSON request-body cap; 16 MiB already covers 1.46 MB. |
| `OBF_TIMEOUT` | `60` | `300` | Parse/generate budget for large local sources. |
| `OBF_RATE_LIMIT` | `24` | `24` | Requests per minute. |
| `OBF_ALLOWED_ORIGIN` | `*` | `https://<your-service>.onrender.com` | Tighten CORS after you know the URL. |
| `OBF_API_KEY` | blank / `sync: false` | long random secret | Set only in Render; send as `X-API-Key`. |
| `OBF_MAX_IDENTIFY` | not present | not supported | After the revert, identify size is hard-coded to 8 MiB in `obf/web.py`. |

Copy-paste template: see `render-large-source.env.example`.

Important: the revert restored the default 256 KiB source cap. Setting `OBF_MAX_SOURCE` in Render raises it for that deployment only; it does not modify the checked-in code. If you also want `/api/identify` to accept files larger than 8 MiB, that requires a separate code change.

### Docker alternative

`Dockerfile` is included. To use it, choose Docker runtime in Render or change `render.yaml` to `runtime: docker`. It also runs `python3 obf/fetch_tools.py` at build time. The Blueprint path is simpler and already configured.

---

## 6. Smoke-test the deployed service

Replace `URL` with your Render URL. If you set `OBF_API_KEY`, include the `X-API-Key` header; otherwise remove that line.

```bash
URL="https://<your-service>.onrender.com"

curl -sS "$URL/api/health"
curl -sS "$URL/api/meta"

curl -sS -X POST "$URL/api/obfuscate" \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: YOUR_RENDER_API_KEY' \
  --data-binary '{"source":"print(\"live\", 6*7)\n","preset":"light","seed":20261118,"verify":true}'
```

Expected:

- `/api/health` returns `{"ok":true,...}`
- `/api/meta` lists `["light","medium","heavy"]`
- `/api/obfuscate` returns `ok: true`, `syntax.ok: true`, and an `output` string starting with `return`
- Running that output with `tools/luau` prints `live	42`

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `source is 1463380 bytes; the public limit is 262144 bytes` | Set `OBF_MAX_SOURCE` above 1,463,380 in Render, e.g. `10485760`, then redeploy/restart. |
| `request body missing or too large` | Raise `OBF_MAX_BODY`. |
| `obfuscation timed out` | Raise `OBF_TIMEOUT` to `300` or higher. |
| `API key required` | Send `X-API-Key: <your Render secret>` or clear `OBF_API_KEY`. |
| Build fails downloading Luau | Check Render outbound access to GitHub releases; retry deploy. `tools/` is fetched by `obf/fetch_tools.py`. |
| CORS error in browser | Set `OBF_ALLOWED_ORIGIN` to the exact Render URL. |
| `/api/identify` rejects a large generated file | Identify cap is hard-coded to 8 MiB after the revert; ask for a code change if needed. |
| GitHub Pages shows a static page but API fails | Use Render or another Python host; the backend is not static. |
| Free tier feels slow on first request | Expected cold start; wait 30–60 seconds and retry. |

---

## 8. Final checklist

- [ ] Downloaded `grandfuscate-github-repo.zip` or `grandfuscate-local-with-tools.zip`
- [ ] Verified checksum against `SHA256SUMS.txt`
- [ ] Tested locally with `/api/health` and `/api/meta`
- [ ] Created an empty GitHub repo
- [ ] Pushed `main` with `git push -u origin main` or `gh repo create ... --push`
- [ ] Created Render Blueprint from `render.yaml`
- [ ] Set `OBF_MAX_SOURCE`, `OBF_MAX_BODY`, `OBF_TIMEOUT`, `OBF_ALLOWED_ORIGIN`, `OBF_API_KEY`
- [ ] Smoke-tested `/api/health`, `/api/meta`, `/api/obfuscate`
- [ ] No secrets committed to GitHub

This remains client-side Luau obfuscation, not encryption or real security. A capable executor-specific debugger can still inspect runtime values; real security needs server-side authority. No commercial or live Roblox executor certification is claimed.
