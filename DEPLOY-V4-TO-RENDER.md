# Deploy the V4 build to your existing Render service

Prepared 2026-11-19 (Pacific/Auckland). **This is a manual guide.** Arena's
GitHub and Render connectors are unsupported in this session, and no push,
deploy, repository, remote, token or new service was created for you. You run
the git commands; Render deploys from the commit you push.

**What you are deploying:** the V4 build — VM integrity verification (private
canonical manifest + seven bounded 96-step window checks), opaque decoy traps
(wrong-ticket controlled error, valid-ticket harmless default), and high-entropy
`!@^&#%...` output inside valid Luau string literals. Full local test suite:
**ALL GREEN, 0 failures** (`TEST-RESULTS-v4-full-suite.txt`). Also included:
the conservative cap increases `OBF_MAX_BODY=33554432` (32 MiB) and
`OBF_MAX_PUBLISH=16777216` (16 MiB). No other default changed —
`OBF_MAX_SOURCE=262144`, `OBF_TIMEOUT=60`, presets/aliases, `OBF_API_KEY`,
`OBF_GITHUB_*` and the hard-coded 8 MiB identify cap are all unchanged.

Your existing setup (from the earlier loadstring/UI-cleanup deploy):
- GitHub app-code repo: `grandfuscate`, branch `main`
- Render service: `luau-obf` (Blueprint from `render.yaml`, runtime `python`,
  free plan, region Singapore, `autoDeployTrigger: commit`)
- Optional raw-loadstring repo: `grandfuscate-loads`

---

## 0. What I prepared for you (no action needed on your side yet)

- A **rebuilt `grandfuscate-github-repo.zip`** containing the complete V4
  source tree (including the new `obf/entropy.py`, `obf/vm/traps.py`,
  `obf/vm/integrity.py`, `tests/vm_integrity_v4.py`,
  `tests/high_entropy_v4.py` and the V4 reports). This is the clean GitHub
  bundle: no `tools/` folder, no `.git`.
- Fresh temporary download links in `PUBLIC-DOWNLOAD-LINKS.md` and in chat.
- `SHA256SUMS.txt` refreshed so you can verify the download.

Links are temporary (tmpfiles.org). If one has expired, tell me and I will
refresh it — the ZIPs themselves stay in the workspace.

---

## 1. Download the V4 bundle

Use the **new** `grandfuscate-github-repo.zip` link from chat or
`PUBLIC-DOWNLOAD-LINKS.md` (the 03:29 UI-cleanup links are stale and do **not**
contain V4).

PowerShell:

```powershell
$url = "PASTE_THE_NEW_grandfuscate-github-repo.zip_DIRECT_URL"
Invoke-WebRequest -Uri $url -OutFile "$env:USERPROFILE\Downloads\grandfuscate-github-repo.zip"
```

Optional integrity check (PowerShell):

```powershell
Get-FileHash "$env:USERPROFILE\Downloads\grandfuscate-github-repo.zip" -Algorithm SHA256
```

Compare with the `grandfuscate-github-repo.zip` line in `SHA256SUMS.txt`.

> Windows CMD alternative: `curl -L -o "%USERPROFILE%\Downloads\grandfuscate-github-repo.zip" "PASTE_URL"`
> Linux/macOS: `curl -L -o ~/Downloads/grandfuscate-github-repo.zip "PASTE_URL"`

---

## 2. Put the V4 files into your existing local clone

This preserves `.git` and your existing `origin`. It does **not** force-push.
Do not keep uncommitted work in this clone — the copy overwrites files.

### Windows PowerShell (recommended)

```powershell
cd $env:USERPROFILE
Remove-Item -Recurse -Force .\grandfuscate-unzip -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\grandfuscate-github-repo.zip" -DestinationPath "$env:USERPROFILE\grandfuscate-unzip" -Force

# Point this at your existing clone (the one already connected to Render):
cd "$env:USERPROFILE\luau-obf-update"

Get-ChildItem -LiteralPath "$env:USERPROFILE\grandfuscate-unzip\grandfuscate" -Force |
    Copy-Item -Destination . -Recurse -Force

git status --short
```

`git status --short` should list the V4 changes (modified `obf/*`, `render.yaml`,
docs, examples, plus new `obf/entropy.py`, `obf/vm/traps.py`,
`obf/vm/integrity.py`, `tests/*_v4.py`, V4 reports). If it shows **no** changes,
you extracted the old bundle — re-download from the new link.

> Prefer the "replace everything" variant used in `WINDOWS-STEP-BY-STEP.md` §8?
> That also works: delete all non-`.git` entries first, then copy. Just be
> aware it removes any extra files you keep in that clone.

### Linux / macOS / WSL

```bash
cd ~
rm -rf grandfuscate-unzip
unzip ~/Downloads/grandfuscate-github-repo.zip -d ~/grandfuscate-unzip
cd ~/luau-obf-update          # your existing clone
cp -a ~/grandfuscate-unzip/grandfuscate/. .
git status --short
```

### Option: no local clone

If you don't have the clone any more, clone it first, then run the copy:

```powershell
cd $env:USERPROFILE
git clone https://github.com/YOUR_USERNAME/grandfuscate.git luau-obf-update
```

(Replace `YOUR_USERNAME`.) Then continue with the copy commands above.

---

## 3. Quick local sanity check (optional but recommended)

Before pushing, confirm the V4 files really are in place and importable:

```powershell
cd "$env:USERPROFILE\luau-obf-update"
py -3 -c "from obf import entropy; from obf.vm import traps, integrity; print('V4 modules OK')"
py -3 -m obf.cli examples/sample.luau --preset light --seed 20261118 --verify --quiet
```

Expect `V4 modules OK`. The CLI build should print no error (`--verify`
compile-checks the output with `luau-compile`). If `luau-compile` is missing
locally, that's fine — Render fetches the Linux tools during its build; skip
`--verify` or use the Windows bundle's `tools\` folder.

---

## 4. Commit and push

```powershell
cd "$env:USERPROFILE\luau-obf-update"
git add -A
git commit -m "V4: VM integrity, decoy traps, high-entropy output and cap raises"
git push origin main
```

If your branch is not `main`, replace `main` with your branch name. If `origin`
is not configured yet, `git remote -v` will show nothing — add it with
`git remote add origin https://github.com/YOUR_USERNAME/grandfuscate.git` first.

`render.yaml` has `autoDeployTrigger: commit`, so Render starts a deploy
automatically. If your service does not auto-deploy, open
**Render Dashboard → `luau-obf` → Manual Deploy → Deploy latest commit**.

Free-tier cold starts take roughly 30–60 seconds; the first build also runs
`pip install -r requirements.txt && python3 obf/fetch_tools.py`.

---

## 5. Update the two Render environment values

Go to **Render Dashboard → `luau-obf` → Environment** and set:

| Key | New value |
|---|---|
| `OBF_MAX_BODY` | `33554432` |
| `OBF_MAX_PUBLISH` | `16777216` |

Then click **Save Changes** (Render restarts the service). These are the
`raise_both` cap increases — conservative guards, not permission for huge
outputs; V4 outputs stay well under 1 MiB.

**Leave these exactly as they are** (they are `sync: false` secrets or already
correct): `OBF_API_KEY`, `OBF_GITHUB_TOKEN`, `OBF_GITHUB_OWNER`,
`OBF_GITHUB_REPO`, `OBF_GITHUB_BRANCH`, `OBF_GITHUB_PATH`,
`OBF_MAX_SOURCE=262144`, `OBF_TIMEOUT=60`, `OBF_RATE_LIMIT`,
`OBF_ALLOWED_ORIGIN`. Do not set `PORT` (Render supplies it) and do not set
`OBF_MAX_IDENTIFY` (not supported; identify stays hard-coded at 8 MiB).

> Blueprint note: both new values are also in `render.yaml` as synced `value:`
> entries, so a **Blueprint → Sync** would apply them too. Setting them
> manually works whether or not you sync, and the values match either way.
> Render does **not** back-fill `sync: false` secret values — those stay as you
> set them.

---

## 6. Smoke-test the deployed V4 service

PowerShell (replace `YOUR-SERVICE`; drop `-Headers` if `OBF_API_KEY` is blank):

```powershell
$URL   = "https://YOUR-SERVICE.onrender.com"
$heads = @{ "X-API-Key" = "YOUR_RENDER_API_KEY" }

# 1. Liveness + new caps (proof the V4 code/limits are live)
Invoke-RestMethod "$URL/api/health"
$meta = Invoke-RestMethod "$URL/api/meta"
$meta.limits.max_body_bytes       # expect 33554432
$meta.limits.max_publish_bytes    # expect 16777216
$meta.loadstring_publish.enabled  # expect True if your GitHub token is set

# 2. Obfuscate a tiny program
$body = @{
  source = "print(`"live`", 6*7)`n"
  preset = "light"
  seed   = 20261118
  verify = $true
} | ConvertTo-Json
$r = Invoke-RestMethod -Method Post -Uri "$URL/api/obfuscate" `
       -Headers $heads -ContentType "application/json" -Body $body

$r.ok            # True
$r.syntax.ok     # True
$r.output.Substring(0, 6)   # "return"

# 3. V4 signature: high-entropy long-bracket markers must be present
$r.output -match '\[=+\['     # True  (long-bracket string literals)
$r.output -match '[!@^&#%]{8,}'  # True (symbol soup inside those literals)
```

Expected: `/api/health` → `ok: true`; `/api/meta` → `light`/`medium`/`heavy`
and the two new cap values; `/api/obfuscate` → `ok: true`, `syntax.ok: true`,
output starting with `return`, containing long-bracket `!@^&#%...` soup.
Running that output prints `live\t42`. The copy/loadstring buttons should still
work unchanged.

If step 3 is `False`, the old build is still live — check the deploy status and
that you pushed to the branch Render watches.

---

## 7. Rollback (if anything looks wrong)

In your clone:

```powershell
git revert --no-edit HEAD
git push origin main
```

Or in Render: **Manual Deploy → pick the previous commit**. You do not need to
change the environment values back; the larger caps are harmless to the old
build.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `git push` asks for credentials | `gh auth login`, or use a GitHub PAT as the password. |
| `git status --short` empty after copy | You extracted the stale 03:29 bundle; re-download from the **new** link. |
| Render build fails fetching Luau | Needs outbound access to GitHub releases; retry the deploy. |
| `/api/meta` still shows `16777216` / `8388608` | Env values were not saved, or the old deploy is live; re-check §5 and deploy status. |
| `API key required` | Send `X-API-Key`, or clear `OBF_API_KEY` in Render Environment. |
| `Loadstring publishing is not configured` | Re-check `OBF_GITHUB_TOKEN` / `OWNER` / `REPO` in Render → Environment, then redeploy. |
| `source is ... public limit ...` | Raise `OBF_MAX_SOURCE` for that deployment only (unchanged checked-in default is 256 KiB). |
| Output lacks the `!@^&#%` soup | The pre-V4 build is running; confirm the pushed commit and branch. |
| Link expired / 404 | Ask me to refresh `PUBLIC-DOWNLOAD-LINKS.md`. |

---

## 9. Checklist

- [ ] Downloaded the **new** `grandfuscate-github-repo.zip` (V4), verified SHA-256
- [ ] Copied V4 files into the existing clone; `git status --short` shows V4 changes
- [ ] `git add -A && git commit && git push origin main`
- [ ] Render deploy succeeded (auto or manual)
- [ ] `OBF_MAX_BODY=33554432`, `OBF_MAX_PUBLISH=16777216` set and saved
- [ ] `/api/health`, `/api/meta` caps, `/api/obfuscate` output + V4 soup verified
- [ ] `OBF_API_KEY` and the three `OBF_GITHUB_*` secrets left untouched

No GitHub repo, remote, push, token or Render service was created here. The
existing 03:29 UI-cleanup bundles/links are superseded by the V4 links in
`PUBLIC-DOWNLOAD-LINKS.md`. This remains client-side Luau obfuscation, not
encryption or real security.
