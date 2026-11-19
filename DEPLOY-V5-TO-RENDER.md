# Deploy the V5 stealth build to your existing Render service

> **Bundled copy note:** a guide inside the ZIP cannot contain that ZIP's
> own SHA-256 or the stable page URL created by uploading it without
> making the hash self-referential. The `$page` and `$want` lines below are
> therefore normalized in this bundled copy. Use the separately published
> `DEPLOY-V5-TO-RENDER.md` or `PUBLIC-DOWNLOAD-LINKS.md` for the current
> page and exact hash, and do not run the snippet with placeholders.


**This is a manual guide.** Arena's GitHub and Render connectors are
unsupported in this session, and no push, deploy, repository, remote, token or
new service was created for you. You run the git commands; Render deploys from
the commit you push.

The V4 build is already live at `https://luau-obf.onrender.com` (commit
`97d767a`). V5 adds an **opt-in** stealth / fail-closed mode; it is **off by
default**. Deploying V5 makes the flag available on the service; you must send
`"stealth": true` (or `"fail_closed": true`) in `/api/obfuscate` to use it.
There is no new UI checkbox in this build.

> Hard boundary: V5 makes the protected script fail closed (opaque error /
> yield / garbage) and feeds malformed bait to an enumerating env logger. It
> cannot crash the external logger process from inside Luau, and no 100%
> dumper/env-logger defeat claim is made. See `REPORT-stealth-v5.md`.

## What is in the V5 bundle

- `obf/vm/stealth.py` — active decoys embedded in the real handler tables and
  guard path, not a separate inert table.
- Four reaction classes across the decoy minefield: `error`, `yield`,
  `garbage`, `error+poison`.
- `obf/layout.py`, `obf/runtime.py`, `obf/vm/runtime.py`, `obf/vm/integrity.py`,
  `obf/pipeline.py`, `obf/render.py`, `obf/format.py`, `obf/web.py`,
  `obf/cli.py`, `tests/*` — V5 wiring, alias rewriting, API/CLI flags, tests.
- `PLAN-stealth-v5.md`, `REPORT-stealth-v5.md`,
  `TEST-RESULTS-stealth-v5.txt`, `TEST-RESULTS-v5-full-suite.txt`.
- Full suite: **ALL GREEN, 507 checks, 0 failures**. Standalone V5: **92 checks,
  ALL GREEN**.

No environment-variable changes are required. Keep `OBF_API_KEY`, the three
`OBF_GITHUB_*` secrets, `OBF_MAX_BODY=33554432` and
`OBF_MAX_PUBLISH=16777216` exactly as they are. `render.yaml` still has
`autoDeployTrigger: commit`; Render's Blueprint spec can update non-secret env
values on sync while leaving `sync: false` secrets untouched [1](https://render.com/docs/blueprint-spec).

## 1. Download the V5 bundle

> **Start every PowerShell session with `$ErrorActionPreference = 'Stop'`.**
> Without it, a failed download can silently lead to an empty `git status` and
> a no-op push.

**Why this matters:** tmpfiles.org `/dl/...` links are short-lived *signed*
URLs. After expiry the server returns an HTML page with HTTP 200, and
`Expand-Archive` fails with *"End of Central Directory record could not be
found"*. Resolve a fresh signed link from the stable page at download time.

### Option A — most reliable: workspace viewer

The V5 `grandfuscate-github-repo.zip` is also in the Arena workspace viewer.
Download it straight from there (no third-party host, no expiry) into
`C:\Users\user\Downloads\`, then continue at §2. Still run the hash check
below.

### Option B — PowerShell (resolves a fresh signed link)

```powershell
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Stable page URL for the V5 GitHub source bundle (from PUBLIC-DOWNLOAD-LINKS.md):
$page  = "USE_THE_CURRENT_STABLE_PAGE_FROM_PUBLIC-DOWNLOAD-LINKS.md"
$dest  = "$env:USERPROFILE\Downloads\grandfuscate-github-repo.zip"
$want  = "USE_THE_CURRENT_SHA256_FROM_PUBLIC-DOWNLOAD-LINKS.md"
$html  = (Invoke-WebRequest -UseBasicParsing -Uri $page).Content
$dl    = [regex]::Match($html, 'href="(https://tmpfiles\.org/dl/[^"]+)"').Groups[1].Value
if (-not $dl) { throw "No download link found on $page - the mirror may have expired. Ask for a refreshed link." }
Invoke-WebRequest -UseBasicParsing -Uri $dl -OutFile $dest

$got = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
if ($got -ne $want) { throw "SHA-256 MISMATCH: got $got - expected $want. Do NOT continue." }
Write-Host "Download OK: $got"
```

The expected hash is also in `SHA256SUMS.txt`. If the file is an HTML page or
truncated, the hash check stops you **before** any git command runs. The copy of
this guide inside the ZIP is hash/page-normalized to avoid a circular checksum;
use this separately published guide or `PUBLIC-DOWNLOAD-LINKS.md` for the
current `$page` and exact `$want` values above.

> Windows CMD: use the viewer (Option A), or
> `curl -L -A "Mozilla/5.0" -o "%USERPROFILE%\Downloads\grandfuscate-github-repo.zip" "PASTE_FRESH_DL_URL"`
> then verify with `certutil -hashfile ... SHA256`.
> Linux/macOS: same page-resolve idea with `curl`/`grep`, then `sha256sum`.

## 2. Extract and copy into your existing clone

```powershell
$ErrorActionPreference = 'Stop'
cd $env:USERPROFILE
Remove-Item -Recurse -Force .\grandfuscate-v5-unzip -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\grandfuscate-github-repo.zip" `
  -DestinationPath "$env:USERPROFILE\grandfuscate-v5-unzip" -Force

cd "$env:USERPROFILE\luau-obf-update"
Get-ChildItem -LiteralPath "$env:USERPROFILE\grandfuscate-v5-unzip\grandfuscate" -Force |
  Copy-Item -Destination . -Recurse -Force

$status = git status --porcelain
if (-not $status) { throw "No changes detected - the V5 files were not copied. Aborting before commit." }
```

The `LF will be replaced by CRLF` warnings from Git are harmless line-ending
notices on Windows.

## 3. Commit + push (no force push)

```powershell
$ErrorActionPreference = 'Stop'
cd "$env:USERPROFILE\luau-obf-update"
git add -A
git commit -m "V5: opt-in stealth / active fail-closed decoys"
git push origin main
```

Render auto-deploys from the push (`autoDeployTrigger: commit`). If it does not,
use **Render → `luau-obf` → Manual Deploy → Deploy latest commit**. Do **not**
change Environment: the V4 caps and your secrets stay exactly as they are.

## 4. Verify V5 is actually live

`/api/meta.hardening.version` stays `3` — it is **not** a V5 flag. Proof is the
new `defaults.stealth` key, the authenticated `stealth` response, and the live
static docs.

### 4a. Public meta (no API key)

```powershell
$m = Invoke-RestMethod -Uri 'https://luau-obf.onrender.com/api/meta'
if ($m.defaults.stealth -ne $false) { throw "V5 meta default missing/wrong: $($m.defaults.stealth)" }
if ($m.limits.max_body_bytes -ne 33554432 -or $m.limits.max_publish_bytes -ne 16777216) {
  throw "Caps changed unexpectedly"
}
Write-Host "META OK: stealth default false, caps 32MiB/16MiB"
```

Also confirm `/api/health` is 200 and `loadstring_publish.enabled` remains true.

### 4b. Authenticated V5 obfuscation (uses your existing API key)

```powershell
$ErrorActionPreference = 'Stop'
$key  = 'PASTE_YOUR_EXISTING_OBF_API_KEY'   # never send this to the assistant
$body = @{
  source       = 'print("Hello World!")'
  preset       = 'medium'
  seed         = 20261118
  stealth      = $true       # alias: fail_closed = $true
  verify       = $true
} | ConvertTo-Json

$r = Invoke-RestMethod -Method Post `
  -Uri 'https://luau-obf.onrender.com/api/obfuscate' `
  -Headers @{ 'X-API-Key' = $key } `
  -ContentType 'application/json' `
  -Body $body

$checks = @(
  ($r.ok -eq $true),
  ($r.syntax.ok -eq $true),
  ($r.stats.stealth -eq $true),
  ($r.stats.stealth_decoys -gt 0),
  ($r.stats.anti_env -eq $false),
  ($r.stats.anti_tamper -eq $false),
  $r.output.StartsWith('return'),
  ($r.output -match '\[=+\['),
  ($r.output -match '[!@^&#%]{8,}'),
  ($r.output -notmatch 'loadstring')
)
if ($checks -contains $false) { throw "V5 output check failed: $($checks -join ',')" }
Write-Host "V5 LIVE OUTPUT CHECKS: PASS ($($r.stats.stealth_decoys) active decoys, $($r.output.Length) chars)"
```

For `preset='medium'` and `seed=20261118` the expected `stealth_decoys` is 48.
Default requests (no `stealth`) must still return `stats.stealth = false` and
`stealth_decoys = 0` — V5 is opt-in.

## 5. Rollback

V5 is opt-in; if a stealth request misbehaves you can simply stop sending
`stealth: true`. To roll the code back to V4:

```powershell
cd "$env:USERPROFILE\luau-obf-update"
git revert --no-edit <V5_COMMIT_SHA>
git push origin main
```

Or use Render → `luau-obf` → **Rollback** to the previous deploy. The V4 guide
is `DEPLOY-V4-TO-RENDER.md`; the known-good V4 commit is `97d767a`.

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `End of Central Directory record could not be found` | The `/dl/` link expired and saved HTML. Use the stable page + resolve-fresh-link snippet, or the workspace viewer. |
| `SHA-256 MISMATCH` | Re-download; do not commit. |
| `No changes detected` | The copy did not land in the clone. Check the extraction path ends in `grandfuscate-v5-unzip\grandfuscate`. |
| Push says `Everything up-to-date` | No commit was created; re-run §2/§3 with `$ErrorActionPreference = 'Stop'`. |
| `/api/meta` still lacks `defaults.stealth` | Render is still on V4 or the deploy is mid-rollout. Wait, then Manual Deploy → Deploy latest commit. |
| `stealth_decoys = 0` | You sent no `stealth`/`fail_closed` flag, or the service is still V4. |
| `401 API key required` | Use your existing `OBF_API_KEY` in the `X-API-Key` header. |

## Checklist

- [ ] V5 ZIP hash matches `SHA256SUMS.txt`.
- [ ] `git status --porcelain` is non-empty before commit.
- [ ] Commit pushed to `main`; no force push.
- [ ] Render deploy succeeded for the new commit.
- [ ] `/api/meta` has `defaults.stealth = false` and unchanged caps.
- [ ] Authenticated `stealth: true` call passes all output checks.
- [ ] Default call still has `stealth = false` / `stealth_decoys = 0`.
- [ ] `OBF_API_KEY` and `OBF_GITHUB_*` secrets were not printed or changed.

No agent commit, push, remote, token, GitHub repo or Render deploy was
performed here.
