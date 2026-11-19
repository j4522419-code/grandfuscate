# Loadstring publisher setup

This is the setup guide for the **make it a loadstring!** button in the web UI.

The button does **not** paste the whole obfuscated script into a giant Lua string.
It uploads the finished obfuscated output to a public GitHub raw file, then shows
a one-line executor-style loader:

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/YOU/REPO/<commit-sha>/loadstrings/<id>.luau"))()
```

**Copy loadstring** copies only that line.

> `loadstring` and `game:HttpGet` are executor-style APIs. They are not standard
> Roblox Studio / vanilla Luau features. Nothing here is a live-executor
> certification or an unbreakable-protection claim.

---

## What was implemented

- `web/index.html`
  - `make it a loadstring!` button below the Output pane.
  - readonly loadstring box.
  - `Copy loadstring` button underneath it.
  - stale loadstring is cleared whenever you obfuscate again or upload a new input.
  - no explanatory helper text under the button; the guide is still served at `/LOADSTRINGS.md`.
- `obf/publish.py`
  - server-side GitHub raw publisher.
  - Base64 upload via GitHub contents API.
  - commit-SHA-pinned raw URL.
  - Lua string escaping.
  - clean errors for missing config, oversized output and GitHub failures.
- `obf/web.py`
  - new protected `POST /api/loadstring`.
  - same `OBF_API_KEY`, rate limit, body cap, CORS and CSP as the other `/api/*` routes.
  - `/api/meta` and `/api/health` report `loadstring_publish`.
  - `/LOADSTRINGS.md` is served as a static setup guide.
- `render.yaml`
  - placeholder env keys for the publisher.
  - the GitHub token is `sync: false`; never commit a real token.
- `tests/test_publish.py`
  - mocked GitHub tests; no real network calls or secrets.

The obfuscated production chunk itself still starts with `return`, contains zero
comments and does **not** call `loadstring`, `load` or `require`. The loader is a
separate wrapper generated only after you click the new button.

---

## Cost

**$0.**

You need only:

- a free GitHub account,
- one free public GitHub repo,
- one free fine-grained GitHub personal access token,
- your existing free Render web service.

No paid Render disk, no GitHub Pro, no paid paste host and no external database.

Render's free filesystem is ephemeral, so the raw file is stored on GitHub, not
on Render. Existing loadstrings keep working even when the free Render service
spins down.

---

## 1. Create the public raw repo

1. Go to https://github.com/new.
2. Name it something like `grandfuscate-loads`.
3. Set it to **Public**.
4. Check **Add a README file** so the default branch exists.
5. Create the repository.

The repo must be public because `game:HttpGet` fetches the raw URL without a
GitHub token. Do not put secrets in this repo.

---

## 2. Create the fine-grained GitHub token

Go to:

```text
https://github.com/settings/personal-access-tokens/new
```

Or:

```text
GitHub → profile picture → Settings
→ Developer settings
→ Personal access tokens
→ Fine-grained tokens
→ Generate new token
```

Use these settings:

```text
Token name:       grandfuscate-publisher
Expiration:       90 days
Resource owner:   your GitHub username
Repository access: Only select repositories → grandfuscate-loads
```

Then expand **Permissions → Repository permissions**, find the row called
**`Contents`**, and set its dropdown to **`Read and write`**.

That is the important one. You will **not** see a literal line that says
`Repository permissions: Contents: Read and write`; the UI shows `Contents` as a
row and `Read and write` as the dropdown value. `Metadata: Read-only` is usually
added automatically; leave everything else on `No access`.

Click **Generate token** and copy it once.

Shortcut that pre-fills `Contents: write`:

```text
https://github.com/settings/personal-access-tokens/new?name=grandfuscate-publisher&description=Publish%20Grandfuscate%20loadstrings&expires_in=90&contents=write
```

You still have to select `grandfuscate-loads` under **Repository access** yourself.

---

## 3. Set the Render Environment variables

Go to:

```text
https://dashboard.render.com/
→ click the actual service, e.g. luau-obf
→ Environment in the service's left pane
→ + Add Environment Variable
```

If you do not see **Environment**, you are probably on the **Blueprint page** or
the dashboard home rather than inside the service. Click the service card first.
It is not under `Settings`.

Add these:

| Key | Value |
|---|---|
| `OBF_GITHUB_TOKEN` | the fine-grained token you just copied |
| `OBF_GITHUB_OWNER` | your GitHub username |
| `OBF_GITHUB_REPO` | `grandfuscate-loads` |
| `OBF_GITHUB_BRANCH` | `main` |
| `OBF_GITHUB_PATH` | `loadstrings` |
| `OBF_MAX_PUBLISH` | `16777216` |

Keep all your existing variables too, especially:

```text
OBF_API_KEY=your-existing-shared-secret
OBF_MAX_SOURCE=...
OBF_MAX_BODY=...
OBF_TIMEOUT=...
OBF_RATE_LIMIT=24
OBF_ALLOWED_ORIGIN=...
```

You can paste several at once with **Add from .env**, but do not commit that
`.env` file. Delete it after pasting.

After saving, choose **`Save and deploy`** for env-var-only changes. Use
**`Save, rebuild, and deploy`** after pushing the updated code. `Save only` will
not restart the service, so the app will not see the new variables until the next
deploy.

### Existing Blueprint note

`render.yaml` uses `sync: false` for `OBF_GITHUB_TOKEN`. Render prompts for those
values only during **initial** Blueprint creation. When you update an existing
Blueprint, Render ignores new `sync: false` variables, so add the new secret and
owner/repo values manually on the service's **Environment** page as above. Do not
hardcode the token in `render.yaml`.

---

## 4. Push the updated code

This guide is shipped with the rebuilt bundles. Render auto-deploys only after
you replace your old repo contents with the new bundle and push to `main`.

On Windows PowerShell, for the existing repo connected to `luau-obf`:

```powershell
cd $env:USERPROFILE
Remove-Item -Recurse -Force .\luau-obf-update, .\grandfuscate-unzip -ErrorAction SilentlyContinue
gh auth login
git clone https://github.com/YOUR_USERNAME/YOUR_EXISTING_REPO.git luau-obf-update
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\grandfuscate-github-repo.zip" -DestinationPath "$env:USERPROFILE\grandfuscate-unzip" -Force
cd .\luau-obf-update
Get-ChildItem -Force -Exclude .git | Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath "$env:USERPROFILE\grandfuscate-unzip\grandfuscate" -Force | Copy-Item -Destination . -Recurse -Force
git add -A
git commit -m "Grandfuscate: loadstring publisher"
git push origin main
```

Replace `YOUR_USERNAME` and `YOUR_EXISTING_REPO` before running the commands.
If your existing branch is not `main`, replace `main` with that branch name.
See `WINDOWS-STEP-BY-STEP.md` for the new-repo path.

You must do this push yourself. Arena did not create a GitHub repo, did not add a
remote, did not push and did not create a Render service.

---

## 5. Use the button

1. Open your Render URL, e.g. `https://luau-obf.onrender.com`.
2. Enter your `OBF_API_KEY` in the top **API key** field.
3. Paste source into **Input**.
4. Click **Obfuscate**.
5. Click **make it a loadstring!**
6. Wait for `Published (... bytes). Copy the loadstring above.`
7. Click **Copy loadstring**.

The raw URL appears under the copy button. The generated loader is pinned to the
exact commit SHA returned by GitHub, so later commits do not silently change that
build.

---

## 6. Verify

Check meta:

```text
GET https://YOUR-SERVICE.onrender.com/api/meta
```

You should see:

```json
"loadstring_publish": {
  "enabled": true,
  "backend": "github",
  "requires_api_key": true,
  "max_publish_bytes": 16777216,
  "wrapper": "loadstring(game:HttpGet(<pinned raw url>))()"
}
```

If `enabled` is `false`, one or more of `OBF_GITHUB_TOKEN`,
`OBF_GITHUB_OWNER` or `OBF_GITHUB_REPO` is missing.

---

## 7. Security and sharing

- The GitHub token stays only in Render Environment. It is never sent to the browser.
- Friends need your `OBF_API_KEY` to **generate** a new loadstring. They do not need the GitHub token.
- Anyone who has the final loadstring can fetch the public raw file.
- A public raw URL exposes the obfuscated output. Do not put secrets in the source.
- Rotating `OBF_API_KEY` stops people using the site; it does not delete existing raw files.
- To kill an old loader, delete/rename the raw file or make the repo private.
- Revoking the GitHub token stops new publishes; existing raw files remain until you delete them.
- Rate limits still apply: the app's per-IP limit plus GitHub's API limits.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Loadstring publishing is not configured` | Add `OBF_GITHUB_TOKEN`, `OBF_GITHUB_OWNER`, `OBF_GITHUB_REPO` in Render → service → Environment, then redeploy. |
| `Obfuscate first.` | Click **Obfuscate** before **make it a loadstring!**. |
| `output is ... bytes; publish limit is ...` | Raise `OBF_MAX_PUBLISH`, or use a smaller preset. |
| `GitHub rejected the token (401)` | The token is wrong, expired or revoked. Generate a new fine-grained token. |
| `GitHub denied the request (403)` | Check that the token selects `grandfuscate-loads`, has `Contents: Read and write`, and is not rate-limited. |
| `GitHub returned 404` | Check `OBF_GITHUB_OWNER`, `OBF_GITHUB_REPO`, `OBF_GITHUB_BRANCH`, and that the repo is public with a README/default branch. |
| `GitHub rejected the upload (422)` | Make sure the repo has a default branch; try again after the first commit exists. |
| raw URL 404s immediately | Wait a few seconds for GitHub raw propagation, then refresh. |
| `API key required` | Enter the same `OBF_API_KEY` in the top **API key** field. |
| Button works locally but says not configured | Local runs usually have no `OBF_GITHUB_*` vars. Configure them only if you want local publishing; the normal obfuscator still works. |

---

## 9. Caveats

- Executor-style only: `loadstring` is not standard Roblox Studio.
- `game:HttpGet` must be available and allowed to reach `raw.githubusercontent.com`.
- GitHub raw is fine for a hobby loader, not a high-traffic CDN.
- Public output remains recoverable to a capable debugger; this is obfuscation, not encryption or real security.
- Real security requires server-side authority.
