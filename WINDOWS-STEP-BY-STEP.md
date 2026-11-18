# Windows 10/11 step-by-step: local run, GitHub, Render

Use this instead of the Bash commands. You are in `cmd.exe`; `unzip`, `./script.sh`, and `PORT=8000 ...` are not Windows syntax. Also, the earlier `grandfuscate-local-with-tools.zip` contains **Linux** Luau binaries. For native Windows, download **`grandfuscate-windows.zip`** from the workspace. It contains the official Luau 0.747 Windows tools plus `.bat`/`.ps1` scripts.

No push, GitHub repository, remote, or Render service has been created for you. This is a manual guide.

---

## 0. Why your commands failed

| You typed | Why it failed | Windows replacement |
|---|---|---|
| `unzip file.zip` | `unzip` is not installed by default | `Expand-Archive` in PowerShell |
| `cd grandfuscate` | Nothing was extracted yet, so the folder did not exist | Extract first, then `cd` into `grandfuscate-windows\grandfuscate` |
| `./setup-local.sh` | `.sh` is a Bash script and `./` is not CMD syntax | `setup-local.bat` or `.\setup-local.ps1` |
| `PORT=8000 ... python3 ...` | That is Bash environment-variable syntax | `$env:PORT="8000"` in PowerShell, or `set PORT=8000` in CMD |
| `python3` | Windows often uses `py -3` or `python` | `py -3 -m obf.web` |

---

## 1. Download the right file

From the Arena workspace, download **`grandfuscate-windows.zip`**. If you already downloaded `grandfuscate-local-with-tools.zip`, ignore it on Windows; it is for Linux/WSL.

The Windows bundle includes `tools\luau.exe`, `tools\luau-ast.exe`, `tools\luau-compile.exe`, `tools\luau-analyze.exe`, plus extensionless copies so the Python code can find them. `tools/` is gitignored and will not be pushed to GitHub; Render downloads its own Linux Luau tools during the build.

---

## 2. Open PowerShell, not CMD

Press **Win + R**, type:

```text
powershell
```

Press **Enter**. You should see a prompt like:

```text
PS C:\Users\user>
```

If you are already in CMD, just type `powershell` and press Enter.

---

## 3. Extract the ZIP

Most browsers save to `Downloads`. Run:

```powershell
cd $env:USERPROFILE\Downloads
dir *.zip
```

Find the exact name. If it is `grandfuscate-windows.zip`, run:

```powershell
Expand-Archive -Path .\grandfuscate-windows.zip -DestinationPath $env:USERPROFILE\grandfuscate-windows -Force
cd $env:USERPROFILE\grandfuscate-windows\grandfuscate
dir
```

If your browser saved it somewhere else, `cd` to that folder first. If the file is named `grandfuscate-windows (1).zip`, replace the name in the `Expand-Archive` command with the exact name shown by `dir *.zip`.

You should now see files like `README.md`, `render.yaml`, `obf\`, `tools\`, and `start-local.bat`.

---

## 4. Run the local setup script

In PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-local.ps1
```

Or, if you prefer CMD:

```cmd
setup-local.bat
```

What this does:

- verifies the Windows `tools\` binaries are present;
- if missing, runs `obf\fetch_tools_windows.py` to download Luau 0.747 Windows binaries;
- tries to recreate `tests\baseline\tools` for the optional full self-test;
- prints the next command.

The symlink is only needed for the full 15-minute self-test. If Windows blocks it, the local web app still works.

---

## 5. Start the local web app

In PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-local.ps1
```

Or, in CMD:

```cmd
start-local.bat
```

This sets:

```text
PORT=8000
OBF_MAX_SOURCE=10485760
OBF_MAX_BODY=16777216
OBF_TIMEOUT=300
```

Leave that window open. Open your browser to:

```text
http://127.0.0.1:8000/
```

In a second PowerShell window, check:

```powershell
curl.exe http://127.0.0.1:8000/api/health
curl.exe http://127.0.0.1:8000/api/meta
```

Use `curl.exe`, not `curl`, because plain `curl` is an alias in Windows PowerShell.

To stop the server, go back to the server window and press **Ctrl + C**.

---

## 6. Optional: full self-test

Only if you want the full verification suite:

```powershell
$env:PYTHONPATH="."
py -3 -m obf.cli --self-test
```

Or use `python` instead of `py -3` if that is how Python is installed. Expect roughly 15 minutes. This is local verification only; do not run it on Render.

---

## 7. Install Git and GitHub CLI on Windows

In PowerShell:

```powershell
winget install --id Git.Git -e
winget install --id GitHub.cli -e
```

If `winget` is not available, download them manually:

- Git: https://git-scm.com/download/win
- GitHub CLI: https://cli.github.com/
- Python 3.13: https://www.python.org/downloads/windows/

After installing, **close and reopen PowerShell** so `git` and `gh` are on PATH. Verify:

```powershell
git --version
gh --version
py -3 --version
```

If `py` is missing but `python` works, use `python` in the commands below.

---

## 8. Push to GitHub from Windows

You can push from the extracted Windows folder. `tools\` is gitignored, so Windows binaries will not be committed; Render will fetch Linux tools during its build.

```powershell
cd $env:USERPROFILE\grandfuscate-windows\grandfuscate

gh auth login
```

Follow the prompts: GitHub.com → HTTPS → login with web browser. Do not paste tokens into chat.

Then:

```powershell
git init -b main
git add .
git commit -m "Grandfuscate: third-pass hardening and deployment files"
gh repo create grandfuscate --public --source=. --remote=origin --push
```

Use `--private` instead of `--public` if you want a private repository.

If the GitHub repo already exists and is empty, use:

```powershell
git remote add origin https://github.com/<your-username>/grandfuscate.git
git push -u origin main
```

Check:

```powershell
git remote -v
git log -1 --oneline
```

---

## 9. Deploy on Render

Use your browser; no Render CLI is needed.

1. Go to https://dashboard.render.com/.
2. Click **New → Blueprint**.
3. Connect GitHub and select your `grandfuscate` repository, branch `main`.
4. Render reads `render.yaml`:
   - build: `pip install -r requirements.txt && python3 obf/fetch_tools.py`
   - start: `python3 -m obf.web`
   - health check: `/api/health`
5. In **Environment**, set these values. The first one is required for your 1,463,380-byte source:

```text
OBF_MAX_SOURCE=10485760
OBF_MAX_BODY=16777216
OBF_TIMEOUT=300
OBF_RATE_LIMIT=24
OBF_ALLOWED_ORIGIN=https://YOUR-SERVICE.onrender.com
OBF_API_KEY=REPLACE_WITH_A_LONG_RANDOM_SECRET
```

Do **not** set `OBF_MAX_IDENTIFY`; after the revert, identify size is hard-coded to 8 MiB in `obf/web.py`.

Do not set `PORT`; Render supplies it. Do not commit `OBF_API_KEY` to GitHub.

6. Click **Apply** / **Create Resources**.
7. Wait for the first deploy. Free-tier cold starts can take roughly 30–60 seconds.

GitHub Pages alone will not work: the UI calls same-origin `/api/*` endpoints and the backend is Python.

---

## 10. Smoke-test the deployed service

In PowerShell, replace `YOUR-SERVICE` and `YOUR_RENDER_API_KEY`:

```powershell
$URL = "https://YOUR-SERVICE.onrender.com"

Invoke-RestMethod "$URL/api/health"
Invoke-RestMethod "$URL/api/meta"

$body = @{
  source = "print(`"live`", 6*7)`n"
  preset = "light"
  seed = 20261118
  verify = $true
} | ConvertTo-Json

$headers = @{ "X-API-Key" = "YOUR_RENDER_API_KEY" }

Invoke-RestMethod -Method Post -Uri "$URL/api/obfuscate" `
  -Headers $headers -ContentType "application/json" -Body $body
```

If you left `OBF_API_KEY` blank, remove the `-Headers $headers` part.

Expected:
- `/api/health` returns `ok: true`
- `/api/meta` lists `light`, `medium`, `heavy`
- `/api/obfuscate` returns `ok: true`, `syntax.ok: true`, and output starting with `return`
- running that output prints `live	42`

---

## 11. Troubleshooting

| Windows error | Fix |
|---|---|
| `'unzip' is not recognized` | Use `Expand-Archive -Path .\grandfuscate-windows.zip -DestinationPath ... -Force` in PowerShell. |
| `The system cannot find the path specified` | Extract first. The folder is `grandfuscate-windows\grandfuscate`, not `grandfuscate`. |
| `'.' is not recognized` | Use `.\setup-local.ps1` in PowerShell or `setup-local.bat` in CMD. |
| `'PORT' is not recognized` | Use `$env:PORT="8000"` in PowerShell or `set PORT=8000` in CMD. |
| `python3` not recognized | Use `py -3 -m obf.web` or `python -m obf.web`. |
| `.ps1 cannot be loaded because running scripts is disabled` | Use `powershell -ExecutionPolicy Bypass -File .\setup-local.ps1`, or use the `.bat` files. |
| `Expand-Archive` says file not found | Run `dir *.zip` and use the exact filename; check you are in `Downloads`. |
| `gh` not recognized | Install GitHub CLI, then reopen PowerShell. |
| `git` not recognized | Install Git for Windows, then reopen PowerShell. |
| `source is ... public limit ...` | Set `OBF_MAX_SOURCE=10485760` in Render Environment, then redeploy/restart. |
| `API key required` | Send `X-API-Key`, or clear `OBF_API_KEY` in Render. |
| Build fails fetching Luau | Render needs outbound access to GitHub releases; retry the deploy. |
| `/api/identify` rejects a large file | 8 MiB hard-coded limit; ask for a code change if needed. |

---

## 12. Final checklist

- [ ] Downloaded `grandfuscate-windows.zip`, not the Linux tools bundle
- [ ] Opened PowerShell
- [ ] Ran `Expand-Archive`
- [ ] Ran `setup-local.ps1` or `setup-local.bat`
- [ ] Ran `start-local.ps1` or `start-local.bat`
- [ ] Opened `http://127.0.0.1:8000/`
- [ ] Installed Git + GitHub CLI
- [ ] Ran `gh auth login`
- [ ] Pushed `main` to GitHub
- [ ] Created Render Blueprint
- [ ] Set `OBF_MAX_SOURCE`, `OBF_TIMEOUT`, `OBF_API_KEY`, `OBF_ALLOWED_ORIGIN`
- [ ] Smoke-tested `/api/health`, `/api/meta`, `/api/obfuscate`

No remote, push, GitHub repository, or Render service has been created by Arena. This remains client-side Luau obfuscation, not encryption or real security.
