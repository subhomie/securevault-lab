# SecureVault — Restricted WKWebView: source→sink bypass writeup

This is the "break the checks" half of the lab. Every restriction in
`SecureVault/` is traced as **attacker-controlled SOURCE → security-sensitive
SINK**, with a concrete bypass and a fix. Read the Swift files alongside this.

> Methodology note (see `.claude/skills/ios-appsec`): a check is only "broken"
> when attacker input reaches a dangerous sink **without** a correct guard.
> A lonely "the app uses a WebView" observation is not a finding — every item
> below has a full arrow.

---

## 0. Threat model & attack surface map

The app enforces three restrictions:

| # | Restriction | Where | File |
|---|-------------|-------|------|
| A | Only allow-listed origins may load | `URLAllowlist.canLoad` / `ViewController.decidePolicyFor` | `URLAllowlist.swift`, `ViewController.swift` |
| B | Native bridge only serves the trusted origin | `WebViewBridge.handleGetToken` origin check | `WebViewBridge.swift` |
| C | File bridge only reads inside Documents | `WebViewBridge.handleReadFile` | `WebViewBridge.swift` |

Attacker entry points (SOURCES) declared by the app:

- **Custom URL scheme** `securevault://open?url=<encoded>` — any app/Safari can
  open it (`Info.plist` → `CFBundleURLTypes`, routed in
  `ViewController.loadExternal`).
- **Network content** loaded into the WebView — the attacker only needs the
  WebView to accept *one* of their origins; then they own the bridge.
- **The bridge itself** — `window.webkit.messageHandlers.native` is injected into
  **every** page (`ViewController.configureWebView`, `forMainFrameOnly: false`).

Sinks:

- `UIApplication.openURL:options:completionHandler:` (`WebViewBridge.swift`,
  `ViewController.swift`) — arbitrary URL/scheme launch.
- `WKWebView.evaluateJavaScript:` (`WebViewBridge.handleGetToken`,
  `handleReadFile`) — native→JS data flow, leaks the session token.
- `FileManager.contents(atPath:)` (`WebViewBridge.handleReadFile`) — file read.

---

## A. Allowlist bypasses (the "restricted" WebView)

### A1 — `hasPrefix` on the raw URL string  *(primary, high)*

```swift
// URLAllowlist.swift  (CHECK-1)
if url.absoluteString.hasPrefix("https://app.example.com") { return true }
```

`absoluteString` is the *whole* string, not the host. Two classic bypasses:

| Attacker URL | `absoluteString.hasPrefix(...)` | Real host |
|---|---|---|
| `https://app.example.com.evil.net/x` | **true** | `app.example.com.evil.net` |
| `https://app.example.com@evil.net/x` | **true** | `evil.net` (userinfo trick) |

**Arrow:** attacker controls the URL → WebView loads attacker origin → injected
`NativeBridge` is present → token theft (chain to B).

**PoC:** `securevault://open?url=https%3A%2F%2Fapp.example.com%40evil.net%2Fpoc.html`

**Fix:** never compare `absoluteString`. Parse and compare `url.host` exactly
(`URLComponents`), and reject URLs containing `@` in the authority.

### A2 — `contains("example.com")` substring  *(high)*

```swift
// URLAllowlist.swift  (CHECK-2)
if url.absoluteString.contains("example.com") { return true }
```

`https://evil.net/?next=example.com` and `https://example.com.evil.net/` both
pass. Same arrow as A1.

**Fix:** delete substring checks entirely; allowlist **exact hosts**.

### A3 — `host.hasSuffix(allowed)` suffix bug  *(primary, critical)*

```swift
// URLAllowlist.swift  (CHECK-3) — used by the navigation delegate
return allowedHosts.contains { allowed in
    host == allowed || host.hasSuffix(allowed)
}
```

`hasSuffix` without the leading dot means **any host that merely *ends* with the
allowed string** passes. `evilapp.example.com` and `notcdn.example.com` end with
`app.example.com` / `cdn.example.com` respectively.

**This is the load-bearing bypass**: the navigation delegate
(`ViewController.swift:100`, `decidePolicyFor` → `isAllowedHost`) uses this check, so
`https://evilapp.example.com/` is **allowed as a main-frame navigation**. The
attacker page now runs in the trusted WebView with the bridge attached → B/C.

**PoC:** `https://evilapp.example.com/poc.html` (see `poc/evilapp.example.com.html`).

**Fix:** `host == allowed || host.hasSuffix("." + allowed)`.

### A4 — Scheme gate allows `file:`  *(medium)*

```swift
// URLAllowlist.swift  (CHECK-4)
return scheme == "https" || scheme == "http" || scheme == "file"
```

Combined with a `file://` load this enables local-file/UXSS-style reads. Prefer
`https` only; if `file:` is required, load from a dedicated bundle directory with
`allowFileAccessFromFileURLs` off.

### A5 — Inconsistent gates  *(design)*

`loadExternal` (deeplink) uses the *weak* `canLoad`; the delegate uses the
*weak-but-different* `isAllowedHost`. Two call sites, two different (both wrong)
policies. Any future 3rd call site is unguarded by construction.

**Fix:** one `func isAllowed(_ url:) -> Bool`, unit-tested, used everywhere.

---

## B. JS-bridge origin check bypass (token theft → ATO)

### B1 — `hasSuffix` again in the bridge *(critical)*

```swift
// WebViewBridge.swift  handleGetToken
if originHost.hasSuffix(trustedOriginHost) { deliverToken() }
```

Even if the WebView were correctly locked to `*.example.com`, this check would
hand the token to `evilapp.example.com` (ends with `app.example.com`).

**Fix:** `originHost == trustedOriginHost` (or `hasSuffix("." + trustedOriginHost)`).

### B2 — Fail-open on empty origin *(high)*

```swift
if originHost.isEmpty {        // "opaque origins can't be attacker controlled"
    deliverToken(); return
}
```

The assumption is wrong. `WKFrameInfo.securityOrigin.host` is empty for
`file://`, `about:blank`, `data:` and **sandboxed/opaque** frames. A `data:` or
`about:blank` page (reachable after A4, or via an iframe from an allowed page)
gets the token. **Fix:** fail **closed** — deny when the origin is unknown.

### B3 — No origin check on the *other* handlers *(high)*

`handleOpenExternal` and `handleReadFile` perform **no** `frameInfo` check at
all. Any frame that can post a message can call them — this is what makes A3 a
full compromise rather than just token theft.

**Fix:** gate every handler behind one `isTrustedFrame(message)` helper.

### B4 — Bridge injected into all frames *(context)*

`forMainFrameOnly: false` (`ViewController.configureWebView`) exposes
`NativeBridge` to every iframe, including third-party ad/tracker iframes on the
legit origin. **Fix:** `forMainFrameOnly: true`, or inject only after origin
validation.

**Chained impact:** A3 (`evilapp.example.com`) → page JS runs → `NativeBridge`
present → `getToken` (B1/B2) → bearer token exfiltrated to
`attacker.example.net` → **account takeover**. Confirm live with `poc/hook.js`
(`[TOKEN LEAK]`).

---

## C. File bridge — path traversal (arbitrary file read)

```swift
// WebViewBridge.swift  handleReadFile
let target = docs.appendingPathComponent(relativePath)   // no canonicalization
FileManager.default.contents(atPath: target.path)
```

`appendingPathComponent` does **not** resolve `..`; `contents(atPath:)` follows
them. Attacker input `path: "../../../Library/Preferences/com.example.securevault.plist"`
reads outside Documents — keychain-adjacent plists, app configs, other app
caches reachable in the sandbox.

**PoC:** from `poc/evilapp.example.com.html`:
`callNative('readFile', { path: '../../../Library/Preferences/com.example.securevault.plist' })`

**Fix:** resolve with `target.resolvingSymlinksInPath().standardizedFileURL`,
then verify it is still prefixed by `docs.standardizedFileURL.path + "/"`; reject
symlinks; read only an explicit asset allowlist.

---

## D. `openExternal` — blind `openURL:` (scheme pivot / deeplink pivot)

```swift
// WebViewBridge.swift  handleOpenExternal  AND  ViewController.decidePolicyFor
UIApplication.shared.open(url, options: [:], completionHandler: nil)
```

Two paths reach this sink with **unvalidated** attacker URLs:
1. Bridge action `openExternal({url})` — no scheme/host check.
2. `decidePolicyFor` on any *rejected* navigation — it immediately `open`s the
   blocked URL externally (an unintended "open anything" gadget).

Impact: launch arbitrary schemes — other apps' deeplinks (`paypal://`,
`shortcuts://`, custom schemes), `http(s)` phishing in Safari, or re-enter
`securevault://` (source A) to chain. On some OS versions/intents this reaches
`tel:`, `sms:`, App-Store URLs, etc.

**Fix:** allowlist schemes (`https` only) and an explicit host allowlist before
`open`; do not auto-open blocked navigations — show an interstitial instead.

---

## E. Deeplink source — `securevault://` unvalidated route

`SceneDelegate.scene(_:openURLContexts:)` → `ViewController.loadExternal` reads
`url` query param and loads it. Any installed app or a Safari link can drive the
app's WebView to an arbitrary URL; combined with A1/A2/A3 it is a one-link entry
into the whole chain:

```
securevault://open?url=https%3A%2F%2Fevilapp.example.com%2Fpoc.html
```

**Fix:** treat deeplink payloads as untrusted; route to *internal destinations*
by an allowlisted enum, never to a raw URL; require an associated-domains
Universal Link for anything sensitive.

---

## F. Runtime bypass (jailbroken device + Frida)

On a jailbroken device the client logic is **not a trust boundary**. Because
`decidePolicyFor` implements an `@objc` protocol method it has a real ObjC
selector, so `poc/hook.js` swizzles the decision block to always return `ALLOW`
and defeats the allowlist *without modifying the .ipa*:

```
frida -U -f com.example.securevault -l poc/hook.js
# [*] ViewController -> SecureVault.ViewController
# [+] hooked SecureVault.ViewController -[ webView:decidePolicyForNavigationAction:decisionHandler: ]
# [+] forced ALLOW (was 0) -> https://evilapp.example.com/poc.html
# [TOKEN LEAK] native evaluated JS: window.__nativeCallback && window.__nativeCallback("eyJ...VICTIM_SESSION_TOKEN...");
```

The same script logs the bridge channel and every `openExternal`. Conclusion:
mirror every client check server-side; never let the WebView origin gate be the
only thing standing between a page and a token.

---

## G. Ranking / fixes summary

| ID | Bug | Severity | Fix |
|----|-----|----------|-----|
| A3 | `host.hasSuffix(allowed)` | Critical | `hasSuffix("." + allowed)` |
| B1 | bridge origin `hasSuffix` | Critical | exact `==` |
| C | path traversal in `readFile` | High | canonicalize + prefix check |
| A1/A2 | URL-string prefix/substring | High | parse `URLComponents`, exact host |
| B2 | fail-open empty origin | High | fail closed |
| B3 | no origin check on other handlers | High | per-handler origin gate |
| D | blind `openURL` | Medium | scheme+host allowlist |
| E | unvalidated deeplink route | Medium | internal route enum only |
| A4 | `file:` scheme allowed | Medium | https only |
| F | runtime swizzle | (inherent) | server-side enforcement |

**Root causes:** (1) string matching instead of URL/host parsing; (2) `hasSuffix`
without the leading dot; (3) fail-open default; (4) bridge reachable from any
frame; (5) no canonicalization on file paths; (6) client-side-only trust.
