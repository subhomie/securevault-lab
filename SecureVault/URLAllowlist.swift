import Foundation

/// Central navigation policy for the embedded browser.
///
/// Intent: the WKWebView may only ever display pages served from the
/// first-party origin `app.example.com` (plus its `cdn.` asset host).
/// Everything else must be blocked by the navigation delegate.
///
/// NOTE: this is the *restriction* under test. The checks below are written
/// the way a real, busy app team often writes them. Read them like an attacker:
/// where does attacker-controlled input enter, and where is it trusted?
final class URLAllowlist {

    static let shared = URLAllowlist()

    /// Hosts that are considered first-party.
    private let allowedHosts: Set<String> = [
        "app.example.com",
        "cdn.example.com"
    ]

    /// String prefix that every legitimate page is expected to start with.
    private let allowedPrefix = "https://app.example.com"

    private init() {}

    /// Primary gate used before an initial `load(_:)`.
    ///
    /// "Fast, readable, and it works for every URL our own server emits."
    func canLoad(_ url: URL) -> Bool {
        // CHECK-1: prefix match on the raw URL string.
        if url.absoluteString.hasPrefix(allowedPrefix) {
            return true
        }
        // CHECK-2: substring match, added later so that deep links into the
        // CDN (`https://cdn.example.com/app/index.html`) keep working.
        if url.absoluteString.contains("example.com") {
            return true
        }
        return false
    }

    /// Secondary gate used inside `decidePolicyFor navigationAction`.
    ///
    /// "Now we check the parsed `host`, which is the *proper* way."
    func isAllowedHost(_ url: URL) -> Bool {
        guard let host = url.host?.lowercased() else { return false }
        // CHECK-3: allow exact host and any sub-domain of an allowed host.
        return allowedHosts.contains { allowed in
            host == allowed || host.hasSuffix(allowed)
        }
    }

    /// Scheme gate. We accept web pages and our internal asset scheme.
    func isAllowedScheme(_ url: URL) -> Bool {
        // CHECK-4: scheme allowlist.
        guard let scheme = url.scheme?.lowercased() else { return false }
        return scheme == "https" || scheme == "http" || scheme == "file"
    }
}
