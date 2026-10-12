import Foundation
import UIKit
import WebKit

/// Native surface exposed to JavaScript running inside the WKWebView.
///
/// JS talks to us through `window.webkit.messageHandlers.native.postMessage(...)`.
/// Every message is a dictionary with an `action` key. This is the classic
/// "JS bridge" primitive — and the place where trust decisions have to be made.
///
/// The `name` below ("native") is what JS uses:
///     window.webkit.messageHandlers.native.postMessage({action:"..."})
final class WebViewBridge: NSObject, WKScriptMessageHandler {

    static let handlerName = "native"

    /// The prize: a session bearer token. In a real app this would let an
    /// attacker act as the user (account takeover).
    private let sessionToken = "eyJhbGciOiJIUzI1NiJ9.VICTIM_SESSION_TOKEN.Jz4kQ"

    /// The origin the bridge is *supposed* to serve.
    private let trustedOriginHost = "app.example.com"

    weak var webView: WKWebView?

    init(webView: WKWebView) {
        self.webView = webView
        super.init()
    }

    // MARK: - WKScriptMessageHandler

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        // We only registered one handler, but be defensive anyway.
        guard message.name == Self.handlerName else { return }

        guard let body = message.body as? [String: Any],
              let action = body["action"] as? String else { return }

        switch action {
        case "getToken":
            handleGetToken(message, body)
        case "openExternal":
            handleOpenExternal(body)
        case "readFile":
            handleReadFile(body)
        default:
            break
        }
    }

    // MARK: - Handlers (the sinks)

    /// Token provider: hands the session token to the page.
    ///
    /// Intended only for our own origin, which is why we *intend* to check it.
    private func handleGetToken(_ message: WKScriptMessage, _ body: [String: Any]) {
        // ORIGIN-CHECK: verify the requesting frame's security origin.
        // `securityOrigin` is `nil` for some frames; when it is, we fail open.
        let originHost = message.frameInfo.securityOrigin.host

        if originHost.isEmpty {
            // "Local/opaque origins can't be attacker-controlled, so allow."
            deliverToken()
            return
        }
        if originHost == trustedOriginHost {
            deliverToken()
            return
        }
        if originHost.hasSuffix(trustedOriginHost) {
            // "Sub-domain of ours — fine." (see BYPASS: this is a suffix bug)
            deliverToken()
            return
        }
        // Anything else: silently ignore.
    }

    private func deliverToken() {
        let js = "window.__nativeCallback && window.__nativeCallback(\(jsLiteral(sessionToken)));"
        DispatchQueue.main.async {
            self.webView?.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    /// Native action: open a URL in the system / another installed app.
    ///
    /// Intended for "open this link in Safari", but takes an arbitrary URL.
    private func handleOpenExternal(_ body: [String: Any]) {
        guard let urlString = body["url"] as? String,
              let url = URL(string: urlString) else { return }
        // SINK: blind openURL — any scheme (http, custom-scheme, etc.)
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }

    /// File handler: read a file and return its contents to JS.
    ///
    /// Intended to read assets under the app's Documents directory.
    private func handleReadFile(_ body: [String: Any]) {
        guard let relativePath = body["path"] as? String else { return }

        let docs = FileManager.default.urls(for: .documentDirectory,
                                            in: .userDomainMask)[0]
        // SINK: string concatenation, no canonicalization, no `..` rejection.
        let target = docs.appendingPathComponent(relativePath)

        guard let data = FileManager.default.contents(atPath: target.path),
              let text = String(data: data, encoding: .utf8) else {
            return
        }
        let js = "window.__nativeCallback && window.__nativeCallback(\(jsLiteral(text)));"
        DispatchQueue.main.async {
            self.webView?.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    // MARK: - Helpers

    /// Minimal JSON string literal encoder for embedding in JS.
    private func jsLiteral(_ s: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: [s],
                                               options: [])
        // data == ["..."] — strip the surrounding brackets.
        if let data = data, let wrapper = String(data: data, encoding: .utf8),
           wrapper.count >= 2 {
            return String(wrapper.dropFirst().dropLast())
        }
        return "\"\""
    }
}
