import UIKit
import WebKit

/// The app's single screen: a locked-down WKWebView pointed at our portal.
///
/// Restrictions in effect:
///   1. Only allow-listed origins may navigate (see URLAllowlist).
///   2. Non-allowed navigations are diverted to the system browser.
///   3. A native JS bridge ("native") is exposed to page JS.
final class ViewController: UIViewController {

    private var webView: WKWebView!
    private var bridge: WebViewBridge!

    private let startURL = URL(string: "https://app.example.com/portal")!

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        configureWebView()
        webView.load(URLRequest(url: startURL))
    }

    private func configureWebView() {
        let config = WKWebViewConfiguration()

        // Inject a bootstrapping user script so pages can call back to native
        // via a friendly wrapper instead of the raw message-handler calls.
        let js = """
        (function () {
            window.__nativeCallback = function (value) {
                window.dispatchEvent(new CustomEvent('native:result', { detail: value }));
            };
            window.NativeBridge = {
                getToken:    function () { window.webkit.messageHandlers.native.postMessage({action: 'getToken'}); },
                openExternal:function (u) { window.webkit.messageHandlers.native.postMessage({action: 'openExternal', url: u}); },
                readFile:    function (p) { window.webkit.messageHandlers.native.postMessage({action: 'readFile', path: p}); }
            };
        })();
        """
        let userScript = WKUserScript(source: js,
                                      injectionTime: .atDocumentStart,
                                      forMainFrameOnly: false)
        config.userContentController.addUserScript(userScript)

        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])

        // Register the native bridge AFTER the web view exists.
        bridge = WebViewBridge(webView: webView)
        config.userContentController.add(bridge, name: WebViewBridge.handlerName)
    }

    /// Deeplink entry point: `securevault://open?url=<encoded>`.
    ///
    /// The URL from the `url` query parameter is treated as a route to load
    /// in the embedded browser. This is handled with `canLoad` (the lenient
    /// gate) rather than the navigation-delegate host check.
    func loadExternal(_ deeplink: URL) {
        guard let comps = URLComponents(url: deeplink, resolvingAgainstBaseURL: false),
              let target = comps.queryItems?.first(where: { $0.name == "url" })?.value,
              let targetURL = URL(string: target) else { return }

        if URLAllowlist.shared.canLoad(targetURL) {
            webView.load(URLRequest(url: targetURL))
        }
        // else: silently drop unrouteable deeplinks
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Avoid leaking the bridge via the (retained) user content controller.
        webView.configuration.userContentController
            .removeScriptMessageHandler(forName: WebViewBridge.handlerName)
    }
}

// MARK: - WKNavigationDelegate (the enforcement point)

extension ViewController: WKNavigationDelegate {

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {

        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        // Allow our own web content.
        if URLAllowlist.shared.isAllowedHost(url) {
            decisionHandler(.allow)
            return
        }

        // Everything else is "external": cancel in-app and hand it to the OS.
        decisionHandler(.cancel)
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
}
