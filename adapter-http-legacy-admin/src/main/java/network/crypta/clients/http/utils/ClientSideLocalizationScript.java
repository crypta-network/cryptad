package network.crypta.clients.http.utils;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;

/**
 * Utility for building the client-side localization payload used by legacy HTTP pages.
 *
 * <p>This helper centralizes the small JavaScript fragment that exposes selected localized strings
 * to the legacy web-pushing client. Both shared-shell code and browse-owned code need the same
 * payload, so the helper provides a neutral location that avoids duplicating string-building logic
 * or forcing shared-shell classes to import browse-owned callback types.
 *
 * <p>The generated script initializes a global {@code l10n} object whose properties are derived
 * from {@code fproxy.push.*} localization keys. Values are HTML-encoded before insertion, so the
 * emitted JavaScript can be embedded directly into legacy pages without changing the current output
 * shape or escaping behavior.
 */
public final class ClientSideLocalizationScript {

  private ClientSideLocalizationScript() {}

  /**
   * Builds the JavaScript localization object consumed by the client-side web-pushing code.
   *
   * <p>The method walks every localization key with the {@code fproxy.push} prefix, strips that
   * prefix down to the property name expected by the client, and appends the translated value into
   * a JavaScript object literal. When no matching keys exist, the method still returns a valid
   * empty object declaration, so callers can embed the result unconditionally.
   *
   * @return JavaScript source that initializes the client-side {@code l10n} object for legacy
   *     web-pushing pages
   */
  public static String getClientSideLocalizationScript() {
    StringBuilder l10nBuilder = new StringBuilder("var l10n={\n");
    boolean isNamePresentAtLeastOnce = false;
    for (String key : NodeL10n.getBase().getAllNamesWithPrefix("fproxy.push")) {
      l10nBuilder
          .append(key.substring("fproxy.push".length() + 1))
          .append(": \"")
          .append(HTMLEncoder.encode(NodeL10n.getBase().getString(key)))
          .append("\",\n");
      isNamePresentAtLeastOnce = true;
    }
    String l10n =
        isNamePresentAtLeastOnce
            ? l10nBuilder.substring(0, l10nBuilder.length() - 2)
            : l10nBuilder.toString();
    return l10n.concat("\n};");
  }
}
