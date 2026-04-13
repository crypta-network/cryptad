package network.crypta.clients.http;

/**
 * Neutralized legacy HTTP category keys shared by the shell and admin-side HTTP toadlets.
 *
 * <p>This holder keeps the stable menu-category identifiers in a shell-owned location, so code that
 * stays outside the future browse leaf does not need to import the concrete browse toadlet just to
 * group routes under the historical menu headings. The values remain the original localization
 * keys, so the visible menu text, category ordering, and translation lookups continue to behave
 * exactly as they do today.
 *
 * <p>The constants are intentionally narrow in scope. They are legacy HTTP implementation details,
 * not a new runtime-wide navigation API, and callers should treat them as stable internal keys for
 * route registration and menu wiring only.
 */
final class LegacyHttpCategories {
  /** Category key for the primary browsing root and other browse-oriented menu links. */
  static final String CATEGORY_BROWSING = "FProxyToadlet.categoryBrowsing";

  /** Category key for transfer queue pages such as downloads, uploads, and filtering tools. */
  static final String CATEGORY_QUEUE = "FProxyToadlet.categoryQueue";

  /** Category key for friend-management pages and related darknet connectivity actions. */
  static final String CATEGORY_FRIENDS = "FProxyToadlet.categoryFriends";

  /** Category key for alerts, diagnostics, and other node-status pages exposed over HTTP. */
  static final String CATEGORY_STATUS = "FProxyToadlet.categoryStatus";

  /** Category key for configuration and security-setting pages in the legacy shell. */
  static final String CATEGORY_CONFIG = "FProxyToadlet.categoryConfig";

  /** Prevents instantiation of this constants' holder. */
  private LegacyHttpCategories() {}
}
