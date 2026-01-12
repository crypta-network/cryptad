package network.crypta.clients.http;

import network.crypta.pluginmanager.FredPluginL10n;

/**
 * Immutable registration payload describing how a {@link Toadlet} is exposed by a {@link
 * ToadletContainer}.
 *
 * <p>This record groups the routing metadata and optional menu presentation data that a container
 * needs when registering a toadlet. Callers typically assemble instances through the static factory
 * methods in this type and then pass the result to {@link ToadletContainer#register(Toadlet,
 * ToadletRegistration)}. The record itself is a simple data carrier: it does not validate inputs,
 * perform lookups, or resolve localization keys; those responsibilities stay with the container or
 * menu renderer that consumes the values.
 *
 * <p>The data is immutable and safe to share between threads once constructed. All fields may be
 * null when the caller intentionally suppresses a menu entry (for example, by omitting a menu key
 * or name). The caller enforces invariants: use a consistent prefix, keep menu identifiers stable
 * across the node lifecycle, and choose whether a link should be visible to limited-access clients.
 * The container interprets the values to determine registration order and menu exposure.
 *
 * <ul>
 *   <li>Captures routing state: menu identifier, URL prefix, and ordering flag.
 *   <li>Captures menu metadata: name/title keys, optional visibility callback, and localization.
 *   <li>Remains immutable so registration decisions are repeatable and thread-safe.
 * </ul>
 *
 * @param menu menu grouping key; {@code null} suppresses menu link creation entirely
 * @param urlPrefix leading path segment used for routing and toadlet resolution
 * @param atFront whether to prioritize this registration over earlier prefix matches
 * @param name localization key for the visible menu label; {@code null} hides the link
 * @param title localization key for tooltip text; may be {@code null} if unused
 * @param fullOnly whether the menu link is limited to clients with full access
 * @param callback optional callback that can enable or hide the link at runtime
 * @param l10n optional localization helper to resolve {@code name} and {@code title}
 */
public record ToadletRegistration(
    String menu,
    String urlPrefix,
    boolean atFront,
    String name,
    String title,
    boolean fullOnly,
    LinkEnabledCallback callback,
    FredPluginL10n l10n) {

  /**
   * Create a registration that routes requests without defining a menu entry.
   *
   * <p>This factory is intended for internal endpoints or helper toadlets that must be reachable by
   * URL but should not appear in navigation menus. The returned record carries only routing
   * metadata and access scoping, leaving menu-related fields {@code null}. Callers should ensure
   * the prefix is normalized to match the container’s routing rules and should decide whether to
   * register the toadlet ahead of other handlers by setting {@code atFront}. The resulting record
   * is immutable and can be cached or reused across registrations without additional
   * synchronization.
   *
   * @param menu menu grouping key; {@code null} omits menu linkage entirely
   * @param urlPrefix leading path segment used for routing and prefix matching
   * @param atFront whether to register ahead of earlier matching prefixes
   * @param fullOnly whether links would be limited to full-access clients
   * @return immutable registration that carries routing data with no menu metadata
   */
  public static ToadletRegistration basic(
      String menu, String urlPrefix, boolean atFront, boolean fullOnly) {
    return new ToadletRegistration(menu, urlPrefix, atFront, null, null, fullOnly, null, null);
  }

  /**
   * Create a registration that includes menu metadata without an explicit localization helper.
   *
   * <p>Use this factory when the menu label and tooltip keys are already resolved by the caller or
   * when localization is handled elsewhere (for example, by the container’s default localization
   * provider). The returned record will still instruct the container to add a navigation link so
   * long as both {@code menu} and {@code name} are non-null. Set {@code fullOnly} when the link
   * must be hidden from restricted clients; the toadlet itself still needs to enforce
   * authorization. The menu renderer invokes optional callbacks to decide whether the link should
   * be shown for the current runtime state.
   *
   * @param menu menu grouping key used to place the link in navigation
   * @param urlPrefix leading path segment used for routing and prefix matching
   * @param atFront whether to register ahead of earlier matching prefixes
   * @param name localization key or label token for the menu entry
   * @param title localization key or tooltip token for the menu entry
   * @param fullOnly whether the menu link should require full-access permissions
   * @param callback optional link-visibility callback invoked when rendering menus
   * @return immutable registration including menu metadata without a localization helper
   */
  public static ToadletRegistration menuLink(
      String menu,
      String urlPrefix,
      boolean atFront,
      String name,
      String title,
      boolean fullOnly,
      LinkEnabledCallback callback) {
    return new ToadletRegistration(menu, urlPrefix, atFront, name, title, fullOnly, callback, null);
  }

  /**
   * Create a registration that includes menu metadata and an explicit localization helper.
   *
   * <p>Use this factory when the caller owns the {@link FredPluginL10n} instance responsible for
   * resolving menu labels and tooltips. The localization helper is stored alongside the menu keys,
   * so the container can defer translation until render time. All routing inputs are retained
   * as-is; callers should supply a stable {@code urlPrefix} and decide whether the toadlet should
   * be prioritized ahead of earlier registrations. If {@code menu} or {@code name} is {@code null},
   * the container will still register the toadlet but will omit the navigation link entirely.
   *
   * @param menu menu grouping key used to place the link in navigation
   * @param urlPrefix leading path segment used for routing and prefix matching
   * @param atFront whether to register ahead of earlier matching prefixes
   * @param name localization key or label token for the menu entry
   * @param title localization key or tooltip token for the menu entry
   * @param fullOnly whether the menu link should require full-access permissions
   * @param callback optional link-visibility callback invoked when rendering menus
   * @param l10n localization helper used to resolve menu labels and tooltip text
   * @return immutable registration including menu metadata and localization helper
   */
  public static ToadletRegistration menuLink(
      String menu,
      String urlPrefix,
      boolean atFront,
      String name,
      String title,
      boolean fullOnly,
      LinkEnabledCallback callback,
      FredPluginL10n l10n) {
    return new ToadletRegistration(menu, urlPrefix, atFront, name, title, fullOnly, callback, l10n);
  }
}
