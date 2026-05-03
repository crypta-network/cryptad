package network.crypta.platform.appui;

import java.util.Optional;

/**
 * Registry of currently assigned app UI browser origins.
 *
 * <p>The interface stays transport-neutral so Platform API summaries, app UI bootstrap, and HTTP
 * CORS handling can consult the same source without depending on a concrete listener
 * implementation. Production code may allocate loopback listeners lazily. Tests and compatibility
 * paths can use {@link #sameOriginOnly()} to preserve the legacy {@code /apps/{appId}/} behavior.
 *
 * <p>Implementations are expected to return fresh answers. A binding can disappear when an app is
 * uninstalled, when a static UI becomes unsupported, or when a loopback listener cannot be kept
 * alive. Callers should treat returned values as snapshots and re-check this registry before making
 * security decisions such as CORS approval or origin-bound session verification.
 */
public interface AppUiOriginRegistry {
  /**
   * Returns the current origin binding for an installed static app when one is available.
   *
   * <p>Registries that own listeners may allocate or refresh the listener as part of this lookup.
   * The returned binding must not contain raw browser-session tokens, process tokens, or filesystem
   * paths because API summaries may expose it to app processes.
   *
   * @param appId normalized app identifier whose UI assignment should be resolved
   * @return origin binding, or empty when no isolated/fallback binding is registered
   */
  Optional<AppUiOriginBinding> bindingForApp(String appId);

  /**
   * Returns a browser launch URL for one installed static app when one is available.
   *
   * <p>The default uses the public URL from {@link #bindingForApp(String)}. Registries that manage
   * isolated listeners may override this method to mint request-specific launch proof for
   * full-access Web Shell redirects. Callers must not serialize such launch URLs into app summaries
   * or other APIs that app processes can read.
   *
   * @param appId normalized app identifier selected for browser launch
   * @return browser launch URL, or empty when no app UI binding is available
   */
  default Optional<String> launchUrlForApp(String appId) {
    return bindingForApp(appId).map(AppUiOriginBinding::uiUrl);
  }

  /**
   * Returns the binding currently assigned to one serialized browser origin.
   *
   * <p>Platform API CORS handling uses this lookup before allowing app-browser requests from
   * isolated origins. Implementations should normalize or trim input consistently with the HTTP
   * adapter but must not match wildcard or remote origins.
   *
   * @param origin serialized browser origin from an HTTP {@code Origin} header
   * @return matching binding, or empty when the origin is not registered
   */
  default Optional<AppUiOriginBinding> bindingForOrigin(String origin) {
    return Optional.empty();
  }

  /**
   * Returns whether an HTTP {@code Origin} header names a registered active app UI origin.
   *
   * <p>The default accepts only bindings that are both registered and active isolated origins. A
   * same-origin fallback binding is intentionally not treated as a CORS-approved app origin.
   *
   * @param origin serialized browser origin from an app-browser request
   * @return {@code true} when the origin is currently assigned to an active isolated app UI
   */
  default boolean isRegisteredOrigin(String origin) {
    return bindingForOrigin(origin).filter(AppUiOriginBinding::isolatedAndActive).isPresent();
  }

  /**
   * Returns a no-op registry that leaves callers on same-origin compatibility paths.
   *
   * <p>This is the correct default for tests and runtime paths that have not installed a loopback
   * origin server. It never approves an isolated CORS origin and never mints launch proof.
   *
   * @return registry with no isolated origin bindings
   */
  static AppUiOriginRegistry sameOriginOnly() {
    return _ -> Optional.empty();
  }
}
