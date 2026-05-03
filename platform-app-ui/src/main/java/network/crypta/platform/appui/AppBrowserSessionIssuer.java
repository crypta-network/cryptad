package network.crypta.platform.appui;

import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Issues browser-scoped Platform API sessions for installed static app UIs.
 *
 * <p>The app-owned UI bootstrap path uses this interface after it has resolved an installed
 * application snapshot and confirmed that the requested resource is the reserved bootstrap JSON
 * route. An implementation should create a short-lived opaque bearer token, bind it to the app id
 * and manifest permissions in the supplied snapshot, and return only the token plus expiry metadata
 * needed by browser code.
 *
 * <p>This interface exists so the HTTP adapter can share the same backing service with an {@link
 * AppBrowserSessionVerifier}. The issuer side must not expose AppHost process launch tokens,
 * trusted key material, filesystem paths, or host/operator form-password credentials. Those
 * credentials belong to different trust boundaries and must not become ambient authority for static
 * app JavaScript.
 */
public interface AppBrowserSessionIssuer {
  /**
   * Issues a browser session for one installed static app snapshot.
   *
   * <p>The snapshot is the source of app identity and manifest-declared permissions.
   * Implementations may also bind version or install-state fingerprints so stale browser sessions
   * stop verifying after uninstall, reinstall, or manifest changes. The method is expected to
   * reject snapshots that do not represent static browser UIs.
   *
   * @param snapshot installed static app snapshot whose manifest permissions bind the session
   * @return issued browser session bearer token and absolute expiry metadata
   * @throws IllegalArgumentException if the snapshot cannot receive a browser UI session
   */
  AppBrowserSessionIssue issue(InstalledAppSnapshot snapshot);

  /**
   * Issues a browser session for one installed static app snapshot and UI origin binding.
   *
   * <p>Implementations that understand origin isolation should bind the verified session metadata
   * to {@code binding}. The default preserves same-origin fallback behavior for tests and
   * compatibility implementations.
   *
   * @param snapshot installed static app snapshot whose manifest permissions bind the session
   * @param binding app UI origin binding used for this bootstrap response
   * @return issued browser session bearer token and absolute expiry metadata
   */
  default AppBrowserSessionIssue issue(InstalledAppSnapshot snapshot, AppUiOriginBinding binding) {
    return issue(snapshot);
  }
}
