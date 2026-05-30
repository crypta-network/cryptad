package network.crypta.clients.http;

import java.net.URI;
import java.util.Optional;
import network.crypta.platform.webshell.routes.WebShellPaths;

/**
 * Central removal policy for legacy admin routes.
 *
 * <p>The policy is intentionally narrower than the retirement registry. It only handles paths whose
 * registry metadata marks them removed by default and whose explicit removal scope matches the
 * current request. Prefix or child-route matching is opt-in per surface; the registry's broad
 * diagnostics prefix attribution is never reused for removal decisions.
 *
 * <p>The dispatcher calls this class after the toadlet container has had a chance to apply
 * higher-priority routing decisions such as first-run wizard redirects. A non-empty result means
 * the old handler should not run for this request. An empty result means either the route is not in
 * the current removal wave, the request targets a helper subpath, or the replacement UI is not
 * reachable in the current browser/session configuration.
 *
 * <p>Availability checks are deliberately conservative. App replacements require full operator
 * access, FProxy JavaScript support, and an installed static app UI. Web Shell replacements require
 * full operator access and Web Shell to be the advertised primary UI. Those checks keep
 * JavaScript-disabled, app-not-installed, and setup-gated deployments on the legacy fallback until
 * a replacement is actually usable.
 */
final class LegacyAdminRemovalPolicy {
  /** Stable first-party app id for the Queue Manager static UI replacement. */
  private static final String QUEUE_MANAGER_APP_ID = "queue-manager";

  /** Stable first-party app id for the Publisher static UI replacement. */
  private static final String PUBLISHER_APP_ID = "publisher";

  /** Exact static query used by Web Shell when it deliberately opens legacy security fallback. */
  private static final String SECURITY_LEVELS_LEGACY_FALLBACK_QUERY =
      "legacyFallback=security-levels";

  /** Prevents construction because the policy is stateless and entirely function-based. */
  private LegacyAdminRemovalPolicy() {}

  /**
   * Computes the removal decision for a request.
   *
   * <p>Safe reads receive the route's configured replacement response. Mutating or otherwise
   * non-read methods are blocked before the legacy toadlet can execute old behavior. This overload
   * is intended for context-free registry checks and assumes replacements are available.
   *
   * @param method HTTP method from the request line
   * @param uri normalized request URI
   * @return removal decision when the request belongs to a removed-by-default canonical route
   */
  static Optional<LegacyAdminRemovalDecision> decide(String method, URI uri) {
    return decide(method, uri, null);
  }

  /**
   * Computes the removal decision for a concrete request.
   *
   * <p>Wave-1 removal applies only when the replacement route is usable for the current request
   * context. When JavaScript is disabled, Web Shell is not the primary UI, or the required static
   * app is not installed, the policy returns empty so the retained legacy fallback can render
   * normally. This avoids redirecting operators into replacement routes that will immediately fail.
   *
   * @param method HTTP method from the request line, compared using the adapter's uppercase method
   *     names
   * @param uri normalized request URI whose path is matched without query or fragment data
   * @param ctx per-request context used to evaluate replacement availability, or {@code null} for
   *     context-free registry checks
   * @return removal decision when the request belongs to a removed-by-default canonical route and
   *     its replacement is currently reachable
   */
  static Optional<LegacyAdminRemovalDecision> decide(String method, URI uri, ToadletContext ctx) {
    Optional<LegacyAdminSurface> surface = removedSurfaceForRequest(uri);
    if (surface.isEmpty()) {
      return Optional.empty();
    }
    LegacyAdminSurface legacyAdminSurface = surface.orElseThrow();
    if (isExplicitSecurityLevelsLegacyFallback(method, uri, legacyAdminSurface)) {
      return Optional.empty();
    }
    if (!replacementAvailable(legacyAdminSurface, ctx)) {
      return Optional.empty();
    }
    if (isMutatingRequestMethod(method) && !legacyAdminSurface.blockMutatingRequests()) {
      return Optional.empty();
    }
    return Optional.of(decisionFor(method, legacyAdminSurface));
  }

  /**
   * Returns whether a URI targets any removed path in its declared removal scope.
   *
   * <p>This helper is used by restricted-method routing before a concrete {@link ToadletContext}
   * exists. It intentionally answers only the static route-map question. Callers that need to know
   * whether a request should actually be redirected or blocked must call {@link #decide(String,
   * URI, ToadletContext)} so replacement availability is honored.
   *
   * @param uri request URI whose path should be checked against the current removal wave
   * @return {@code true} when the path is currently removed by default
   */
  static boolean isRemovedCanonicalPath(URI uri) {
    return removedSurfaceForRequest(uri).isPresent();
  }

  /**
   * Returns whether a URI targets a removed path whose mutating requests are blocked.
   *
   * <p>Restricted-method routing uses this before a {@link ToadletContext} exists. Surfaces with
   * partial replacement coverage can still redirect safe reads while leaving legacy mutations as
   * fallback, so those routes must not make otherwise-restricted HTTP verbs pass this early gate.
   *
   * @param uri request URI whose path should be checked against the current removal wave
   * @return {@code true} when the path is removed by default and its mutating requests are blocked
   */
  static boolean isRemovedMutatingPath(URI uri) {
    return removedSurfaceForRequest(uri)
        .filter(LegacyAdminSurface::blockMutatingRequests)
        .isPresent();
  }

  /**
   * Converts a matched surface and HTTP method into the response decision.
   *
   * @param method uppercase HTTP method from the request line
   * @param surface registry surface already known to be in the current removal wave
   * @return redirect, gone, or blocked-mutation decision for the matched request
   */
  private static LegacyAdminRemovalDecision decisionFor(String method, LegacyAdminSurface surface) {
    if (isMutatingRequestMethod(method)) {
      return LegacyAdminRemovalDecision.blockedMutation(surface);
    }
    if (surface.removalMode() == LegacyAdminRemovalMode.GONE_WITH_REPLACEMENT) {
      return LegacyAdminRemovalDecision.gone(surface);
    }
    return LegacyAdminRemovalDecision.redirect(surface);
  }

  /**
   * Classifies the method subset that must not execute removed legacy actions.
   *
   * @param method uppercase HTTP method from the request line
   * @return {@code true} for every method except {@code GET} and {@code HEAD}
   */
  private static boolean isMutatingRequestMethod(String method) {
    return !"GET".equals(method) && !"HEAD".equals(method);
  }

  private static boolean isExplicitSecurityLevelsLegacyFallback(
      String method, URI uri, LegacyAdminSurface surface) {
    return "security-levels".equals(surface.id())
        && !isMutatingRequestMethod(method)
        && SECURITY_LEVELS_LEGACY_FALLBACK_QUERY.equals(uri.getRawQuery());
  }

  /**
   * Checks whether the mapped replacement can be used for this request.
   *
   * <p>A {@code null} context means the caller is performing a context-free policy or registry
   * check, so the method assumes availability and preserves the old unit-testable map behavior.
   * Real dispatch requests pass a context and receive the conservative operator/session checks.
   *
   * @param surface registry surface matched by canonical path
   * @param ctx request context used for operator access and UI availability checks
   * @return {@code true} when the replacement destination is reachable for this request
   */
  private static boolean replacementAvailable(LegacyAdminSurface surface, ToadletContext ctx) {
    if (ctx == null) {
      return true;
    }
    return switch (surface.id()) {
      case "queue-downloads", "queue-uploads" ->
          staticAppReplacementAvailable(ctx, QUEUE_MANAGER_APP_ID);
      case "file-insert", "local-file-insert" ->
          staticAppReplacementAvailable(ctx, PUBLISHER_APP_ID);
      case "friends",
          "add-friend",
          "strangers",
          "connectivity",
          "alerts",
          "config",
          "security-levels",
          "core-update",
          "statistics" ->
          webShellReplacementAvailable(ctx);
      default -> true;
    };
  }

  /**
   * Checks whether a first-party static app replacement can receive this request.
   *
   * @param ctx request context that exposes operator access and container-level UI settings
   * @param appId stable first-party app id declared by the replacement surface
   * @return {@code true} only for full-access sessions with JavaScript and an installed static UI
   */
  private static boolean staticAppReplacementAvailable(ToadletContext ctx, String appId) {
    ToadletContainer container = ctx.getContainer();
    return container != null
        && ctx.isAllowedFullAccess()
        && container.isFProxyJavascriptEnabled()
        && container.isStaticAppUiAvailable(appId);
  }

  /**
   * Checks whether Web Shell is the reachable primary destination for this request.
   *
   * @param ctx request context that exposes operator access and the container's primary UI route
   * @return {@code true} only when full-access Web Shell navigation is currently available
   */
  private static boolean webShellReplacementAvailable(ToadletContext ctx) {
    ToadletContainer container = ctx.getContainer();
    return container != null
        && ctx.isAllowedFullAccess()
        && WebShellPaths.SHELL_ROOT.equals(container.primaryUiRoot());
  }

  /**
   * Resolves a URI path to a removed-by-default surface in the current wave.
   *
   * <p>The method ignores query strings and fragments and matches only the route scope declared on
   * the removed surface. Canonical aliases remain the default; prefix and explicit-child scopes
   * must be opted into by the registry entry being matched.
   *
   * @param uri request URI supplied by the dispatch loop or restricted-method gate
   * @return matching removed surface, or empty when normal legacy routing should continue
   */
  private static Optional<LegacyAdminSurface> removedSurfaceForRequest(URI uri) {
    if (uri == null || uri.getPath() == null) {
      return Optional.empty();
    }
    String requestPath = uri.getPath();
    return LegacyAdminRetirementRegistry.surfaces().stream()
        .filter(LegacyAdminRemovalPolicy::isRemovedByDefault)
        .filter(surface -> matchesRemovalScope(surface, requestPath))
        .findFirst();
  }

  /**
   * Checks whether a registry surface has a removal-response execution mode.
   *
   * @param surface registry entry from the authoritative legacy-admin retirement map
   * @return {@code true} for redirect or gone-with-replacement execution modes
   */
  private static boolean isRemovedByDefault(LegacyAdminSurface surface) {
    return surface.removalMode() == LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT
        || surface.removalMode() == LegacyAdminRemovalMode.GONE_WITH_REPLACEMENT;
  }

  /**
   * Matches the declared removal scope for one removed-by-default surface.
   *
   * @param surface registry surface carrying the canonical legacy path
   * @param requestPath request path without query string or fragment data
   * @return {@code true} when the request targets a path inside the removal scope
   */
  private static boolean matchesRemovalScope(LegacyAdminSurface surface, String requestPath) {
    if (matchesCanonicalPageOrSlashlessAlias(surface, requestPath)) {
      return true;
    }
    return switch (surface.removalScope()) {
      case CANONICAL_AND_SLASHLESS_ALIAS -> false;
      case PREFIX_FAMILY -> requestPath.startsWith(surface.legacyPath());
      case EXPLICIT_CHILDREN -> surface.explicitRemovalChildPaths().contains(requestPath);
    };
  }

  private static boolean matchesCanonicalPageOrSlashlessAlias(
      LegacyAdminSurface surface, String requestPath) {
    String legacyPath = surface.legacyPath();
    return requestPath.equals(legacyPath) || requestPath.equals(withoutTrailingSlash(legacyPath));
  }

  /**
   * Removes the trailing slash from a non-root canonical path.
   *
   * @param path same-origin path from the retirement registry
   * @return slashless alias for non-root paths, or the original path for root and slashless inputs
   */
  private static String withoutTrailingSlash(String path) {
    if (path.length() > 1 && path.endsWith("/")) {
      return path.substring(0, path.length() - 1);
    }
    return path;
  }
}
