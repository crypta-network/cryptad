package network.crypta.clients.http;

/**
 * Path-matching scope used by the legacy-admin removal gate.
 *
 * <p>The registry uses broad prefix matching for diagnostics and fallback notices, but removal
 * execution must stay narrower and opt-in. This enum records which request paths are eligible for a
 * replacement response once a surface has a removal mode and its replacement is available.
 *
 * <p>Use this metadata when a removal wave needs to distinguish the canonical page from helper
 * routes that share the same legacy prefix. The removal policy always matches against {@link
 * java.net.URI#getPath()} and ignores query strings and fragments, so sensitive request data never
 * participates in the decision. Each value describes only the path family; it does not decide
 * whether Web Shell, a first-party app, or a mutating Platform API replacement is reachable for the
 * current request.
 *
 * <p>The safest value is {@link #CANONICAL_AND_SLASHLESS_ALIAS}. Broader scopes should appear only
 * after the corresponding Web Shell or app-owned UI flow has equivalent behavior and after retained
 * browse, wizard, Platform API, and app UI routes have been checked as out of scope.
 */
public enum LegacyAdminRemovalScope {
  /**
   * Match only the canonical legacy path and its slashless alias.
   *
   * <p>This is the original wave-1 behavior and remains the default for removed surfaces unless a
   * later wave explicitly expands the route family. Use it for page routes where helper paths,
   * local browsers, or recovery flows may still belong to retained legacy behavior.
   */
  CANONICAL_AND_SLASHLESS_ALIAS,

  /**
   * Match the canonical path, slashless alias, and every child path below the canonical prefix.
   *
   * <p>Use this only for route families whose children have been reviewed as part of the same
   * legacy admin surface. The matcher still uses {@link java.net.URI#getPath()} only, so query
   * strings and fragments never participate. This scope is appropriate for tightly owned page
   * families such as configuration section pages, not for broad mounts that also contain browse,
   * setup, or app-owned routes.
   */
  PREFIX_FAMILY,

  /**
   * Match the canonical path, slashless alias, and an explicit list of reviewed child paths.
   *
   * <p>This scope is for route families where only selected helper pages have proven replacement
   * coverage. Other child paths continue through normal legacy fallback dispatch. Prefer this over
   * {@link #PREFIX_FAMILY} when a legacy prefix mixes queue-owned actions with local file helpers,
   * diagnostics exports, or other flows whose replacement is incomplete.
   */
  EXPLICIT_CHILDREN
}
