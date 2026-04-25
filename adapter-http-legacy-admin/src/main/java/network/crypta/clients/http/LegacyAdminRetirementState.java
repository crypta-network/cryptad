package network.crypta.clients.http;

/**
 * Retirement state assigned to one legacy admin HTTP surface.
 *
 * <p>The values are intentionally conservative. They describe how operators should treat the legacy
 * surface today; they do not delete routes or imply that a later PR can remove a page without
 * checking diagnostics and remaining migration gaps.
 *
 * <p>States are used by three separate consumers: notice rendering, Web Shell fallback-link
 * selection, and process-local diagnostics. A state therefore needs to describe current product
 * ownership, not only implementation location. For example, a page can still exist in the legacy
 * adapter while being marked {@link #PRIMARY_REPLACED} because Web Shell or a first-party app is
 * now the expected operator entry point.
 *
 * <ul>
 *   <li>Deletion decisions must be made in later PRs after usage counters and migration gaps are
 *       reviewed.
 *   <li>FProxy browse and browse-owned content rendering should remain {@link #RETAINED} or outside
 *       this admin registry.
 *   <li>{@link #INFRASTRUCTURE} entries support routing or hosting and are not user-facing
 *       retirement candidates.
 * </ul>
 */
public enum LegacyAdminRetirementState {
  /**
   * A Web Shell or first-party app route is now the primary user path.
   *
   * <p>The legacy page remains reachable for fallback, debug, or bookmarked access. Replaced pages
   * normally render a retirement notice and are excluded from primary Web Shell legacy-link lists.
   */
  PRIMARY_REPLACED,

  /**
   * The page remains reachable as a fallback but is not the preferred path.
   *
   * <p>This state is reserved for pages that are still operational and expected to be reachable,
   * but whose replacement status is softer than {@link #PRIMARY_REPLACED}. It lets future PRs
   * describe transitional surfaces without showing a strong replacement warning by default.
   */
  FALLBACK,

  /**
   * The surface is intentionally kept as long-term functionality.
   *
   * <p>Retained surfaces are not deletion candidates for the current retirement plan. This state is
   * appropriate for browse-adjacent tools, support pages, and other routes that remain legitimate
   * endpoints even after Web Shell becomes the primary admin UI.
   */
  RETAINED,

  /**
   * A complete replacement is not available or has not been proven.
   *
   * <p>Pending surfaces should stay reachable and should not receive strong replacement notices.
   * Use this state when coverage exists only partially, startup routing still depends on legacy
   * behavior, or the replacement path needs more validation.
   */
  PENDING,

  /**
   * The route supports other pages and is not a standalone user-facing admin page.
   *
   * <p>Infrastructure entries include bridges, helpers, and static hosting routes. They can appear
   * in the registry so matching remains explicit, but usage diagnostics and Web Shell fallback
   * navigation normally exclude them.
   */
  INFRASTRUCTURE
}
