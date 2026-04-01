/**
 * Provides the runtime-owned seam for the legacy queue page read path.
 *
 * <p>The types in this package let {@code network.crypta.runtime.admin} render the existing queue
 * page without importing FCP request-status classes or HTTP-layer progress helpers. The seam stays
 * intentionally narrow: it carries only the backend lookup needed for queue-page reads, the small
 * request views consumed by {@code LegacyQueuePagePort}, and a runtime-owned progress-cell renderer
 * that preserves the established HTML output.
 *
 * <p>This package is not a general queue domain model. It exists to keep one legacy admin page
 * working while the runtime/admin boundary is narrowed in small, behavior-preserving steps.
 */
package network.crypta.runtime.admin.queue.page;
