/**
 * Bookmark support for the HTTP UI.
 *
 * <p>This package models and manages the bookmark tree shown by the node's web interface (often
 * referred to as {@code FProxy}). Bookmarks represent user-visible links to keys such as freesites,
 * along with metadata needed to render navigation entries and support stable, path-based
 * addressing.
 *
 * <p>The primary entry point is {@code BookmarkManager}, which loads bookmark state from disk,
 * maintains a path-based index for fast lookups and operations like rename/move, and persists
 * changes back to the node user directory using a backup file for resilience. Some bookmark entries
 * may represent USKs; when they do, bookmark management can subscribe to update notifications so
 * newly discovered editions can be recorded and subsequent fetches can start from a known-good
 * edition. The types in this package are typically used by HTTP handlers that render pages and
 * process user actions in a request/response flow.
 *
 * <p><b>Notable behaviors:</b>
 *
 * <ul>
 *   <li>Bookmarks are organized as a tree of categories and items rooted at {@code "/"}.
 *   <li>Operations commonly address entries via stable path strings (for example, {@code
 *       "/MyCategory/MyItem"}), avoiding repeated tree walks.
 *   <li>Callers should not assume concurrent mutation is safe; coordinate multistep updates at a
 *       higher level.
 * </ul>
 */
package network.crypta.clients.http.bookmark;
