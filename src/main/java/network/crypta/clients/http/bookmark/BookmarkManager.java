package network.crypta.clients.http.bookmark;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.FSParseException;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the in-memory bookmark tree used by the HTTP UI and persists it to the node user
 * directory.
 *
 * <p>This manager loads bookmarks from {@code bookmarks.dat} at startup, falling back to {@code
 * bookmarks.dat.bak} or a bundled default bookmark set when needed. It maintains a path index (for
 * example {@code "/MyCategory/MyItem"}) to provide fast lookups and to simplify operations like
 * rename, move, and removal without requiring repeated tree walks.
 *
 * <p>The manager also integrates with USK polling. When a bookmark item represents a USK, it
 * subscribes to updates and records new known-good editions as they are discovered, optionally
 * coalescing persistence to reduce frequent disk writes.
 *
 * <p><b>Threading:</b> the path index is guarded by {@code synchronized (bookmarks)} in the common
 * lookup and persistence paths. Higher-level operations also mutate the underlying bookmark tree;
 * callers should treat {@link BookmarkManager} as not generally thread-safe and avoid concurrent
 * mutations without external coordination.
 *
 * <p><b>Responsibilities:</b>
 *
 * <ul>
 *   <li>Load bookmark state from disk with a backup/default fallback.
 *   <li>Maintain a path-to-bookmark index for categories and items.
 *   <li>Serialize and write bookmark state (backup write then rename).
 *   <li>Subscribe/unsubscribe to USK updates for USK-typed bookmark items.
 * </ul>
 */
public class BookmarkManager implements RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(BookmarkManager.class);

  /**
   * Parsed default bookmark set loaded from the bundled {@code defaultbookmarks.dat} resource.
   *
   * <p>This value may be {@code null} if the resource cannot be loaded or parsed; code that
   * populates defaults should tolerate the absence of bundled defaults.
   */
  public static final SimpleFieldSet DEFAULT_BOOKMARKS;

  private final NodeClientCore node;
  private final USKUpdatedCallback uskCB = new USKUpdatedCallback();

  /**
   * Root category for the primary bookmark tree, addressed under the {@code "/"} path prefix.
   *
   * <p>All user-visible bookmark items and categories are stored beneath this root unless the node
   * is running in a gateway mode that uses {@link #DEFAULT_CATEGORY}.
   */
  public static final BookmarkCategory MAIN_CATEGORY = new BookmarkCategory("/");

  /**
   * Root category for gateway-mode defaults, addressed under the {@code "\\"} path prefix.
   *
   * <p>This category is populated with the bundled defaults when the node is configured as a public
   * gateway, allowing a distinct default set for restricted hosts.
   */
  public static final BookmarkCategory DEFAULT_CATEGORY = new BookmarkCategory("\\");

  private final HashMap<String, Bookmark> bookmarks = new HashMap<>();
  private final File bookmarksFile;
  private final File backupBookmarksFile;
  private boolean isSavingBookmarks = false;
  private boolean isSavingBookmarksLazy = false;

  static {
    String name = "network/crypta/clients/http/staticfiles/defaultbookmarks.dat";
    SimpleFieldSet defaultBookmarks = null;
    try {
      ClassLoader loader = BookmarkManager.class.getClassLoader();
      try (InputStream in = loader.getResourceAsStream(name)) {
        // loader returns null on lookup failures:
        if (in != null) defaultBookmarks = SimpleFieldSet.readFrom(in, false, false);
      }
    } catch (Exception e) {
      LOG.error(
          "Error while loading the default bookmark file from {} :{}", name, e.getMessage(), e);
    } finally {
      DEFAULT_BOOKMARKS = defaultBookmarks;
    }
  }

  // Legacy threshold callback removed.

  /**
   * Creates a new manager, loads bookmarks from disk, and registers a shutdown hook to persist
   * changes.
   *
   * <p>The constructor attempts to read {@code bookmarks.dat} from the node user directory. When
   * that fails (missing/empty file, I/O errors, or malformed content), it tries the backup file
   * {@code bookmarks.dat.bak}. If neither is readable, the bundled {@link #DEFAULT_BOOKMARKS} is
   * used as a last resort.
   *
   * <p>When {@code publicGateway} is enabled, the manager also initializes {@link
   * #DEFAULT_CATEGORY} and applies the bundled defaults under that category.
   *
   * @param n the node core used for filesystem access, scheduling, alerts, and USK subscriptions
   * @param publicGateway whether to initialize a secondary default category for gateway-mode hosts
   */
  public BookmarkManager(NodeClientCore n, boolean publicGateway) {
    putPaths("/", MAIN_CATEGORY);
    this.node = n;
    this.bookmarksFile = n.getNode().userDir().file("bookmarks.dat");
    this.backupBookmarksFile = n.getNode().userDir().file("bookmarks.dat.bak");

    try {
      // Read the backup file if necessary
      if (!bookmarksFile.exists() || bookmarksFile.length() == 0) throw new IOException();
      LOG.info("Attempting to read the bookmark file from {}", bookmarksFile);
      SimpleFieldSet sfs = SimpleFieldSet.readFrom(bookmarksFile, false, true);
      readBookmarks(MAIN_CATEGORY, sfs);
    } catch (MalformedURLException _) {
      // Bookmark file contains a malformed key; ignore and fall back to backup/defaults.
    } catch (IOException ioe) {
      LOG.error("Error reading the bookmark file ({}):{}", bookmarksFile, ioe.getMessage(), ioe);

      try {
        if (backupBookmarksFile.exists()
            && backupBookmarksFile.canRead()
            && backupBookmarksFile.length() > 0) {
          LOG.info("Attempting to read the backup bookmark file from {}", backupBookmarksFile);
          SimpleFieldSet sfs = SimpleFieldSet.readFrom(backupBookmarksFile, false, true);
          readBookmarks(MAIN_CATEGORY, sfs);
        } else {
          LOG.info(
              "We couldn't find the backup either! - {}",
              FileUtil.getCanonicalFile(backupBookmarksFile));
          // restore the default bookmark set
          readBookmarks(MAIN_CATEGORY, DEFAULT_BOOKMARKS);
        }
      } catch (IOException e) {
        LOG.error("Error reading the backup bookmark file !{}", e.getMessage(), e);
      }
    }
    // populate defaults for hosts without full access permissions if we're in gateway mode.
    if (publicGateway) {
      putPaths("\\", DEFAULT_CATEGORY);
      readBookmarks(DEFAULT_CATEGORY, DEFAULT_BOOKMARKS);
    }

    SemiOrderedShutdownHook.get()
        .addEarlyJob(
            new Thread() {
              BookmarkManager bm = BookmarkManager.this;

              @Override
              public void run() {
                bm.storeBookmarks();
                bm = null;
              }
            });
  }

  /**
   * Re-imports the bundled default bookmarks into a newly created category under the main root.
   *
   * <p>The category name is localized and includes the current time to minimize collisions with
   * existing names. This method parses {@link #DEFAULT_BOOKMARKS} and adds its entries into the new
   * category, then persists the updated tree if parsing succeeds.
   *
   * <p>This operation is additive: it does not remove or overwrite existing user bookmarks.
   */
  public void reAddDefaultBookmarks() {
    DateTimeFormatter formatter =
        DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US)
            .withZone(ZoneId.systemDefault());
    BookmarkCategory bc =
        new BookmarkCategory(l10n("defaultBookmarks") + " - " + formatter.format(Instant.now()));
    addBookmark("/", bc);
    innerReadBookmarks("/", bc, DEFAULT_BOOKMARKS);
  }

  private class USKUpdatedCallback implements USKCallback {

    @Override
    public void onFoundEdition(USKFoundEdition foundEdition) {
      if (!foundEdition.newKnownGood()) {
        FreenetURI uri = foundEdition.key().copy(foundEdition.edition()).getURI();
        node.makeClient(PRIORITY_PROGRESS, false, false)
            .prefetch(
                uri,
                MINUTES.toMillis(60),
                FProxyToadlet.getMaxLengthWithProgress(),
                null,
                PRIORITY_PROGRESS);
        return;
      }
      long edition = foundEdition.edition();
      USK key = foundEdition.key();
      List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
      boolean matched = false;
      boolean updated = false;
      for (BookmarkItem bookmarkItem : items) {
        if (!"USK".equals(bookmarkItem.getKeyType())) continue;

        try {
          FreenetURI furi = new FreenetURI(bookmarkItem.getKey());
          USK usk = USK.create(furi);

          if (usk.equals(key, false)) {
            if (LOG.isDebugEnabled())
              LOG.debug("Updating bookmark for {} to edition {}", furi, edition);
            matched = true;
            updated |= bookmarkItem.setEdition(edition, node);
            // We may have bookmarked the same site twice, so continue the search.
          }
        } catch (MalformedURLException _) {
          // Malformed bookmark key; ignore this entry.
        }
      }
      if (updated) {
        storeBookmarksLazy();
      } else if (!matched) {
        LOG.error("No match for bookmark {} edition {}", key, edition);
      }
    }

    @Override
    public short getPollingPriorityNormal() {
      return PRIORITY;
    }

    @Override
    public short getPollingPriorityProgress() {
      return PRIORITY_PROGRESS;
    }
  }

  /**
   * Looks up a localized string for BookmarkManager UI text.
   *
   * <p>This method prefixes the provided key with {@code "BookmarkManager."} and delegates to the
   * node localization base. It does not validate the key beyond basic concatenation, and it does
   * not cache results; callers should avoid invoking it in tight loops if localization lookups are
   * expensive in the current environment.
   *
   * <p>If the key is unknown, the behavior is determined by the localization subsystem; callers
   * should treat the returned value as user-facing text and avoid relying on any particular
   * fallback format.
   *
   * @param key the localization key suffix to resolve; typically a short identifier without spaces
   * @return the localized string for the current locale, or a fallback provided by the l10n system
   */
  public String l10n(String key) {
    return NodeL10n.getBase().getString("BookmarkManager." + key);
  }

  /**
   * Computes the parent path of a bookmark path.
   *
   * <p>The root path {@code "/"} is its own parent. For all other paths, this method returns the
   * substring up to (and including) the previous {@code '/'} separator. This is used to map a
   * concrete item or category path back to the category that contains it.
   *
   * <p>The input is expected to be a canonical bookmark path produced by this manager (for example,
   * the paths used by {@link #addBookmark(String, Bookmark)} and {@link #renameBookmark(String,
   * String)}). Malformed paths (such as strings without a {@code '/'} separator) may result in
   * {@link StringIndexOutOfBoundsException}.
   *
   * @param path an absolute bookmark path such as {@code "/Category/Item"} or {@code "/Category/"}
   * @return the parent category path, always ending with {@code '/'} (or {@code "/"} for root)
   */
  public String parentPath(String path) {
    if (path.equals("/")) return "/";

    return path.substring(0, path.substring(0, path.length() - 1).lastIndexOf('/')) + "/";
  }

  /**
   * Returns the bookmark object currently registered for a given path.
   *
   * <p>The returned value is the live instance stored in the in-memory bookmark tree. Callers
   * should avoid mutating returned instances directly unless they also update the path index
   * through this manager.
   *
   * @param path an absolute bookmark path keyed in the internal index (for example {@code "/Foo/"})
   * @return the bookmark instance for {@code path}, or {@code null} if no entry exists
   */
  public Bookmark getBookmarkByPath(String path) {
    synchronized (bookmarks) {
      return bookmarks.get(path);
    }
  }

  /**
   * Returns the category stored at a given path, if the path resolves to a category.
   *
   * <p>This is a convenience wrapper around {@link #getBookmarkByPath(String)} that performs a
   * type-check and returns {@code null} when the path is unknown or points to a non-category
   * bookmark. It does not create categories or normalize paths; callers should provide the exact
   * key used by the internal index.
   *
   * @param path an absolute bookmark path expected to identify a category (typically ending in
   *     {@code '/'})
   * @return the category at {@code path}, or {@code null} if absent or not a category
   */
  public BookmarkCategory getCategoryByPath(String path) {
    Bookmark cat = getBookmarkByPath(path);
    if (cat instanceof BookmarkCategory category) return category;

    return null;
  }

  /**
   * Returns the item stored at a given path, if the path resolves to an item.
   *
   * <p>This is a convenience wrapper around {@link #getBookmarkByPath(String)} that performs a
   * type-check and returns {@code null} when the path is unknown or points to a category.
   *
   * <p>The returned value is the live in-memory item instance; it is not copied. Callers should
   * prefer higher-level operations (rename/move/remove) over mutating the returned item directly so
   * that the path index and related subscriptions remain consistent.
   *
   * @param path an absolute bookmark path expected to identify an item (typically not ending in
   *     {@code '/'})
   * @return the item at {@code path}, or {@code null} if absent or not an item
   */
  public BookmarkItem getItemByPath(String path) {
    Bookmark bookmark = getBookmarkByPath(path);
    if (bookmark instanceof BookmarkItem item) return item;

    return null;
  }

  /**
   * Adds a bookmark under an existing parent category and updates the internal path index.
   *
   * <p>The {@code parentPath} must resolve to an existing {@link BookmarkCategory}. The bookmark is
   * appended to that category and then indexed under a computed absolute path. For categories, the
   * computed path is suffixed with {@code '/'} so that category paths and item paths remain
   * distinct.
   *
   * <p>If the bookmark is a {@link BookmarkItem} whose {@link BookmarkItem#getKeyType()} equals
   * {@code "USK"}, this method also subscribes to USK polling for that item so editions can be kept
   * up to date.
   *
   * <p>This method does not persist changes by itself. Callers are expected to choose between
   * immediate persistence ({@link #storeBookmarks()}) and a delayed/coalesced write ({@link
   * #storeBookmarksLazy()}) depending on the update pattern.
   *
   * <pre>{@code
   * BookmarkCategory category = new BookmarkCategory("News");
   * manager.addBookmark("/", category);
   * manager.storeBookmarksLazy();
   * }</pre>
   *
   * @param parentPath absolute path of the parent category (for example {@code "/"} or {@code
   *     "/Foo/"})
   * @param bookmark bookmark instance to add; its {@link Bookmark#getName()} is used to compute the
   *     indexed path
   */
  public void addBookmark(String parentPath, Bookmark bookmark) {
    if (LOG.isDebugEnabled()) LOG.debug("Adding bookmark {} to {}", bookmark, parentPath);
    BookmarkCategory parent = getCategoryByPath(parentPath);
    parent.addBookmark(bookmark);
    putPaths(
        parentPath + bookmark.getName() + ((bookmark instanceof BookmarkCategory) ? "/" : ""),
        bookmark);

    if (bookmark instanceof BookmarkItem item) subscribeToUSK(item);
  }

  /**
   * Renames a bookmark and rewrites all indexed paths that refer to it or its descendants.
   *
   * <p>This method updates the bookmark's name and then rebuilds the path index entries whose keys
   * start with the previous {@code path}. For a renamed category, all child entries are migrated to
   * the new path prefix as well.
   *
   * <p>After the index update completes, the updated tree is persisted immediately via {@link
   * #storeBookmarks()}.
   *
   * @param path absolute path of the bookmark to rename, using the current name
   * @param newName new bookmark name to set; used as the final path segment of the new path
   */
  public void renameBookmark(String path, String newName) {
    Bookmark bookmark = getBookmarkByPath(path);
    String oldName = bookmark.getName();
    String oldPath = '/' + oldName;
    String newPath =
        path.substring(0, path.indexOf(oldPath))
            + '/'
            + newName
            + (bookmark instanceof BookmarkCategory ? "/" : "");

    bookmark.setName(newName);
    synchronized (bookmarks) {
      bookmarks.keySet().removeIf(s -> s.startsWith(path));
      putPaths(newPath, bookmark);
    }
    storeBookmarks();
  }

  /**
   * Moves an existing bookmark to a different parent category and updates the path index.
   *
   * <p>The same bookmark instance is re-attached under {@code newParentPath}, removed from its
   * previous parent category, and then de-indexed from its former path prefix.
   *
   * <p>This method does not persist changes automatically; callers typically follow up with {@link
   * #storeBookmarks()} or {@link #storeBookmarksLazy()} depending on the desired persistence
   * strategy.
   *
   * @param bookmarkPath absolute path of the bookmark to move, using its current location
   * @param newParentPath absolute path of the destination parent category
   */
  public void moveBookmark(String bookmarkPath, String newParentPath) {
    Bookmark b = getBookmarkByPath(bookmarkPath);
    addBookmark(newParentPath, b);

    getCategoryByPath(parentPath(bookmarkPath)).removeBookmark(b);
    removePaths(bookmarkPath);
  }

  /**
   * Removes a bookmark from the tree and cleans up any associated USK subscription state.
   *
   * <p>If the bookmark is a category, all descendant bookmarks are removed recursively. If the
   * bookmark is a USK-typed item, the manager may unsubscribe from USK polling when no other
   * bookmark item still references the same USK key.
   *
   * <p>This method updates the in-memory tree and path index only; it does not automatically
   * persist changes to disk.
   *
   * @param path absolute path of the bookmark to remove
   */
  public void removeBookmark(String path) {
    Bookmark bookmark = getBookmarkByPath(path);
    switch (bookmark) {
      case null -> {
        return;
      }
      case BookmarkCategory category -> removeCategoryBookmarks(path, category);
      case BookmarkItem item -> unsubscribeFromUskIfUnneeded(item);
      default -> {
        // No subtype-specific cleanup is required for unknown Bookmark implementations.
      }
    }

    getCategoryByPath(parentPath(path)).removeBookmark(bookmark);
    synchronized (bookmarks) {
      bookmarks.remove(path);
    }
  }

  private void removeCategoryBookmarks(String path, BookmarkCategory category) {
    for (int i = 0; i < category.size(); i++) {
      Bookmark child = category.get(i);
      String childPath = path + child.getName() + (child instanceof BookmarkCategory ? "/" : "");
      removeBookmark(childPath);
    }
  }

  private void unsubscribeFromUskIfUnneeded(BookmarkItem item) {
    if (!"USK".equals(item.getKeyType())) return;

    try {
      USK u = item.getUSK();
      if (!wantUSK(u, item)) {
        node.getUskManager().unsubscribe(u, uskCB);
      }
    } catch (MalformedURLException _) {
      // Malformed bookmark key; there is nothing to unsubscribe from.
    }
  }

  private boolean wantUSK(USK u, BookmarkItem ignore) {
    List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
    for (BookmarkItem item : items) {
      if (ignore != null && item.instanceId() == ignore.instanceId()) continue;
      if (!"USK".equals(item.getKeyType())) continue;

      try {
        FreenetURI furi = new FreenetURI(item.getKey());
        USK usk = USK.create(furi);

        if (usk.equals(u, false)) return true;
      } catch (MalformedURLException _) {
        // Ignore malformed bookmark keys when checking whether any other bookmark wants this USK.
      }
    }
    return false;
  }

  /**
   * Moves a bookmark one position earlier within its parent category.
   *
   * <p>The move is performed within the parent category returned by {@link #parentPath(String)}. If
   * {@code store} is true, the updated tree is persisted immediately.
   *
   * <p>This method affects only the ordering within the parent category and does not change the
   * bookmark's path. If the bookmark is already at the top of the list, the underlying category may
   * leave the order unchanged.
   *
   * @param path absolute path of the bookmark to move up
   * @param store whether to persist the updated ordering to disk after the move
   */
  public void moveBookmarkUp(String path, boolean store) {
    BookmarkCategory parent = getCategoryByPath(parentPath(path));
    parent.moveBookmarkUp(getBookmarkByPath(path));

    if (store) storeBookmarks();
  }

  /**
   * Moves a bookmark one position later within its parent category.
   *
   * <p>The move is performed within the parent category returned by {@link #parentPath(String)}. If
   * {@code store} is true, the updated tree is persisted immediately.
   *
   * <p>This method affects only the ordering within the parent category and does not change the
   * bookmark's path. If the bookmark is already at the bottom of the list, the underlying category
   * may leave the order unchanged.
   *
   * @param path absolute path of the bookmark to move down
   * @param store whether to persist the updated ordering to disk after the move
   */
  public void moveBookmarkDown(String path, boolean store) {
    BookmarkCategory parent = getCategoryByPath(parentPath(path));
    parent.moveBookmarkDown(getBookmarkByPath(path));

    if (store) storeBookmarks();
  }

  private void putPaths(String path, Bookmark b) {
    synchronized (bookmarks) {
      bookmarks.put(path, b);
    }
    if (b instanceof BookmarkCategory category)
      for (int i = 0; i < category.size(); i++) {
        Bookmark child = category.get(i);
        putPaths(path + child.getName() + (child instanceof BookmarkItem ? "" : "/"), child);
      }
  }

  private void removePaths(String path) {
    if (getBookmarkByPath(path) instanceof BookmarkCategory) {
      BookmarkCategory cat = getCategoryByPath(path);
      for (int i = 0; i < cat.size(); i++)
        removePaths(
            path + cat.get(i).getName() + (cat.get(i) instanceof BookmarkCategory ? "/" : ""));
    }
    bookmarks.remove(path);
  }

  /**
   * Returns all bookmark item URIs under the main category.
   *
   * <p>The returned array is a snapshot of the current item list at the time of iteration. The
   * array ordering follows the underlying item order returned by {@link BookmarkCategory} for
   * {@link #MAIN_CATEGORY}.
   *
   * <p>Only {@link BookmarkItem} instances contribute to the result. Category entries are excluded,
   * and the returned array does not include items from {@link #DEFAULT_CATEGORY}.
   *
   * @return an array containing the {@link FreenetURI} for each bookmark item under the main root
   */
  public FreenetURI[] getBookmarkURIs() {
    List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
    FreenetURI[] uris = new FreenetURI[items.size()];
    for (int i = 0; i < items.size(); i++) uris[i] = items.get(i).getURI();

    return uris;
  }

  /**
   * Schedules a delayed persistence of bookmarks, coalescing multiple updates into one write.
   *
   * <p>If a delayed save is already scheduled, this method is a no-op. Otherwise, it queues a job
   * on the node ticker to invoke {@link #storeBookmarks()} after approximately 5 minutes. This is
   * used to reduce disk churn for bursty updates (for example, USK edition updates).
   *
   * <p>The method returns immediately and does not wait for I/O. A best-effort guard ensures only
   * one delayed job is queued at a time, so repeated calls within the delay window are collapsed
   * into the same scheduled write.
   */
  public void storeBookmarksLazy() {
    synchronized (bookmarks) {
      if (isSavingBookmarksLazy) return;
      isSavingBookmarksLazy = true;
      node.getNode()
          .network()
          .ticker()
          .queueTimedJob(
              () -> {
                try {
                  storeBookmarks();
                } finally {
                  isSavingBookmarksLazy = false;
                }
              },
              MINUTES.toMillis(5));
    }
  }

  /**
   * Writes the current bookmark tree to disk, using a backup write-then-rename strategy.
   *
   * <p>This method serializes the current tree to a {@link SimpleFieldSet}, writes it to {@code
   * bookmarks.dat.bak}, and then attempts to move it into place as {@code bookmarks.dat}. A
   * re-entrant guard prevents concurrent writers from executing the write simultaneously.
   *
   * <p>Failures are logged and do not throw to callers. The write operation uses regular file I/O
   * and may block while data is flushed to disk.
   */
  public void storeBookmarks() {
    LOG.info("Attempting to save bookmarks to {}", bookmarksFile);
    SimpleFieldSet sfs;
    synchronized (bookmarks) {
      if (isSavingBookmarks) return;
      isSavingBookmarks = true;

      sfs = toSimpleFieldSet();
    }
    try {
      try (FileOutputStream fos = new FileOutputStream(backupBookmarksFile)) {
        sfs.writeToBigBuffer(fos);
      }
      if (!FileUtil.moveTo(backupBookmarksFile, bookmarksFile))
        LOG.error("Unable to rename {} to {}", backupBookmarksFile, bookmarksFile);
    } catch (IOException ioe) {
      LOG.error("An error has occured saving the bookmark file :{}", ioe.getMessage(), ioe);
    } finally {
      synchronized (bookmarks) {
        isSavingBookmarks = false;
      }
    }
  }

  private void readBookmarks(BookmarkCategory category, SimpleFieldSet sfs) {
    innerReadBookmarks("", category, sfs);
  }

  static final short PRIORITY = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;
  static final short PRIORITY_PROGRESS = RequestStarter.UPDATE_PRIORITY_CLASS;

  private void subscribeToUSK(BookmarkItem item) {
    if (!"USK".equals(item.getKeyType())) return;
    try {
      USK u = item.getUSK();
      this.node.getUskManager().subscribe(u, this.uskCB, true, this);
    } catch (MalformedURLException _) {
      // Malformed bookmark key; ignore and do not subscribe.
    }
  }

  private synchronized void innerReadBookmarks(
      String prefix, BookmarkCategory category, SimpleFieldSet sfs) {
    boolean isRoot = ("".equals(prefix) && MAIN_CATEGORY.equals(category));
    boolean parsedOk = parseBookmarksIntoCategory(prefix, category, sfs, isRoot);
    if (parsedOk) storeBookmarks();
  }

  private boolean parseBookmarksIntoCategory(
      String prefix, BookmarkCategory category, SimpleFieldSet sfs, boolean isRoot) {
    synchronized (bookmarks) {
      if (!isRoot) putPaths(prefix + category.name + '/', category);
      if (sfs == null) return false;

      try {
        int nbBookmarks = sfs.getInt(BookmarkItem.BOOKMARK_PREFIX);
        int nbCategories = sfs.getInt(BookmarkCategory.SFS_KEY);

        parseBookmarkItems(prefix, category, sfs, isRoot, nbBookmarks);
        parseBookmarkCategories(prefix, category, sfs, isRoot, nbCategories);
        return true;
      } catch (FSParseException e) {
        LOG.error("Error parsing the bookmarks file!", e);
        return false;
      }
    }
  }

  private void parseBookmarkItems(
      String prefix, BookmarkCategory category, SimpleFieldSet sfs, boolean isRoot, int nbBookmarks)
      throws FSParseException {
    for (int i = 0; i < nbBookmarks; i++) {
      SimpleFieldSet subset = sfs.getSubset(BookmarkItem.BOOKMARK_PREFIX + i);
      addBookmarkItem(prefix, category, subset, isRoot);
    }
  }

  private void addBookmarkItem(
      String prefix, BookmarkCategory category, SimpleFieldSet subset, boolean isRoot)
      throws FSParseException {
    try {
      BookmarkItem item = new BookmarkItem(subset, this, node.getAlerts());
      String name = (isRoot ? "" : prefix + category.name) + '/' + item.name;
      putPaths(name, item);
      category.addBookmark(item);
      item.registerUserAlert();
      subscribeToUSK(item);
    } catch (MalformedURLException e) {
      throw new FSParseException(e);
    }
  }

  private void parseBookmarkCategories(
      String prefix,
      BookmarkCategory category,
      SimpleFieldSet sfs,
      boolean isRoot,
      int nbCategories)
      throws FSParseException {
    for (int i = 0; i < nbCategories; i++) {
      SimpleFieldSet subset = sfs.getSubset(BookmarkCategory.SFS_KEY + i);
      BookmarkCategory currentCategory = new BookmarkCategory(subset);
      category.addBookmark(currentCategory);
      String name = (isRoot ? "/" : (prefix + category.name + '/'));
      innerReadBookmarks(name, currentCategory, subset.getSubset("Content"));
    }
  }

  /**
   * Serializes the current manager state into a {@link SimpleFieldSet}.
   *
   * <p>The returned field set uses a simple versioned format and contains the serialized form of
   * {@link #MAIN_CATEGORY}. The returned instance is a detached representation that can be written
   * to disk via {@link SimpleFieldSet#writeToBigBuffer(java.io.OutputStream)}.
   *
   * <p>This method snapshots the tree while holding the {@code bookmarks} lock to keep the map
   * consistent with the serialized structure. The returned {@link SimpleFieldSet} is mutable, but
   * mutating it does not affect the manager state; callers should treat it as write-only
   * persistence output.
   *
   * @return a newly created field set representing the current bookmark tree
   */
  public SimpleFieldSet toSimpleFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);

    sfs.put("Version", 1);
    synchronized (bookmarks) {
      sfs.putAllOverwrite(BookmarkManager.toSimpleFieldSet(MAIN_CATEGORY));
    }

    return sfs;
  }

  /**
   * Serializes a bookmark category (and all of its descendants) into a {@link SimpleFieldSet}.
   *
   * <p>This method writes both child categories and bookmark items into indexed subsets using the
   * keys defined by {@link BookmarkCategory#SFS_KEY} and {@link BookmarkItem#BOOKMARK_PREFIX}. It
   * is used for persistence and can be invoked for any subtree, not only the main root.
   *
   * <p>The resulting field set includes counts for both categories and items, allowing the reader
   * to iterate deterministically when reconstructing the tree.
   *
   * @param cat the category to serialize; all subcategories and items are included recursively
   * @return a newly created field set representing {@code cat} and its contents
   */
  public static SimpleFieldSet toSimpleFieldSet(BookmarkCategory cat) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    List<BookmarkCategory> bc = cat.getSubCategories();

    for (int i = 0; i < bc.size(); i++) {
      BookmarkCategory currentCat = bc.get(i);
      sfs.put(BookmarkCategory.SFS_KEY + i, currentCat.getSimpleFieldSet());
    }
    sfs.put(BookmarkCategory.SFS_KEY, bc.size());

    List<BookmarkItem> bi = cat.getItems();
    for (int i = 0; i < bi.size(); i++)
      sfs.put(BookmarkItem.BOOKMARK_PREFIX + i, bi.get(i).getSimpleFieldSet());
    sfs.put(BookmarkItem.BOOKMARK_PREFIX, bi.size());

    return sfs;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This manager does not represent a persistent request client; it is used for UI-driven helper
   * requests (such as USK polling) and does not require restart persistence at the request layer.
   *
   * @return always {@code false}
   */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Bookmark-related requests are not treated as real-time traffic by this client.
   *
   * @return always {@code false}
   */
  @Override
  public boolean realTimeFlag() {
    return false;
  }
}
