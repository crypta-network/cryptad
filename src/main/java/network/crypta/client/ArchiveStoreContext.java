package network.crypta.client;

import java.util.ArrayDeque;
import network.crypta.keys.FreenetURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks extracted archive members and state for a specific {@link FreenetURI} key.
 *
 * <p>This context is the per-key index used by {@link ArchiveManager} to remember which {@link
 * ArchiveStoreItem}s are currently cached for an archive and to retain lightweight state about the
 * last successful extraction. It records the last known archive size and hash so callers can detect
 * when the underlying container has changed and refresh cached members accordingly. The class
 * itself performs no I/O; it provides bookkeeping and coordination hooks invoked by the manager
 * during extraction and eviction.
 *
 * <p>Typical usage is: the manager creates a context for a key, extracts members, and registers
 * resulting items with {@link #addItem(ArchiveStoreItem)}. If a later fetch discovers a changed
 * hash or size, the manager calls {@link #removeAllCachedItems(ArchiveManager)} to evict previous
 * items and then repopulates the cache before signalling a restart to the caller.
 *
 * <p>Thread-safety: the internal item list is guarded by its own monitor. Code outside this class
 * must always lock the {@code ArchiveStoreContext} (or its {@code myItems} list) before acquiring
 * the {@link ArchiveManager} lock to avoid deadlocks; the correct ordering is <em>context →
 * manager</em>. Minimal cleanup for individual items is performed outside the list lock.
 *
 * <ul>
 *   <li>Remembers last observed archive size and hash for change detection.
 *   <li>Indexes cached items for the owning key using LIFO semantics.
 *   <li>Coordinates safe removal of items and their resource cleanup.
 * </ul>
 *
 * @see ArchiveManager
 * @see ArchiveStoreItem
 * @see FreenetURI
 */
class ArchiveStoreContext {
  /** Logger for diagnostic messages within this context. */
  private static final Logger LOG = LoggerFactory.getLogger(ArchiveStoreContext.class);

  /** The immutable network key identifying the archive whose members are tracked. */
  private final FreenetURI key;

  /**
   * The archive container type associated with {@link #key}; fixed for the lifetime of this
   * context.
   */
  private final ArchiveManager.ARCHIVE_TYPE archiveType;

  /** Archive size */
  private long lastSize = -1;

  /** Archive hash */
  private byte[] lastHash;

  /**
   * Index of still-cached ArchiveStoreItems with this key. Note that we never ever hold this and
   * then take another lock! In particular, we must not take the ArchiveManager lock while holding
   * this lock. It must be the inner lock to avoid deadlocks.
   */
  private final ArrayDeque<ArchiveStoreItem> myItems;

  /**
   * Creates a new context bound to a specific key and archive type.
   *
   * <p>The newly created context has no cached items and no prior size or hash; {@link
   * #getLastSize()} returns {@code -1} and {@link #getLastHash()} returns {@code null} until
   * collaborators record concrete values after extraction. This constructor performs no I/O.
   *
   * @param key the {@link FreenetURI} of the container whose members are tracked; callers pass the
   *     non-null key they are working with
   * @param archiveType the {@link ArchiveManager.ARCHIVE_TYPE} for the container; determines how
   *     higher layers will interpret the data when extracting
   */
  ArchiveStoreContext(FreenetURI key, ArchiveManager.ARCHIVE_TYPE archiveType) {
    this.key = key;
    this.archiveType = archiveType;
    myItems = new ArrayDeque<>();
  }

  /**
   * Returns the size of the archive during the last successful extraction.
   *
   * <p>A value of {@code -1} indicates that no size has been recorded yet for this context. The
   * value is advisory and used primarily for change detection by collaborating components.
   *
   * @return the last recorded size in bytes, or {@code -1} when unknown
   */
  long getLastSize() {
    return lastSize;
  }

  /**
   * Records the last observed size of the archive for change detection.
   *
   * <p>This method simply stores the provided value. It is commonly invoked after a successful
   * extraction, and may be set back to {@code -1} to indicate an unknown size.
   *
   * @param size size of the archive in bytes; use {@code -1} to clear and mark as unknown
   * @see #getLastSize()
   */
  void setLastSize(long size) {
    lastSize = size;
  }

  /**
   * Returns the content hash of the archive from the last successful extraction, if any.
   *
   * <p>The hashing algorithm is defined by collaborating components; this context only stores the
   * raw bytes. A {@code null} value indicates that no hash has been recorded.
   *
   * @return raw hash bytes for the last extracted state, or {@code null} when none recorded
   */
  byte[] getLastHash() {
    return lastHash;
  }

  /**
   * Records the content hash bytes for the current archive state.
   *
   * <p>Callers provide the raw bytes as produced by their hashing mechanism. Passing {@code null}
   * clears any previously stored value.
   *
   * @param realHash raw hash bytes representing current contents; {@code null} to clear
   * @see #getLastHash()
   */
  void setLastHash(byte[] realHash) {
    lastHash = realHash;
  }

  /**
   * Removes all {@link ArchiveStoreItem} instances with this key from the manager's cache.
   *
   * <p>The method repeatedly obtains the head of the internal stack and asks the {@link
   * ArchiveManager} to remove it. Removal proceeds until the local index is empty. Items perform
   * their own minimal cleanup during removal.
   *
   * @param manager the {@link ArchiveManager} coordinating eviction and cleanup; must not be {@code
   *     null} when items are present
   */
  void removeAllCachedItems(ArchiveManager manager) {
    ArchiveStoreItem item;
    while (true) {
      synchronized (myItems) {
        // removeCachedItem() will call removeItem(), so don't remove it here.
        item = myItems.peek();
      }
      if (item == null) break;
      manager.removeCachedItem(item);
    }
  }

  /**
   * Registers that a new {@link ArchiveStoreItem} for this key has been added to the cache.
   *
   * @param item the item to add to this context's local index; must not be {@code null}
   */
  void addItem(ArchiveStoreItem item) {
    synchronized (myItems) {
      myItems.push(item);
    }
  }

  /**
   * Notify that an archive store item with this key has been expelled from the cache. Remove it
   * from our local cache and ask it to free the bucket if necessary.
   *
   * <p>If the item has already been removed, the method logs a debug message and returns without
   * further action. On first removal, {@link ArchiveStoreItem#innerClose()} is invoked after
   * releasing the list lock to allow safe cleanup.
   *
   * @param item the item to remove; repeated calls for the same instance are tolerated and become
   *     no-ops after the first successful removal
   */
  void removeItem(ArchiveStoreItem item) {
    synchronized (myItems) {
      if (!myItems.remove(item)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Not removing: {} for {} - already removed", item, this);
        return; // only removed once
      }
    }
    item.innerClose();
  }

  /**
   * Returns the stable numeric identifier for this context's archive type.
   *
   * <p>The value corresponds to {@link ArchiveManager.ARCHIVE_TYPE#metadataID} and does not change
   * during the lifetime of the context.
   *
   * @return the {@code short} metadata identifier for the archive type represented here
   */
  public short getArchiveType() {
    return archiveType.metadataID;
  }

  /**
   * Returns the {@link FreenetURI} key associated with this context.
   *
   * <p>The reference is the same instance provided at construction time and should be treated as
   * immutable by callers.
   *
   * @return the immutable key identifying the tracked archive
   */
  public FreenetURI getKey() {
    return key;
  }
}
