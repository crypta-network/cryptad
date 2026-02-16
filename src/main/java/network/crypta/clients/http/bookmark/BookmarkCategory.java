package network.crypta.clients.http.bookmark;

import java.util.ArrayList;
import java.util.List;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;

/**
 * A {@link Bookmark} that groups other bookmarks into a hierarchical category tree.
 *
 * <p>A {@code BookmarkCategory} is used by the HTTP bookmark UI to model folders that can contain
 * both {@link BookmarkItem} leaves and nested {@link BookmarkCategory} children. Instances are
 * typically created either from a display name (for new categories) or by decoding a persisted
 * {@link SimpleFieldSet} (for loading existing bookmark structures). Callers then add, remove, and
 * reorder entries via the provided methods and finally persist the structure again via {@link
 * #getSimpleFieldSet()}.
 *
 * <p>The internal list is mutable but is guarded by {@code synchronized} instance methods, making
 * compound operations on the category contents atomic with respect to other calls on the same
 * object. Returned collections are snapshots: modifications to the returned lists do not affect
 * this category, although the contained bookmark objects themselves are shared references.
 *
 * <ul>
 *   <li><b>Responsibility:</b> maintain an ordered list of child bookmarks.
 *   <li><b>Notable behavior:</b> movement operations are best-effort and no-op when not applicable.
 *   <li><b>Persistence:</b> serializes name plus content using {@link BookmarkManager} helpers.
 * </ul>
 *
 * @see Bookmark
 * @see BookmarkItem
 * @see BookmarkManager
 */
public final class BookmarkCategory extends Bookmark {
  /**
   * Type discriminator used when encoding or decoding this bookmark kind in a {@link
   * SimpleFieldSet}.
   *
   * <p>This key is intentionally stable because persisted bookmark data may include it as an
   * identifier for category nodes.
   */
  public static final String SFS_KEY = "BookmarkCategory";

  private final List<Bookmark> bookmarks = new ArrayList<>();

  /**
   * Creates an empty category with the given display name.
   *
   * <p>The new instance contains no child bookmarks. After construction, callers typically add
   * {@link BookmarkItem} and/or nested {@link BookmarkCategory} instances and then persist the
   * resulting structure via {@link #getSimpleFieldSet()}.
   *
   * @param name the display name for the category; must be non-null and non-empty for UI display
   */
  public BookmarkCategory(String name) {
    setName(name);
  }

  /**
   * Reconstructs a category from its serialized {@link SimpleFieldSet} representation.
   *
   * <p>This constructor reads the required {@code Name} field from {@code sfs} and initializes the
   * category name accordingly. The category contents are expected to be handled by surrounding code
   * that parses the serialized bookmark tree.
   *
   * @param sfs the serialized field set to read from; must contain a {@code Name} entry
   * @throws FSParseException if the field set is missing required fields or is otherwise malformed
   */
  public BookmarkCategory(SimpleFieldSet sfs) throws FSParseException {
    String aName = sfs.get("Name");
    if (aName == null) throw new FSParseException("No Name!");
    setName(aName);
  }

  /**
   * Adds a child bookmark to this category if it is not already present.
   *
   * <p>The category maintains a single ordered list containing both {@link BookmarkItem} leaves and
   * nested {@link BookmarkCategory} nodes. If a bookmark that compares equal to {@code b} already
   * exists (as defined by {@link List#indexOf(Object)}), this method returns the existing instance
   * and leaves the list unchanged.
   *
   * <p>This method is synchronized to ensure that the presence check and conditional insertion are
   * performed atomically with respect to other mutations of the category contents.
   *
   * @param b the bookmark to add; may be {@code null}, in which case this method does nothing
   * @return the bookmark instance present in the category, or {@code null} if {@code b} is null
   */
  synchronized Bookmark addBookmark(Bookmark b) {
    if (b == null) {
      return null;
    }
    // Return the existing bookmark if one is already present.
    int x = bookmarks.indexOf(b);
    if (x >= 0) {
      return bookmarks.get(x);
    }
    bookmarks.add(b);
    return b;
  }

  /**
   * Removes a child bookmark from this category.
   *
   * <p>If the bookmark is not present, this method has no effect. Removal uses the list's equality
   * semantics, so it removes the first entry that compares equal to {@code b}.
   *
   * @param b the bookmark to remove; may be {@code null}, in which case this method does nothing
   */
  synchronized void removeBookmark(Bookmark b) {
    bookmarks.remove(b);
  }

  /**
   * Returns the child bookmark at the given index in this category.
   *
   * <p>The ordering corresponds to the in-memory order maintained by this category, which is
   * affected by insertion order and by {@link #moveBookmarkUp(Bookmark)} / {@link
   * #moveBookmarkDown(Bookmark)} operations.
   *
   * @param i the zero-based index of the child entry to return; must be within the current bounds
   * @return the child bookmark stored at the requested index
   * @throws IndexOutOfBoundsException if {@code i} is negative or not less than {@link #size()}
   */
  public synchronized Bookmark get(int i) {
    return bookmarks.get(i);
  }

  /**
   * Moves the given bookmark one position earlier within this category's ordering.
   *
   * <p>If the bookmark is not present, this method is a no-op. If the bookmark is already the first
   * element, it remains at position {@code 0}. Movement is performed as a remove-then-insert within
   * the underlying list and is synchronized to prevent concurrent reordering or removal from
   * producing inconsistent results.
   *
   * @param b the bookmark to move; if {@code null} or absent, this method has no effect
   */
  synchronized void moveBookmarkUp(Bookmark b) {
    int index = bookmarks.indexOf(b);
    if (index == -1) {
      return;
    }

    Bookmark bk = bookmarks.remove(index);
    bookmarks.add((--index < 0) ? 0 : index, bk);
  }

  /**
   * Moves the given bookmark one position later within this category's ordering.
   *
   * <p>If the bookmark is not present, this method is a no-op. If the bookmark is already the last
   * element, it remains at the end of the list. Movement is performed as a remove-then-insert
   * operation and is synchronized to provide an atomic reordering with respect to other category
   * mutations.
   *
   * @param b the bookmark to move; if {@code null} or absent, this method has no effect
   */
  synchronized void moveBookmarkDown(Bookmark b) {
    int index = bookmarks.indexOf(b);
    if (index == -1) {
      return;
    }

    Bookmark bk = bookmarks.remove(index);
    bookmarks.add((++index > size()) ? size() : index, bk);
  }

  /**
   * Returns the number of direct child bookmarks held by this category.
   *
   * <p>This count includes both {@link BookmarkItem} entries and nested {@link BookmarkCategory}
   * entries, but does not include grandchildren or deeper descendants.
   *
   * @return the number of immediate children currently stored in this category
   */
  public synchronized int size() {
    return bookmarks.size();
  }

  /**
   * Returns the direct {@link BookmarkItem} children of this category.
   *
   * <p>The returned list is a snapshot built at the time of the call. Modifying the returned list
   * does not affect this category, but the {@link BookmarkItem} instances inside are the same
   * objects stored in the category.
   *
   * @return a new list containing only direct {@link BookmarkItem} children, in current order
   */
  public synchronized List<BookmarkItem> getItems() {
    List<BookmarkItem> items = new ArrayList<>();
    for (Bookmark b : bookmarks) {
      if (b instanceof BookmarkItem item) {
        items.add(item);
      }
    }
    return items;
  }

  /**
   * Returns all {@link BookmarkItem} descendants reachable from this category.
   *
   * <p>This method traverses the category tree depth-first. It first returns the direct items from
   * {@link #getItems()} and then recursively accumulates items from each sub-category returned by
   * {@link #getSubCategories()}. The returned list is a snapshot; later mutations to the category
   * structure are not reflected in the result.
   *
   * @return a new list containing all item descendants, preserving the current traversal order
   */
  public synchronized List<BookmarkItem> getAllItems() {
    List<BookmarkItem> items = getItems();
    for (BookmarkCategory cat : getSubCategories()) {
      items.addAll(cat.getAllItems());
    }
    return items;
  }

  /**
   * Returns the direct sub-categories contained by this category.
   *
   * <p>The returned list is a snapshot that includes only those children that are themselves {@link
   * BookmarkCategory} instances. The ordering matches the current in-memory ordering of the
   * underlying child list.
   *
   * @return a new list containing the direct sub-categories of this category, in current order
   */
  public synchronized List<BookmarkCategory> getSubCategories() {
    List<BookmarkCategory> categories = new ArrayList<>();
    for (Bookmark b : bookmarks) {
      if (b instanceof BookmarkCategory category) {
        categories.add(category);
      }
    }
    return categories;
  }

  /**
   * Returns all descendant sub-categories reachable from this category.
   *
   * <p>This method returns the direct children from {@link #getSubCategories()} and then
   * recursively adds each child's descendants. The returned list is a snapshot, so subsequent
   * mutations to the category tree do not affect the returned result.
   *
   * @return a new list containing all descendant categories, preserving the current traversal order
   */
  public synchronized List<BookmarkCategory> getAllSubCategories() {
    List<BookmarkCategory> categories = getSubCategories();
    for (BookmarkCategory cat : getSubCategories()) {
      categories.addAll(cat.getAllSubCategories());
    }
    return categories;
  }

  /**
   * Flattens this category tree into a list of display-oriented strings.
   *
   * <p>The resulting strings use {@code '/'} as a path separator. Each {@link BookmarkCategory}
   * contributes its {@linkplain #getName() name} followed by a trailing {@code '/'} to the prefix,
   * and each {@link BookmarkItem} contributes its {@link Object#toString()} representation at the
   * leaf. This method is intended for UI-facing or debugging-style output, not for persistence.
   *
   * <p>This method does not synchronize; it relies on called methods that snapshot the current
   * children. Callers that concurrently mutate category names or structure should synchronize
   * externally if they require a fully consistent view.
   *
   * @return an array of flattened path-like strings for items contained within this category tree
   */
  public String[] toStrings() {
    return toStrings("").toArray(new String[0]);
  }

  // Internal use only

  private List<String> toStrings(String prefix) {
    List<String> strings = new ArrayList<>();
    List<BookmarkItem> items = getItems();
    List<BookmarkCategory> subCategories = getSubCategories();
    prefix += this.name + "/";

    for (BookmarkItem item : items) {
      strings.add(prefix + item.toString());
    }

    for (BookmarkCategory subCategory : subCategories) {
      strings.addAll(subCategory.toStrings(prefix));
    }

    return strings;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized SimpleFieldSet getSimpleFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Name", name);
    sfs.put("Content", BookmarkManager.toSimpleFieldSet(this));
    return sfs;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
