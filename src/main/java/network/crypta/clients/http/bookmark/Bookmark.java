package network.crypta.clients.http.bookmark;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.SimpleFieldSet;

/**
 * Base type for bookmarks exposed by the HTTP client UI.
 *
 * <p>A {@code Bookmark} primarily wraps a user-visible name and provides a compact serialization
 * via {@link #getSimpleFieldSet()} so that subclasses can be persisted and restored consistently.
 * The name is stored in a "raw" form (see {@link #getName()}) and can optionally use an {@code
 * l10n:} prefix to reference a translation key; {@link #getVisibleName()} resolves that prefix via
 * {@link NodeL10n} for display, while leaving ordinary names unchanged.
 *
 * <p>This class is intentionally small and mutable: subclasses typically set the name during
 * construction or deserialization, and callers should treat instances as ordinary in-memory model
 * objects. The implementation is not thread-safe; if a bookmark instance may be accessed from
 * multiple threads, callers must provide external synchronization or publish immutable snapshots.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Store the bookmark's raw name and expose it to callers.
 *   <li>Provide a localized display name for built-in/default bookmark entries.
 *   <li>Expose a {@link SimpleFieldSet} representation for persistence and transport.
 * </ul>
 *
 * @see NodeL10n
 * @see SimpleFieldSet
 */
public abstract class Bookmark {

  /**
   * Raw bookmark name.
   *
   * <p>The value is expected to be non-null before any public accessor is called. Subclasses are
   * responsible for initializing it (for example during construction or deserialization). If the
   * string begins with {@code l10n:} (case-insensitive), {@link #getVisibleName()} treats the
   * remainder as a localization key suffix rather than literal user input.
   */
  protected String name;

  /**
   * Creates an uninitialized bookmark instance.
   *
   * <p>This constructor performs no initialization beyond the implicit Java defaults. Subclasses
   * are expected to set a non-null {@link #name} (for example via {@link #setName(String)} or by
   * assigning directly) before exposing the instance to other code.
   *
   * <p>As a consequence, calling methods such as {@link #getVisibleName()}, {@link
   * #equals(Object)}, or {@link #hashCode()} before initialization may result in a {@link
   * NullPointerException}. Implementations that deserialize bookmarks typically populate {@link
   * #name} before returning the instance to callers.
   */
  protected Bookmark() {}

  /**
   * Returns the raw bookmark name as stored on this instance.
   *
   * <p>This is the unprocessed value, which may include the {@code l10n:} prefix used for
   * built-in/default bookmark entries. Callers that want a UI-friendly value should prefer {@link
   * #getVisibleName()}.
   *
   * @return the raw name string, as stored, without localization or normalization.
   */
  public String getName() {
    return name;
  }

  /**
   * Returns a display-friendly bookmark name.
   *
   * <p>If the raw name begins with {@code l10n:} (case-insensitive), this method resolves the name
   * through {@link NodeL10n#getBase()} using the key prefix {@code Bookmarks.Defaults.Name.} plus
   * the suffix after {@code l10n:}. Otherwise, it returns the raw name unchanged.
   *
   * <p>This method does not perform trimming or validation; it mirrors the stored data so that the
   * UI can render both user-defined and built-in entries predictably.
   *
   * @return the localized name when {@code l10n:} is used, otherwise the raw name.
   */
  public String getVisibleName() {
    if (name.toLowerCase().startsWith("l10n:"))
      return NodeL10n.getBase()
          .getString("Bookmarks.Defaults.Name." + name.substring("l10n:".length()));
    return name;
  }

  /**
   * Sets the raw bookmark name, applying the standard empty-name fallback.
   *
   * <p>If {@code s} is empty, this method substitutes the localized {@code Bookmark.noName} string
   * from {@link NodeL10n#getBase()}. Otherwise, the provided string is stored verbatim and may
   * later be interpreted as a localization reference if it starts with {@code l10n:}.
   *
   * <p>This method is protected to keep name initialization under subclass control; callers should
   * treat bookmarks as mutable model objects rather than stable identifiers.
   *
   * @param s the desired raw name; must be non-null, and an empty string selects the default name.
   */
  protected void setName(String s) {
    name = (!s.isEmpty() ? s : NodeL10n.getBase().getString("Bookmark.noName"));
  }

  /**
   * Compares this bookmark to another object for equality.
   *
   * <p>Two {@code Bookmark} instances are considered equal when they are both bookmarks and their
   * raw {@link #name} strings are equal. Subclasses do not contribute additional state to equality
   * in this base implementation.
   *
   * @param o the object to compare with this bookmark; may be {@code null}.
   * @return {@code true} when {@code o} is a bookmark with the same raw name.
   */
  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    if (o instanceof Bookmark b) {
      return b.name.equals(name);
    } else return false;
  }

  /**
   * Returns a hash code for this bookmark.
   *
   * <p>The hash code is derived solely from the raw {@link #name} string so that it is consistent
   * with {@link #equals(Object)}.
   *
   * @return the hash code of the raw name string.
   */
  @Override
  public int hashCode() {
    return name.hashCode();
  }

  /**
   * Returns a {@link SimpleFieldSet} representation of this bookmark.
   *
   * <p>Subclasses implement this method to serialize bookmark state into a stable, key/value
   * representation. The returned field set is typically used to persist bookmark configuration or
   * to transfer bookmark data through internal APIs.
   *
   * <p>The returned instance is owned by the caller; callers should not assume it will be updated
   * if the bookmark is mutated after this method returns.
   *
   * @return a field-set representation of this bookmark, suitable for persistence or transport.
   */
  public abstract SimpleFieldSet getSimpleFieldSet();
}
