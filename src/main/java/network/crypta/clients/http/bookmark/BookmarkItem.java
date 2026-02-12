package network.crypta.clients.http.bookmark;

import java.net.MalformedURLException;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.FSParseException;
import network.crypta.node.NodeClientCore;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A single persisted bookmark entry backed by a {@link FreenetURI}, with optional update tracking.
 *
 * <p>{@code BookmarkItem} represents the concrete, user-visible bookmark record used by the HTTP
 * bookmarks UI and the bookmark persistence layer. In addition to the inherited {@code name} from
 * {@link Bookmark}, it stores the target URI, a long and short description, and a small amount of
 * state used for UI behavior and notifications. When the bookmark points to a {@link USK}, the item
 * can mark itself as “updated” after an edition bump; this state is surfaced to the user via a
 * {@link UserAlert} registered with the owning {@link UserAlertManager}.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Persists to and restores from {@link SimpleFieldSet} using stable field names.
 *   <li>Supports inline localization tokens using the {@code "l10n:"} prefix for descriptions.
 *   <li>Tracks update state for USKs and exposes a per-item {@link UserAlert}.
 * </ul>
 *
 * <p><b>Thread-safety</b>: some mutating methods are {@code synchronized} and the update alert uses
 * synchronized access to the {@code updated} flag. Callers should treat instances as effectively
 * mutable and not inherently thread-safe unless they provide external synchronization.
 */
public final class BookmarkItem extends Bookmark {
  private static final Logger LOG = LoggerFactory.getLogger(BookmarkItem.class);

  /**
   * Stable identifier prefix used to tag bookmark items in serialized or display-oriented contexts.
   *
   * <p>This constant provides a durable string identifier that other components can use when they
   * need to distinguish bookmark item records from other bookmark-related structures (for example,
   * when persisting or displaying composite bookmark data).
   */
  public static final String BOOKMARK_PREFIX = "Bookmark";

  private static final String L10N_KEY_PREFIX = "BookmarkItem.";
  private static final String L10N_INLINE_PREFIX = "l10n:";
  private static final AtomicLong INSTANCE_COUNTER = new AtomicLong();

  private final BookmarkManager manager;
  private FreenetURI key;
  private volatile boolean updated;
  private boolean hasAnActivelink;
  private final BookmarkUpdatedUserAlert alert;
  private final UserAlertManager alerts;
  private final long instanceId = INSTANCE_COUNTER.incrementAndGet();

  /**
   * The persisted description value for this bookmark, possibly {@code null}.
   *
   * <p>If the value begins with {@code "l10n:"} (case-insensitive), {@link #getDescription()}
   * resolves it via {@link NodeL10n}. Callers should prefer the accessor to get the effective
   * user-facing text.
   */
  protected String desc;

  /**
   * The persisted short description value for this bookmark, possibly {@code null}.
   *
   * <p>If the value begins with {@code "l10n:"} (case-insensitive), {@link #getShortDescription()}
   * resolves it via {@link NodeL10n}. Callers should prefer the accessor to get the effective
   * user-facing text.
   */
  protected String shortDescription;

  /**
   * Creates a new bookmark item with the supplied fields and associated managers.
   *
   * <p>This constructor does not perform persistence. The created instance owns a per-item {@link
   * UserAlert} (available via {@link #getUserAlert()}) and will register/unregister it with the
   * provided {@link UserAlertManager} as the {@code updated} state changes.
   *
   * @param k the target URI for this bookmark; must be non-{@code null} and well-formed
   * @param n the display name for this bookmark; must be non-{@code null} and non-empty
   * @param d the long description text; may be {@code null} and may use {@code "l10n:"} indirection
   * @param s the short description text; may be {@code null} and may use {@code "l10n:"}
   *     indirection
   * @param hasAnActivelink {@code true} if the bookmark currently has an active link target
   * @param bm the owning bookmark manager responsible for persistence callbacks; must be non-{@code
   *     null}
   * @param uam the alert manager used to register the per-item {@link UserAlert}; must be
   *     non-{@code null} and associated with the same node context as {@code bm}
   */
  public BookmarkItem(
      FreenetURI k,
      String n,
      String d,
      String s,
      boolean hasAnActivelink,
      BookmarkManager bm,
      UserAlertManager uam) {
    key = k;
    this.name = n;
    this.desc = d;
    this.shortDescription = s;
    this.hasAnActivelink = hasAnActivelink;
    this.manager = bm;
    this.alerts = uam;
    alert = new BookmarkUpdatedUserAlert();
    assert (name != null);
    assert (key != null);
  }

  /**
   * Restores a bookmark item from a {@link SimpleFieldSet} as persisted by {@link
   * #getSimpleFieldSet()}.
   *
   * <p>The constructor reads the expected fields {@code Name}, {@code Description}, {@code
   * ShortDescription}, {@code hasAnActivelink}, {@code Updated}, and {@code URI}. Missing or empty
   * string fields fall back to safe defaults (empty descriptions and a localized placeholder name).
   * The {@code Updated} flag defaults to {@code false} for backward compatibility with older saved
   * bookmark databases that predate this field.
   *
   * <p>This constructor does not automatically register the update notification. If the restored
   * item is both a USK and marked updated, call {@link #registerUserAlert()} after construction to
   * register its {@link UserAlert} with the provided {@link UserAlertManager}.
   *
   * @param sfs the serialized field set containing bookmark item data; must be non-{@code null}
   * @param bm the owning bookmark manager responsible for persistence callbacks; must be non-{@code
   *     null}
   * @param uam the alert manager used to register the per-item {@link UserAlert}; must be
   *     non-{@code null} and associated with the same node context as {@code bm}
   * @throws FSParseException if the field set is missing required fields or contains invalid values
   * @throws MalformedURLException if the stored URI cannot be parsed into a {@link FreenetURI}
   */
  public BookmarkItem(SimpleFieldSet sfs, BookmarkManager bm, UserAlertManager uam)
      throws FSParseException, MalformedURLException {
    this.name = sfs.get("Name");
    if (name == null || name.isEmpty()) {
      name = NodeL10n.getBase().getString(L10N_KEY_PREFIX + "unnamedBookmark");
    }
    this.desc = sfs.get("Description");
    if (desc == null) desc = "";
    this.shortDescription = sfs.get("ShortDescription");
    if (shortDescription == null) shortDescription = "";
    this.hasAnActivelink = sfs.getBoolean("hasAnActivelink");
    // "Updated" was added in 2016-08-19, so we must assume it doesn't exist in previously saved
    // bookmark databases and provide a default to prevent getBoolean() from throwing.
    this.updated = sfs.getBoolean("Updated", false);
    this.key = new FreenetURI(sfs.get("URI"));
    this.manager = bm;
    this.alerts = uam;
    this.alert = new BookmarkUpdatedUserAlert();
  }

  private class BookmarkUpdatedUserAlert extends AbstractUserAlert {

    public BookmarkUpdatedUserAlert() {
      super(true, null, null, UserAlert.MINOR, false, new DismissOptions(null, true));
    }

    @Override
    public String getTitle() {
      return l10nWithName("bookmarkUpdatedTitle", name);
    }

    @Override
    public String getText() {
      return NodeL10n.getBase()
          .getString(
              L10N_KEY_PREFIX + "bookmarkUpdated",
              new String[] {"name", "edition"},
              new String[] {name, Long.toString(key.getSuggestedEdition())});
    }

    @Override
    public HTMLNode getHTMLText() {
      HTMLNode n = new HTMLNode("div");
      NodeL10n.getBase()
          .addL10nSubstitution(
              n,
              "BookmarkItem.bookmarkUpdatedWithLink",
              new String[] {"link", "name", "edition"},
              new HTMLNode[] {
                HTMLNode.link("/" + key),
                HTMLNode.text(name),
                HTMLNode.text(key.getSuggestedEdition())
              });
      return n;
    }

    @Override
    public boolean isValid() {
      synchronized (BookmarkItem.this) {
        return updated;
      }
    }

    @Override
    public void isValid(boolean validity) {
      if (validity) {
        return;
      }
      disableBookmark();
    }

    @Override
    public String dismissButtonText() {
      return NodeL10n.getBase().getString(L10N_KEY_PREFIX + "deleteBookmarkUpdateNotification");
    }

    @Override
    public void onDismiss() {
      disableBookmark();
      manager.storeBookmarks();
    }

    @Override
    public String getShortText() {
      return l10nWithName("bookmarkUpdatedShort", name);
    }

    @Override
    public boolean isEventNotification() {
      return true;
    }

    private String l10nWithName(String key, String nameValue) {
      return NodeL10n.getBase()
          .getString(L10N_KEY_PREFIX + key, new String[] {"name"}, new String[] {nameValue});
    }
  }

  private synchronized void disableBookmark() {
    updated = false;
    alerts.unregister(alert);
  }

  private synchronized void enableBookmark() {
    if (updated) {
      return;
    }
    assert key.isUSK();
    updated = true;
    alerts.register(alert);
  }

  /**
   * If this bookmark is marked as updated, registers a {@link UserAlert} which notifies the user.
   * You usually only need to call this function after having loaded a bookmark from disk using
   * {@link #BookmarkItem(SimpleFieldSet, BookmarkManager, UserAlertManager)}.
   */
  synchronized void registerUserAlert() {
    if (key.isUSK() && updated) alerts.register(alert);
  }

  /**
   * Returns the per-item {@link UserAlert} representing an update notification for this bookmark.
   *
   * <p>The returned alert object is owned by this {@code BookmarkItem} instance. It is registered
   * and unregistered with the {@link UserAlertManager} configured at construction time based on the
   * {@code updated} state and bookmark type (USK vs. non-USK).
   *
   * @return the non-{@code null} alert instance associated with this bookmark item
   */
  public UserAlert getUserAlert() {
    return alert;
  }

  /**
   * Returns the current bookmark key as a string.
   *
   * <p>This is the string form of the underlying {@link FreenetURI} and is suitable for storage or
   * display. It is equivalent to calling {@code getURI().toString()} but avoids exposing the URI
   * object itself.
   *
   * <p>This method is not synchronized; in concurrent contexts where the bookmark may be updated
   * while being read, callers should use {@link #getURI()} (which is synchronized) and then convert
   * to a string.
   *
   * @return a non-{@code null} string representation of the bookmark target URI
   */
  public String getKey() {
    return key.toString();
  }

  long instanceId() {
    return instanceId;
  }

  /**
   * Returns the current target {@link FreenetURI} for this bookmark item.
   *
   * <p>This method is synchronized to provide a consistent view of the underlying URI during
   * concurrent updates. If callers retain the returned reference, they should re-fetch via this
   * method if they require the latest value after {@link #update(FreenetURI, boolean, String,
   * String)} or {@link #setEdition(long, NodeClientCore)}.
   *
   * @return the current {@link FreenetURI} instance for this bookmark; never {@code null}
   */
  public synchronized FreenetURI getURI() {
    return key;
  }

  /**
   * Updates the bookmark’s URI and descriptive fields in-place.
   *
   * <p>This method replaces the stored URI, descriptions, and active-link flag. If the new URI is
   * not a USK, any existing update notification is disabled because edition tracking is only
   * meaningful for USKs. This method does not persist changes to disk; callers typically update the
   * in-memory object and then trigger persistence via the owning {@link BookmarkManager}.
   *
   * @param uri the new target URI to store for this bookmark; must be non-{@code null}
   * @param hasAnActivelink {@code true} if the bookmark should be treated as having an active link
   * @param description the new long description value to store; may be {@code null}
   * @param shortDescription the new short description value to store; may be {@code null}
   */
  public synchronized void update(
      FreenetURI uri, boolean hasAnActivelink, String description, String shortDescription) {
    this.key = uri;
    this.desc = description;
    this.shortDescription = shortDescription;
    this.hasAnActivelink = hasAnActivelink;
    if (!key.isUSK()) disableBookmark();
  }

  /**
   * Returns the key type string for the current bookmark URI.
   *
   * <p>This is a convenience wrapper for {@link FreenetURI#getKeyType()} and reflects the current
   * stored value returned by {@link #getURI()}.
   *
   * <p>The returned value is an identifier such as {@code "USK"} for updatable keys. The exact set
   * of possible key type strings depends on the URI implementation; callers should treat it as an
   * opaque identifier and avoid hard-coding behavior beyond well-known, explicitly supported types.
   *
   * @return the key type identifier for the current URI; never {@code null}
   */
  public synchronized String getKeyType() {
    return key.getKeyType();
  }

  @Override
  public String toString() {
    return this.name
        + "###"
        + (this.desc != null ? this.desc : "")
        + "###"
        + this.hasAnActivelink
        + "###"
        + this.key.toString();
  }

  /**
   * Updates the suggested edition for a USK bookmark and enables update notifications when needed.
   *
   * <p>If the current suggested edition is already greater than or equal to {@code ed}, this method
   * leaves the bookmark unchanged and returns {@code false}. Otherwise, it updates the stored
   * {@link FreenetURI} to use the provided suggested edition and enables the update notification
   * alert for the item.
   *
   * <p>This method is synchronized to serialize updates and to keep the {@code updated} flag and
   * alert registration consistent with the stored key.
   *
   * @param ed the new suggested edition to apply; must be greater than the current suggested
   *     edition
   * @param node the node context used for diagnostic logging; may be {@code null}
   * @return {@code true} if the edition was updated; {@code false} if {@code ed} was not newer
   */
  public synchronized boolean setEdition(long ed, NodeClientCore node) {
    if (key.getSuggestedEdition() >= ed) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Edition {} is too old, not updating {} (nodePresent={})", ed, key, node != null);
      }
      return false;
    }
    key = key.setSuggestedEdition(ed);
    enableBookmark();
    return true;
  }

  /**
   * Returns this bookmark’s key as a {@link USK}.
   *
   * <p>This is a convenience wrapper around {@link USK#create(FreenetURI)} for callers that need to
   * treat the bookmark target as an updatable key. Callers should ensure the current URI represents
   * a USK before calling; otherwise the conversion will fail.
   *
   * @return a {@link USK} instance created from the current bookmark URI
   * @throws MalformedURLException if the current URI cannot be represented as a {@link USK}
   */
  public USK getUSK() throws MalformedURLException {
    return USK.create(key);
  }

  @Override
  public int hashCode() {
    int hash = super.hashCode();
    hash = 31 * hash + this.key.setSuggestedEdition(0).hashCode();
    hash = 31 * hash + (this.hasAnActivelink ? 1 : 0);
    hash = 31 * hash + (this.desc != null ? this.desc.hashCode() : 0);
    return hash;
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o instanceof BookmarkItem b) {
      if (!super.equals(o)) {
        return false;
      }
      if (!b.key.equals(key)) {
        if ("USK".equals(b.key.getKeyType())) {
          if (!b.key.setSuggestedEdition(key.getSuggestedEdition()).equals(key)) {
            return false;
          }
        } else {
          return false;
        }
      }
      if (b.alerts != alerts) {
        return false;
      } // Belongs to a different node???
      if (b.hasAnActivelink != hasAnActivelink) {
        return false;
      }
      return Objects.equals(b.desc, desc);
    } else {
      return false;
    }
  }

  /**
   * Returns whether this bookmark is currently marked as updated.
   *
   * <p>The updated flag is used to decide whether the per-item {@link UserAlert} should be
   * considered valid and shown to the user. The flag is typically set via {@link #setEdition(long,
   * NodeClientCore)} for USKs and cleared when the user dismisses the notification or when the
   * bookmark no longer represents a USK.
   *
   * @return {@code true} if the bookmark is marked updated; {@code false} otherwise
   */
  public boolean hasUpdated() {
    return updated;
  }

  /**
   * Clears the updated flag for this bookmark without modifying the stored URI.
   *
   * <p>This method only updates the in-memory state. Callers that need to fully disable update
   * notifications should also ensure the corresponding {@link UserAlert} is unregistered (for
   * example, via user dismissal flows) and that persistence is triggered by the owning {@link
   * BookmarkManager} if appropriate.
   *
   * <p>If this item is a USK and the alert was previously registered, clearing the flag affects the
   * alert’s validity check but does not, by itself, force an immediate unregistering; the
   * surrounding alert lifecycle is managed by {@link BookmarkItem} and the {@link
   * UserAlertManager}.
   */
  public void clearUpdated() {
    this.updated = false;
  }

  /**
   * Returns whether this bookmark is currently treated as having an active link target.
   *
   * <p>This flag is persisted as {@code hasAnActivelink} and is typically used by the bookmarks UI
   * to decide how to render or enable the bookmark entry. The meaning of “active” is intentionally
   * coarse-grained: it is a stored UI/state hint rather than an on-demand validation of the target.
   *
   * @return {@code true} if the bookmark is marked as active; {@code false} otherwise
   */
  public boolean hasAnActivelink() {
    return hasAnActivelink;
  }

  /**
   * Returns the effective long description for this bookmark.
   *
   * <p>If the stored description value is {@code null}, this method returns an empty string. If the
   * stored value begins with {@code "l10n:"} (case-insensitive), the suffix is treated as a key and
   * resolved via {@link NodeL10n} under {@code "Bookmarks.Defaults.Description."}. Otherwise, the
   * stored description is returned as-is.
   *
   * @return the resolved long description text; never {@code null}
   */
  public String getDescription() {
    if (desc == null) return "";
    if (desc.toLowerCase(Locale.ROOT).startsWith(L10N_INLINE_PREFIX))
      return NodeL10n.getBase()
          .getString(
              "Bookmarks.Defaults.Description." + desc.substring(L10N_INLINE_PREFIX.length()));
    return desc;
  }

  /**
   * Returns the effective short description for this bookmark.
   *
   * <p>If the stored short description value is {@code null}, this method returns an empty string.
   * If the stored value begins with {@code "l10n:"} (case-insensitive), the suffix is treated as a
   * key and resolved via {@link NodeL10n} under {@code "Bookmarks.Defaults.ShortDescription."}.
   * Otherwise, the stored short description is returned as-is.
   *
   * @return the resolved short description text; never {@code null}
   */
  public String getShortDescription() {
    if (shortDescription == null) return "";
    if (shortDescription.toLowerCase(Locale.ROOT).startsWith(L10N_INLINE_PREFIX))
      return NodeL10n.getBase()
          .getString(
              "Bookmarks.Defaults.ShortDescription."
                  + shortDescription.substring(L10N_INLINE_PREFIX.length()));
    return shortDescription;
  }

  @Override
  public SimpleFieldSet getSimpleFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Name", name);
    sfs.putSingle("Description", desc);
    sfs.putSingle("ShortDescription", shortDescription);
    sfs.put("hasAnActivelink", hasAnActivelink);
    sfs.put("Updated", updated);
    sfs.putSingle("URI", key.toString());
    return sfs;
  }
}
