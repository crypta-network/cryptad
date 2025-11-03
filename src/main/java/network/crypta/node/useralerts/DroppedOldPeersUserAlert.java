package network.crypta.node.useralerts;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.PeerTooOldException;
import network.crypta.support.HTMLNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User alert summarizing peers that were dropped because they are too old to communicate with the
 * current node build.
 *
 * <p>This alert accumulates the display names of peers that were rejected due to an older
 * encryption protocol or build, along with the highest observed incompatible build number and its
 * build date. It renders human‑readable text and simple HTML content, and it can also be serialized
 * into an {@code FCP} {@link network.crypta.clients.fcp.FCPMessage} to notify external clients.
 *
 * <p>Typical usage: create an instance early in peer loading, call {@link #add(PeerTooOldException,
 * String)} for each incompatible peer, and, if non‑empty, register the alert with the system alert
 * service. The instance is mutable while peers are being processed; once registered and shown to
 * users it is usually treated as immutable.
 *
 * <ul>
 *   <li>Not thread‑safe: update it from a single thread.
 *   <li>Displays a filename where references to dropped peers are persisted by callers.
 *   <li>Emits a critical‑priority alert intended to be user‑dismissible.
 * </ul>
 */
public class DroppedOldPeersUserAlert implements UserAlert {
  private static final Logger LOG = LoggerFactory.getLogger(DroppedOldPeersUserAlert.class);

  private static final String KEY_COUNT = "count";
  private static final String KEY_BUILD_NUMBER = "buildNumber";
  private static final String KEY_BUILD_DATE = "buildDate";

  private final List<String> droppedOldPeers;
  private int droppedOldPeersBuild;
  private Date droppedOldPeersDate;
  private final File peersBrokenFile;
  private final long creationTime;

  /**
   * Creates a new alert accumulator for peers dropped due to being too old.
   *
   * <p>The provided file is referenced in the generated text so that users know where the list of
   * dropped peers has been saved by the caller. This constructor does not read from or write to the
   * file; it only stores the path for inclusion in the alert text.
   *
   * @param droppedPeersFile path to a human‑readable list of dropped peers; must be non‑null and
   *     point to a file under a directory that exists.
   */
  public DroppedOldPeersUserAlert(File droppedPeersFile) {
    this.droppedOldPeers = new ArrayList<>();
    this.peersBrokenFile = droppedPeersFile;
    creationTime = System.currentTimeMillis();
    this.droppedOldPeersBuild = 0;
    this.droppedOldPeersDate = new Date();
  }

  /**
   * Records a peer rejected for being too old and updates summary metadata.
   *
   * <p>When {@code name} is {@code null}, the peer is recorded as {@code (unknown name)}; otherwise
   * the name is stored quoted to make UI rendering unambiguous. The alert tracks the maximum build
   * number observed across all adds and uses the corresponding build date for titles.
   *
   * <p>This method logs an error‑level summary about the rejection. It does not throw.
   *
   * @param e details about the version mismatch including the other node's build number and date;
   *     must be non‑null.
   * @param name display name of the peer, or {@code null} when unknown; empty strings are allowed
   *     and will be quoted.
   */
  public void add(PeerTooOldException e, String name) {
    // May or may not have a name...
    if (name == null) {
      name = "(unknown name)";
    } else {
      name = "\"" + name + "\"";
    }
    droppedOldPeers.add(name);
    if (e.buildNumber > droppedOldPeersBuild) {
      droppedOldPeersBuild = e.buildNumber;
      droppedOldPeersDate = e.buildDate;
    }
    String shortError = getLogWarning(e);
    LOG.error(shortError);
  }

  /**
   * Reports whether no peers have been recorded yet.
   *
   * @return {@code true} when {@link #add(PeerTooOldException, String)} has not been called, or no
   *     entries were retained; {@code false} otherwise.
   */
  public boolean isEmpty() {
    return droppedOldPeers.isEmpty();
  }

  /** {@inheritDoc} */
  @Override
  public boolean userCanDismiss() {
    return true;
  }

  /**
   * Builds the localized introductory paragraph for the long text body.
   *
   * @return a localized string that summarizes the count, build information, and file path.
   */
  private String getErrorIntro() {
    String[] keys = new String[] {KEY_COUNT, KEY_BUILD_NUMBER, KEY_BUILD_DATE, "filename"};
    String[] values =
        new String[] {
          "" + droppedOldPeers.size(),
          "" + droppedOldPeersBuild,
          droppedOldPeersDate.toString(),
          peersBrokenFile.toString()
        };
    return l10n("droppingOldFriendFull", keys, values);
  }

  /**
   * Returns a localized, concise title summarizing the situation.
   *
   * <p>The title includes the number of dropped peers and references the build date associated with
   * the highest observed incompatible build number.
   *
   * @return a short, single‑line title intended for alert headers and feeds.
   */
  @Override
  public String getTitle() {
    String[] keys = new String[] {KEY_COUNT, KEY_BUILD_NUMBER, KEY_BUILD_DATE, "filename"};
    String[] values =
        new String[] {
          "" + droppedOldPeers.size(),
          "" + droppedOldPeersBuild,
          droppedOldPeersDate.toString(),
          peersBrokenFile.toString()
        };
    return l10n("droppingOldFriendTitle", keys, values);
  }

  /**
   * Returns a full, multi‑line textual description of the alert.
   *
   * <p>The first line contains a localized summary, followed by a label and then one line per peer
   * name in the order they were added. Unknown names are rendered as {@code (unknown name)} and
   * known names are quoted.
   *
   * <pre>{@code
   * var alert = new DroppedOldPeersUserAlert(file);
   * alert.add(exc1, "Alice");
   * alert.add(exc2, null);
   * String body = alert.getText();
   * }</pre>
   *
   * @return a newly constructed string; callers own the returned instance and may cache it.
   */
  @Override
  public String getText() {
    StringBuilder longErrorText = new StringBuilder();
    longErrorText.append(getErrorIntro());
    longErrorText.append('\n');
    longErrorText.append(
        NodeL10n.getBase().getString("DroppedOldPeersUserAlert.droppingOldFriendList"));
    longErrorText.append('\n');
    for (String name : droppedOldPeers) {
      longErrorText.append(name);
      longErrorText.append('\n');
    }
    longErrorText.setLength(longErrorText.length() - 1);
    return longErrorText.toString();
  }

  /**
   * Returns a minimal HTML representation of the alert message.
   *
   * <p>The root contains two paragraphs—an introductory sentence and a list label—followed by an
   * unordered list with one {@code <li>} per peer name. A new tree is created on each call.
   *
   * @return an {@code HTMLNode} tree describing the message; callers may freely modify it.
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode html = new HTMLNode("#");
    html.addChild("p", getErrorIntro());
    html.addChild(
        "p", NodeL10n.getBase().getString("DroppedOldPeersUserAlert.droppingOldFriendList"));
    HTMLNode list = html.addChild("ul");
    for (String name : droppedOldPeers) {
      list.addChild("li", name);
    }
    return html;
  }

  /**
   * Returns a concise string suitable for compact UI surfaces.
   *
   * @return the same value as {@link #getTitle()}.
   */
  @Override
  public String getShortText() {
    return getTitle();
  }

  /** {@inheritDoc} */
  @Override
  public short getPriorityClass() {
    return CRITICAL_ERROR;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isValid() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation ignores the requested validity flag. The alert remains valid until the
   * owning alert service unregisters it (typically when the user dismisses the message).
   *
   * @param validity requested validity flag; ignored by this implementation.
   */
  @Override
  public void isValid(boolean validity) {
    // Ignore, will be unregistered on dismiss.
  }

  /** {@inheritDoc} */
  @Override
  public String dismissButtonText() {
    return NodeL10n.getBase().getString("UserAlert.hide");
  }

  /** {@inheritDoc} */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public void onDismiss() {
    // Do nothing.
  }

  /**
   * Returns a stable anchor identifier for deep‑linking and UI selection.
   *
   * @return a short, ASCII identifier that uniquely identifies this alert type.
   */
  @Override
  public String anchor() {
    return "droppedPeersUserAlert";
  }

  /** {@inheritDoc} */
  @Override
  public boolean isEventNotification() {
    return false;
  }

  /**
   * Serializes the alert into an FCP feed message.
   *
   * <p>The returned message contains the title, short text, full text bytes length, priority class,
   * and the creation time as the updated time. The message does not include attachments.
   *
   * @return a new {@code Feed} message conveying the alert; safe to send to external clients.
   */
  @Override
  public FCPMessage getFCPMessage() {
    return new FeedMessage(
        getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
  }

  /**
   * Returns the logical update time of this alert.
   *
   * <p>This implementation uses the construction time so the value remains stable for the lifetime
   * of the instance.
   *
   * @return milliseconds since the epoch representing when the alert was created.
   */
  @Override
  public long getUpdatedTime() {
    return creationTime;
  }

  private static String l10n(String key, String[] pattern, String[] value) {
    return NodeL10n.getBase().getString("DroppedOldPeersUserAlert." + key, pattern, value);
  }

  private String getLogWarning(PeerTooOldException e) {
    String[] keys = new String[] {KEY_COUNT, KEY_BUILD_NUMBER, KEY_BUILD_DATE, "port"};
    String[] values =
        new String[] {
          Integer.toString(droppedOldPeers.size()),
          Integer.toString(e.buildNumber),
          e.buildDate.toString(),
          peersBrokenFile.getPath()
        };
    return l10n("droppingOldFriendTitle", keys, values);
  }
}
