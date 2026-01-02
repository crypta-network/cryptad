package network.crypta.node.useralerts;

import java.lang.ref.WeakReference;
import java.text.DateFormat;
import java.util.Date;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.TextFeedMessage;
import network.crypta.io.comm.PeerContext;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;

/**
 * User alert representing a Node-to-Node Text Message (N2NTM).
 *
 * <p>This alert encapsulates the text payload and a set of timestamps produced along the delivery
 * path (composed, sent, and received). It also carries lightweight identity information about the
 * source darknet peer and a reference to the originating {@link PeerContext}. The alert exposes
 * multiple readouts tailored to different front-ends: a localized plain-text title and body, a
 * concise short text for summaries, an {@link HTMLNode} fragment for HTML renderers, and an {@link
 * FCPMessage} view for programmatic consumption via FCP.
 *
 * <p>Instances are mostly immutable after construction. The only mutable parts are the cached
 * {@code sourceNodeName} and {@code sourcePeer} strings, which may be refreshed opportunistically
 * in {@link #isValid()} if the peer reference is still alive. No external synchronization is
 * performed; typical usage confines instances to a single UI thread or an alert manager that
 * serializes access.
 *
 * <p>Typical flow:
 *
 * <ol>
 *   <li>Create the alert when a text message is received from a darknet peer.
 *   <li>Present {@link #getTitle()} and either {@link #getText()} or {@link #getHTMLText()} to the
 *       user interface.
 *   <li>On dismissal, {@link #onDismiss()} will remove the backing extra peer data file referenced
 *       by {@link #getFileNumber()} when the peer is still reachable.
 * </ol>
 *
 * @see AbstractUserAlert
 * @see NodeToNodeMessageUserAlert
 * @see DarknetPeerNode
 */
public class N2NTMUserAlert extends AbstractUserAlert implements NodeToNodeMessageUserAlert {
  private static final String L10N_PREFIX = "N2NTMUserAlert.";
  private final WeakReference<PeerContext> peerRef;
  private final String messageText;
  private final int fileNumber;
  private final long composedTime;
  private final long sentTime;
  private final long receivedTime;
  private final long msgid;
  private String sourceNodeName;
  private String sourcePeer;

  /**
   * Creates a new alert for a Node-to-Node text message with an explicit message identifier.
   *
   * <p>All timestamps are expressed as milliseconds since the Unix epoch. The {@code fileNumber}
   * refers to a peer-specific extra data file used for persistence and cleanup on dismissal. The
   * supplied {@code sourcePeerNode} is stored as a {@link WeakReference} to avoid retaining peers
   * beyond their lifetime.
   *
   * <pre>{@code
   * // Example: construct an alert from an inbound message
   * var alert = new N2NTMUserAlert(peer, text, fileNo, tComposed, tSent, tReceived, msgId);
   * }</pre>
   *
   * @param sourcePeerNode non-null darknet peer that originated the message; used for display and
   *     dismissal logic when still reachable
   * @param message full message text; may contain newlines that will be preserved in HTML output
   * @param fileNumber identifier of the extra peer data file to delete on dismissal; non-negative
   *     values are expected by the caller
   * @param composedTime time the sender composed the message, in epoch milliseconds; may predate
   *     network transmission
   * @param sentTime time the sender sent the message, in epoch milliseconds; used for display only
   * @param receivedTime local receipt time in epoch milliseconds; also used as {@link
   *     #getUpdatedTime()} for alert freshness
   * @param msgid opaque message identifier supplied by the sender or transport; negative values
   *     indicate no identifier was provided
   */
  public N2NTMUserAlert(
      DarknetPeerNode sourcePeerNode,
      String message,
      int fileNumber,
      long composedTime,
      long sentTime,
      long receivedTime,
      long msgid) {
    super(
        true, null, null, UserAlert.MINOR, true, new AbstractUserAlert.DismissOptions(null, true));
    this.messageText = message;
    this.fileNumber = fileNumber;
    this.composedTime = composedTime;
    this.sentTime = sentTime;
    this.receivedTime = receivedTime;
    this.peerRef = sourcePeerNode.getWeakRef();
    this.sourceNodeName = sourcePeerNode.getName();
    this.sourcePeer = sourcePeerNode.getPeer().toString();
    this.msgid = msgid;
  }

  /**
   * Creates a new alert for a Node-to-Node text message without an explicit message identifier.
   *
   * <p>This constructor is equivalent to the full constructor with {@code msgid} set to {@code -1}.
   * All other parameters have the same meaning and units.
   *
   * @param sourcePeerNode non-null darknet peer that originated the message; used for display and
   *     dismissal logic when still reachable
   * @param message full message text; may contain newlines that will be preserved in HTML output
   * @param fileNumber identifier of the extra peer data file to delete on dismissal; non-negative
   *     values are expected by the caller
   * @param composedTime time the sender composed the message, in epoch milliseconds; may predate
   *     network transmission
   * @param sentTime time the sender sent the message, in epoch milliseconds; used for display only
   * @param receivedTime local receipt time in epoch milliseconds; also used as {@link
   *     #getUpdatedTime()} for alert freshness
   */
  public N2NTMUserAlert(
      DarknetPeerNode sourcePeerNode,
      String message,
      int fileNumber,
      long composedTime,
      long sentTime,
      long receivedTime) {
    this(sourcePeerNode, message, fileNumber, composedTime, sentTime, receivedTime, -1);
  }

  /**
   * Returns a localized, human-readable title summarizing the message source and index.
   *
   * <p>The title typically includes the peer-provided display name and a textual representation of
   * the peer identity, combined with the {@link #getFileNumber()} that indexes the stored payload.
   *
   * @return a short title suitable for notification headers; never {@code null}
   */
  @Override
  public String getTitle() {
    return l10n(
        "title",
        new String[] {"number", "peername", "peer"},
        new String[] {Integer.toString(fileNumber), sourceNodeName, sourcePeer});
  }

  /**
   * Returns a localized text body that includes metadata (from/sent/received times) followed by the
   * raw message text.
   *
   * <p>Date values are formatted with the environment {@link DateFormat} in the current locale.
   * Newlines embedded in the original message are preserved in the returned string.
   *
   * @return the full plain-text message body including a localized header; never {@code null}
   */
  @Override
  public String getText() {
    return l10n(
            "header",
            new String[] {"from", "composed", "sent", "received"},
            new String[] {
              sourceNodeName,
              DateFormat.getInstance().format(new Date(composedTime)),
              DateFormat.getInstance().format(new Date(sentTime)),
              DateFormat.getInstance().format(new Date(receivedTime))
            })
        + ": "
        + messageText;
  }

  /**
   * Returns a brief, localized summary string appropriate for compact lists and notifications.
   *
   * @return a concise description containing the peer name; never {@code null}
   */
  @Override
  public String getShortText() {
    return NodeL10n.getBase().getString(L10N_PREFIX + "headerShort", "from", sourceNodeName);
  }

  /**
   * Produces an {@link HTMLNode} fragment representing the alert with readable formatting.
   *
   * <p>The generated structure contains a paragraph with a localized header and a line-broken
   * representation of {@link #getMessageText()}. When the originating peer is still available, a
   * "reply" link is appended that leads to the N2NTM reply endpoint for that peer.
   *
   * @return an HTML fragment suitable for embedding in UI renderers; never {@code null}
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode alertNode = new HTMLNode("div");
    alertNode.addChild(
        "p",
        l10n(
            "header",
            new String[] {"from", "composed", "sent", "received"},
            new String[] {
              sourceNodeName,
              DateFormat.getInstance().format(new Date(composedTime)),
              DateFormat.getInstance().format(new Date(sentTime)),
              DateFormat.getInstance().format(new Date(receivedTime))
            }));
    String[] lines = messageText.split("\n");
    for (int i = 0, c = lines.length; i < c; i++) {
      alertNode.addChild("#", lines[i]);
      if (i != lines.length - 1) alertNode.addChild("br");
    }

    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null)
      alertNode
          .addChild("p")
          .addChild("a", "href", "/send_n2ntm/?peernode_hashcode=" + pn.hashCode(), l10n("reply"));
    return alertNode;
  }

  /**
   * Returns the localized label to use on the dismiss button for this alert.
   *
   * @return a short action string such as "delete"; never {@code null}
   */
  @Override
  public String dismissButtonText() {
    return l10n("delete");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  private String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, patterns, values);
  }

  // No 3-arg l10n helper: the only usage is the fixed pattern in getShortText()

  /**
   * Handles alert dismissal by removing the associated extra peer data file when the source peer is
   * still available.
   *
   * <p>If the peer has already been collected or disconnected, the operation becomes a no-op. No
   * exceptions are thrown by this method.
   */
  @Override
  public void onDismiss() {
    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null) pn.deleteExtraPeerDataFile(fileNumber);
  }

  /**
   * Returns an FCP representation of this alert for consumption by external clients.
   *
   * <p>The returned {@link TextFeedMessage} mirrors the data shown in the UI: title, short text,
   * full text, priority, update time, peer name, timestamps, and the raw message body.
   *
   * @return a non-null {@link FCPMessage} describing the alert contents
   */
  @Override
  public FCPMessage getFCPMessage() {
    return new TextFeedMessage(
        getTitle(),
        getShortText(),
        getText(),
        getPriorityClass(),
        getUpdatedTime(),
        sourceNodeName,
        composedTime,
        sentTime,
        receivedTime,
        messageText);
  }

  /**
   * Returns the timestamp that should be considered the alert's "last updated" time.
   *
   * <p>For N2NTM alerts this is the local receipt time, in milliseconds since the Unix epoch.
   *
   * @return the receipt time in epoch milliseconds
   */
  @Override
  public long getUpdatedTime() {
    return receivedTime;
  }

  /**
   * Returns the raw message text exactly as received.
   *
   * <p>Newlines are preserved and are rendered as line breaks by {@link #getHTMLText()}.
   *
   * @return the unmodified message body; never {@code null}
   */
  public String getMessageText() {
    return messageText;
  }

  /**
   * Returns the identifier of the extra peer data file backing this message.
   *
   * <p>The number is used by {@link #onDismiss()} to remove the stored payload when appropriate.
   *
   * @return a non-negative file number assigned by the caller
   */
  public int getFileNumber() {
    return fileNumber;
  }

  /**
   * Returns the time the sender composed the message, expressed in epoch milliseconds.
   *
   * @return sender-side composition time in milliseconds since the Unix epoch
   */
  public long getComposedTime() {
    return composedTime;
  }

  /**
   * Returns the time the sender transmitted the message, expressed in epoch milliseconds.
   *
   * @return sender-side transmission time in milliseconds since the Unix epoch
   */
  public long getSentTime() {
    return sentTime;
  }

  /**
   * Returns the opaque message identifier provided by the sender or transport.
   *
   * <p>A negative value indicates that no identifier was supplied.
   *
   * @return message identifier, or a negative value when missing
   */
  public long getMsgid() {
    return msgid;
  }

  /**
   * Indicates whether the alert remains valid for display, and refreshes cached peer display data
   * when possible.
   *
   * <p>This implementation always returns {@code true}. When the peer reference is still alive, the
   * cached {@code sourceNodeName} and {@code sourcePeer} fields are updated to reflect the latest
   * values provided by the peer.
   *
   * @return {@code true} always, after refreshing cached peer strings when available
   */
  @Override
  public boolean isValid() {
    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null) {
      sourceNodeName = pn.getName();
      sourcePeer = pn.getPeer().toString();
    }
    return true;
  }
}
