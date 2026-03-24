package network.crypta.runtime.alerts;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.N2NFeedMessageParams;
import network.crypta.clients.fcp.URIFeedMessage;
import network.crypta.io.comm.PeerContext;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;

/**
 * User alert representing a download feed entry advertised by a direct peer.
 *
 * <p>This alert surfaces a file announcement received via the node-to-node download feed. It holds
 * the target {@link FreenetURI}, an optional human-readable description, and basic timing
 * information (when the announcement was composed, sent, and received). The alert content can be
 * consumed as plain text, short text, or lightweight HTML using {@link #getText()}, {@link
 * #getShortText()}, and {@link #getHTMLText()} respectively. A localized, concise title is provided
 * by {@link #getTitle()} and is suitable for lists and notifications.
 *
 * <p>Instances are largely immutable once created; the only mutable aspect is the cached {@code
 * sourceNodeName}, which may be refreshed from the backing peer reference during {@link
 * #isValid()}. The class does not perform I/O besides the optional cleanup performed by {@link
 * #onDismiss()}, which asks the source peer to remove temporary metadata associated with the alert.
 *
 * <p>Thread-safety: this type does not synchronize access. Typical usage constructs the alert on a
 * scheduler thread, then reads its data on UI or client threads. Callers should apply their own
 * synchronization if they share an instance across threads.
 *
 * <ul>
 *   <li>Title and text are localized via {@link NodeL10n} using resource keys scoped to this class.
 *   <li>HTML output is minimal and safe for embedding in simple views; it deliberately avoids
 *       arbitrary markup beyond line breaks and a link to the URI.
 *   <li>Conversion to FCP is provided by {@link #getFCPMessage()} using {@link URIFeedMessage} for
 *       downstream clients.
 * </ul>
 *
 * @see URIFeedMessage
 * @see NodeToNodeMessageUserAlert
 */
public class DownloadFeedUserAlert extends AbstractUserAlert implements NodeToNodeMessageUserAlert {
  private final WeakReference<PeerContext> peerRef;
  private final FreenetURI uri;
  private final int fileNumber;
  private final String description;
  private final long composed;
  private final long sent;
  private final long received;
  private String sourceNodeName;

  /**
   * Creates a new alert for a file announcement received from a direct peer.
   *
   * <p>The supplied peer is held via a {@link WeakReference} to avoid extending its lifetime. The
   * {@code fileNumber} identifies peer-scoped temporary metadata that can be deleted on dismissal.
   * Time fields are forwarded as-is to clients; this class does not interpret their units.
   *
   * @param alertContext bundled peer, file number, and timing metadata for this alert
   * @param description optional human-readable description; may be {@code null} or empty;
   *     multi-line values are split on {@code \n} when rendered as HTML
   * @param uri the target content address to present to the user; must not be {@code null}; the
   *     instance is not modified
   */
  public DownloadFeedUserAlert(
      NodeToNodeAlertContext alertContext, String description, FreenetURI uri) {
    super(true, null, null, UserAlert.MINOR, true, new DismissOptions(null, true));
    DarknetPeerNode sourcePeerNode = alertContext.sourcePeerNode();
    this.description = description;
    this.uri = uri;
    this.fileNumber = alertContext.fileNumber();
    this.composed = alertContext.composedTime();
    this.sent = alertContext.sentTime();
    this.received = alertContext.receivedTime();
    this.peerRef = sourcePeerNode.getWeakRef();
    this.sourceNodeName = sourcePeerNode.getName();
  }

  /**
   * Returns a localized, human-readable title summarizing the announcement source.
   *
   * <p>The title interpolates the peer name into a localized resource string. It is intended for
   * compact UIs such as notification lists where a short, readable label is preferred over the full
   * text body. The value is computed on each call rather than cached, so recent name changes can be
   * reflected after {@link #isValid()} refreshes the peer name.
   *
   * @return a non-{@code null} localized title including the source peer name; suitable for short
   *     labels and summaries
   */
  @Override
  public String getTitle() {
    return l10nTitleFrom(sourceNodeName);
  }

  /**
   * Returns a plain-text body describing the file announcement.
   *
   * <p>The body includes the URI on the first line prefixed with a localized label. When a
   * description is available and not empty, it is appended on the same line separated by a single
   * space. Newlines are included only where shown in the returned string and are not
   * platform-normalized beyond the single trailing line break after the URI.
   *
   * @return a non-{@code null} plain-text representation of the alert, including the URI and, when
   *     provided, the description
   */
  @Override
  public String getText() {
    StringBuilder sb = new StringBuilder();
    sb.append(l10n("fileURI")).append(" ").append(uri).append("\n");
    if (description != null && !description.isEmpty())
      sb.append(l10n("fileDescription")).append(" ").append(description);
    return sb.toString();
  }

  /**
   * Returns a compact textual summary equivalent to {@link #getTitle()}.
   *
   * <p>This method is intended for clients that expect a short message body. It does not duplicate
   * or reformat the longer text returned by {@link #getText()}.
   *
   * @return the same value as {@link #getTitle()}, never {@code null}
   */
  @Override
  public String getShortText() {
    return getTitle();
  }

  /**
   * Builds a minimal HTML representation of the alert content.
   *
   * <p>The returned node is a {@code <div>} containing a hyperlink to the URI using its short
   * string form. If a description is present, it is added below the link with line breaks between
   * original description lines. The structure is intentionally simple and suitable for embedding in
   * basic HTML views.
   *
   * @return a non-{@code null} {@link HTMLNode} tree rooted at a {@code div} with a link and
   *     optional description
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode alertNode = new HTMLNode("div");
    alertNode.addChild("a", "href", "/" + uri).addChild("#", uri.toShortString());
    if (description != null && !description.isEmpty()) {
      String[] lines = splitLines(description);
      alertNode.addChild("br");
      alertNode.addChild("br");
      alertNode.addChild("#", l10n("fileDescription"));
      alertNode.addChild("br");
      for (int i = 0; i < lines.length; i++) {
        alertNode.addChild("#", lines[i]);
        if (i != lines.length - 1) alertNode.addChild("br");
      }
    }
    return alertNode;
  }

  /**
   * Returns the localized label for the dismissal action.
   *
   * <p>The value originates from {@link NodeL10n} and is intended to be shown on a button or action
   * link that removes this alert from the user interface.
   *
   * @return a non-{@code null} localized dismissal label appropriate for UI controls
   */
  @Override
  public String dismissButtonText() {
    return l10n("delete");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("DownloadFeedUserAlert." + key);
  }

  private static String[] splitLines(String text) {
    ArrayList<String> lines = new ArrayList<>();
    int start = 0;
    int idx;
    while ((idx = text.indexOf('\n', start)) >= 0) {
      lines.add(text.substring(start, idx));
      start = idx + 1;
    }
    lines.add(text.substring(start));
    while (!lines.isEmpty() && lines.get(lines.size() - 1).isEmpty()) {
      lines.remove(lines.size() - 1);
    }
    return lines.toArray(new String[0]);
  }

  /**
   * Resolve the localized title using the ${from} placeholder for the source node name.
   *
   * <p>This avoids a generic helper with constant parameters (key="title", pattern="from").
   */
  private String l10nTitleFrom(String value) {
    return NodeL10n.getBase().getString("DownloadFeedUserAlert.title", "from", value);
  }

  /**
   * Handles alert dismissal by requesting peer-side cleanup when possible.
   *
   * <p>If the originating peer is still reachable through the weak reference, this method asks it
   * to delete any extra peer data associated with {@code fileNumber}. The call is best-effort and
   * silently does nothing when the peer is no longer available.
   */
  @Override
  public void onDismiss() {
    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null) pn.deleteExtraPeerDataFile(fileNumber);
  }

  /**
   * Converts this alert into an FCP message for clients.
   *
   * <p>The returned {@link URIFeedMessage} includes the localized title, short and long text,
   * priority class, update time, peer name, the provided timestamps, target URI, and description.
   * No additional transformation is applied beyond field mapping.
   *
   * @return a non-{@code null} {@link FCPMessage} conveying this alert to FCP consumers
   */
  @Override
  public FCPMessage getFCPMessage() {
    N2NFeedMessageParams params =
        new N2NFeedMessageParams(
            getTitle(),
            getShortText(),
            getText(),
            getPriorityClass(),
            getUpdatedTime(),
            sourceNodeName,
            composed,
            sent,
            received);
    return new URIFeedMessage(params, uri, description);
  }

  /**
   * Refreshes cached peer information and indicates the alert remains displayable.
   *
   * <p>If the peer reference is still live, the stored {@code sourceNodeName} is updated so future
   * titles reflect any name changes. No further validation is performed, and the method always
   * returns {@code true} so callers can continue to show the alert until explicitly dismissed.
   *
   * @return {@code true} to signal that the alert is still valid for display
   */
  @Override
  public boolean isValid() {
    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null) sourceNodeName = pn.getName();
    return true;
  }
}
