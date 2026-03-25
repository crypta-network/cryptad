package network.crypta.runtime.alerts;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import network.crypta.clients.fcp.BookmarkFeed;
import network.crypta.clients.fcp.N2NFeedMessageParams;
import network.crypta.io.comm.PeerContext;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;

/**
 * User alert that conveys a bookmark suggestion received from a peer via a node-to-node message.
 * The alert presents both a human-readable summary and a structured payload suitable for
 * programmatic consumption (FCP {@link network.crypta.clients.fcp.BookmarkFeed}).
 *
 * <p>Instances are created when a remote peer shares a bookmark entry, typically containing a name,
 * an optional description, and a {@link FreenetURI}. The alert renders a short title, a plain-text
 * body, and an HTML fragment that includes links to add the bookmark and to open the referenced
 * URI. Dismissal cleans up any temporary per-peer file associated with the alert.
 *
 * <p>Lifecycle and mutability: all constructor-provided fields are immutable. The alert maintains a
 * weak reference to the originating peer to avoid retaining node instances longer than necessary.
 * The visible source node name may be refreshed on calls to {@link #isValid()} if the peer is still
 * reachable. Aside from that cosmetic update, the alert content is stable and suitable for
 * concurrent reads by UI and transport layers.
 *
 * <ul>
 *   <li>Renders localized text using {@link NodeL10n} keys scoped to this alert.
 *   <li>Generates an HTML node tree for rich presentation, including bookmark actions.
 *   <li>Exposes an FCP representation via {@link #getFCPMessage()} for client protocols.
 * </ul>
 *
 * <pre>{@code
 * // Example: build and render the alert
 * var context = new NodeToNodeAlertContext(peer, fileNo, composed, sent, received);
 * var alert = new BookmarkFeedUserAlert(context, name, desc, true, uri);
 * HTMLNode view = alert.getHTMLText();
 * BookmarkFeed fcp = alert.getFCPMessage();
 * }</pre>
 *
 * @see AbstractUserAlert
 * @see NodeToNodeMessageUserAlert
 * @see FreenetURI
 * @see HTMLNode
 */
public class BookmarkFeedUserAlert extends AbstractUserAlert implements NodeToNodeMessageUserAlert {
  private final WeakReference<PeerContext> peerRef;
  private final FreenetURI uri;
  private final int fileNumber;
  private final String name;
  private final String description;
  private final boolean hasAnActivelink;
  private final long composed;
  private final long sent;
  private final long received;
  private String sourceNodeName;

  /**
   * Creates a new alert representing a bookmark suggestion received from a darknet peer. The alert
   * content combines a title, a plain-text message, and an HTML view while also retaining metadata
   * about when the item was composed, sent, and received.
   *
   * <p>All arguments are stored verbatim. The peer is kept via a {@link WeakReference} to avoid
   * strong ownership; the alert may still render correctly even if the peer object is later
   * collected. Times are expressed as epoch milliseconds as provided by the caller.
   *
   * @param alertContext bundled peer, file number, and timing metadata for this alert; the peer is
   *     held weakly to avoid leaks and may be {@code null} by the time the alert is rendered
   * @param name the human-readable bookmark name to display; should be concise and safe for UI
   *     titles; must not be {@code null}
   * @param description optional longer description text; may be {@code null} or empty; newline
   *     characters are preserved and rendered as line breaks
   * @param hasAnActivelink whether an explicit “add bookmark” action should be presented in the
   *     HTML rendering; influences the presence of the actionable link parameter
   * @param uri the {@link FreenetURI} of the bookmark target; must be a valid, fully-formed URI
   *     string understood by clients
   */
  public BookmarkFeedUserAlert(
      NodeToNodeAlertContext alertContext,
      String name,
      String description,
      boolean hasAnActivelink,
      FreenetURI uri) {
    super(
        true, null, null, UserAlert.MINOR, true, new AbstractUserAlert.DismissOptions(null, true));
    DarknetPeerNode sourcePeerNode = alertContext.sourcePeerNode();
    this.name = name;
    this.description = description;
    this.uri = uri;
    this.fileNumber = alertContext.fileNumber();
    this.hasAnActivelink = hasAnActivelink;
    this.composed = alertContext.composedTime();
    this.sent = alertContext.sentTime();
    this.received = alertContext.receivedTime();
    this.peerRef = sourcePeerNode.getWeakRef();
    this.sourceNodeName = sourcePeerNode.getName();
  }

  /**
   * Returns the localized title of this alert, including the name of the originating peer when
   * available. The method performs a lightweight localization lookup and formats a short phrase
   * optimized for list, tray, or toast-style presentations. The value intentionally mirrors {@link
   * #getShortText()} to preserve consistency across compact contexts and allows callers to render a
   * single-line summary without inspecting the full body or HTML content. The result does not
   * mutate internal state and may be called repeatedly.
   *
   * @return a short, localized title suitable for compact UI elements; never {@code null} and safe
   *     for immediate display.
   */
  @Override
  public String getTitle() {
    return l10nTitleFrom(sourceNodeName);
  }

  /**
   * Produces a multi-line, plain-text description of the bookmark suggestion. The text includes the
   * peer’s display name, the bookmark URI, and the optional description when provided. Newlines in
   * the description are preserved to keep author-intended formatting. This output is
   * audience-focused and primarily intended for display; consumers that need structured data should
   * prefer {@link #getFCPMessage()} instead of parsing this text. The method does not alter the
   * object state and can be called multiple times without side effects.
   *
   * @return a human-readable, plain-text body with stable keys and values; never {@code null},
   *     though the description section may be omitted when empty.
   */
  @Override
  public String getText() {
    StringBuilder sb = new StringBuilder();
    sb.append(l10n("peerName")).append(" ").append(name).append("\n");
    sb.append(l10n("bookmarkURI")).append(" ").append(uri).append("\n");
    if (description != null && !description.isEmpty())
      sb.append(l10n("bookmarkDescription")).append(" ").append(description);
    return sb.toString();
  }

  /**
   * Provides a compact, single-line summary of the alert for condensed UI placements. The result is
   * identical to {@link #getTitle()} and exists as a convenience for API clients that expect a
   * short-text contract. Using this method avoids recomputing or reformatting the title in multiple
   * call sites and ensures consistent labeling across different renderers.
   *
   * @return a concise description appropriate for summary views; never {@code null}.
   */
  @Override
  public String getShortText() {
    return getTitle();
  }

  /**
   * Builds an {@link HTMLNode} tree that renders a rich alert with actionable links. The HTML
   * version includes a button to add the bookmark (when enabled) and a link to open the {@code
   * freenet:} URI. Line breaks in the description are converted into {@code <br>} nodes for
   * readability.
   *
   * <p>The returned node is self-contained and safe to embed in a larger document fragment. Callers
   * may style container elements but should not assume a particular child order beyond the anchor
   * and image elements produced here.
   *
   * @return a hierarchical {@link HTMLNode} representation of the alert content; never {@code
   *     null}.
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode alertNode = new HTMLNode("div");
    alertNode
        .addChild(
            "a",
            "href",
            "/?newbookmark=" + uri + "&desc=" + name + "&hasAnActivelink=" + hasAnActivelink)
        .addChild(
            "img",
            new String[] {"src", "alt", "title"},
            new String[] {
              "/static/icon/bookmark-new.png", l10n("addAsABookmark"), l10n("addAsABookmark")
            });
    alertNode.addChild("a", "href", "/freenet:" + uri.toString()).addChild("#", name);
    if (description != null && !description.isEmpty()) {
      String[] lines = splitLines(description);
      alertNode.addChild("br");
      alertNode.addChild("br");
      alertNode.addChild("#", l10n("bookmarkDescription"));
      alertNode.addChild("br");
      for (int i = 0; i < lines.length; i++) {
        alertNode.addChild("#", lines[i]);
        if (i != lines.length - 1) alertNode.addChild("br");
      }
    }
    return alertNode;
  }

  /**
   * Returns the localized label for the dismiss action. This text is suitable for a button or menu
   * item that removes the alert from view and is kept short to fit compact controls. The label is
   * resolved via the alert’s localization keys to match the rest of the UI.
   *
   * @return a localized, single-word or short-phrase label for the Dismiss button; never {@code
   *     null}.
   */
  @Override
  public String dismissButtonText() {
    return l10n("delete");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("BookmarkFeedUserAlert." + key);
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

  /** Resolve the localized title using the {@code ${from}} placeholder for the source node name. */
  private String l10nTitleFrom(String value) {
    return NodeL10n.getBase().getString("BookmarkFeedUserAlert.title", "from", value);
  }

  /**
   * Performs cleanup when the user dismisses the alert. If the originating peer is still available,
   * the method requests removal of the associated temporary peer data file identified by {@code
   * fileNumber}. If the peer is gone, the method silently does nothing.
   */
  @Override
  public void onDismiss() {
    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null) pn.deleteExtraPeerDataFile(fileNumber);
  }

  /**
   * Returns an FCP {@link BookmarkFeed} message equivalent to the current alert content. The
   * returned object carries the same title, text, priority, timestamps, and bookmark details used
   * by the UI, enabling remote clients to process or display the alert consistently.
   *
   * @return a new {@link BookmarkFeed} instance encapsulating this alert’s data; the caller gains
   *     full ownership of the returned object.
   */
  @Override
  public BookmarkFeed getFCPMessage() {
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
    return new BookmarkFeed(params, name, uri, description, hasAnActivelink);
  }

  /**
   * Refreshes transient peer-derived fields and reports that the alert remains displayable. If the
   * originating peer is still referenced, the visible source node name is updated from the live
   * peer state. The alert itself does not expire by design.
   *
   * @return always {@code true}; callers may rely on this to keep the alert visible unless external
   *     policy removes it.
   */
  @Override
  public boolean isValid() {
    DarknetPeerNode pn = (DarknetPeerNode) peerRef.get();
    if (pn != null) sourceNodeName = pn.getName();
    return true;
  }
}
