package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.Comparator;
import java.util.HashMap;
import java.util.function.Consumer;
import java.util.function.ObjLongConsumer;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNodeStatus;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renders and processes the Darknet friends management pages served over FProxy.
 *
 * <p>This toadlet lists known Darknet peers, exposes actions to adjust trust, visibility, and local
 * routing preferences, and allows users to exchange node references (noderefs) as downloadable
 * {@code .fref} files. It bridges user interactions from HTML forms to {@link DarknetPeerNode}
 * state changes while keeping the page content localized via {@link NodeL10n}. The handler supports
 * both standard and advanced UI modes; advanced mode reveals noderef download links and peer + *
 * lifecycle controls that would otherwise clutter the default view.
 *
 * <p>Lifecycle and concurrency: Instances are request-scoped within the HTTP server; they reuse the
 * parent {@link ConnectionsToadlet} helpers for list rendering and for redirect behavior. Methods
 * avoid caching peer state across calls so that concurrent peer updates (adds/removals or noderef
 * changes) are reflected immediately, and noderef downloads defensively re-check availability to
 * avoid null dereferences. The toadlet itself is stateless apart from injected collaborators.
 *
 * <ul>
 *   <li>Handles GET requests by delegating to {@link #handleMethodGET(URI, HTTPRequest,
 *       ToadletContext)}.
 *   <li>Handles POST form submissions through {@link #handleAltPost(URI, HTTPRequest,
 *       ToadletContext, boolean)} for actions other than adding peers.
 *   <li>Formats noderef downloads with {@code Content-Disposition} so browsers save the file to
 *       disk.
 * </ul>
 *
 * @see ConnectionsToadlet
 * @see DarknetPeerNode
 */
public class DarknetConnectionsToadlet extends ConnectionsToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(DarknetConnectionsToadlet.class);
  private static final String ATTR_CLASS = "class";
  private static final String ELEMENT_INPUT = "input";
  private static final String ELEMENT_SELECT = "select";
  private static final String ELEMENT_OPTION = "option";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_ID = "id";
  private static final String TYPE_SUBMIT = "submit";
  private static final String ACTION = "action";
  private static final String DO_ACTION = "doAction";
  private static final String CHANGE_VISIBILITY = "changeVisibility";
  private static final String REMOVE = "remove";
  private static final String CHANGE_TRUST = "changeTrust";
  private static final String FRIEND_PREFIX = "friend-";
  private static final String FREF_SUFFIX = ".fref";
  private static final char PATH_DELIMITER = '/';
  private static final String FRIENDS_PATH = PATH_DELIMITER + "friends" + PATH_DELIMITER;
  private static final String NODE_PREFIX = "node_";
  private static final String PRIVATE_NOTE_PREFIX = "peerPrivateNote_";
  private static final long WEEK_MILLIS = 1000L * 60 * 60 * 24 * 7;

  /**
   * Creates a toadlet bound to the given node and client helpers.
   *
   * <p>The constructor does not perform any I/O. It simply wires collaborators so that subsequent
   * request handling can resolve peers, render pages, and push actions to the {@link Node} and
   * {@link NodeClientCore}.
   *
   * @param n node providing peer state, noderef export helpers, and removal operations; must not be
   *     {@code null}.
   * @param core client core used for higher-level operations delegated by the superclass; must not
   *     be {@code null}.
   * @param client HTTP-facing client used by parent classes to issue follow-on requests; must not
   *     be {@code null}.
   */
  DarknetConnectionsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
    super(n, core, client);
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  /**
   * Comparator that orders {@link DarknetPeerNodeStatus} instances using Darknet-specific fields
   * before falling back to the base ordering.
   *
   * <p>Sorting respects the current UI choice exposed via {@code sortBy} and honours the reversed
   * flag managed by the caller. Fields such as trust level, visibility, and user-supplied private
   * notes are compared using case-insensitive semantics to deliver predictable table ordering
   * across locales.
   */
  protected class DarknetComparator extends ComparatorByStatus {

    DarknetComparator(String sortBy, boolean reversed) {
      super(sortBy, reversed);
    }

    /**
     * Applies Darknet-specific sort keys ahead of the base comparator.
     *
     * <p>When {@code sortBy} selects name, private note, trust, or visibility, this method compares
     * those fields directly and returns as soon as a difference is found. Otherwise, it delegates
     * to {@link ComparatorByStatus#customCompare(PeerNodeStatus, PeerNodeStatus, String)} for
     * common handling. Callers should pass peer statuses originating from {@link
     * #getPeerNodeStatuses(boolean)} to avoid {@link ClassCastException}.
     *
     * @param firstNode first peer to compare; expected to be a {@link DarknetPeerNodeStatus}
     *     instance.
     * @param secondNode second peer to compare; expected to be a {@link DarknetPeerNodeStatus}
     *     instance.
     * @param sortBy requested sort key, matching one of the column identifiers or {@code null} for
     *     default behavior.
     * @return negative if {@code firstNode} should appear before {@code secondNode}; positive for
     *     the inverse; zero when considered equal for the requested key.
     */
    @Override
    protected int customCompare(
        PeerNodeStatus firstNode, PeerNodeStatus secondNode, String sortBy) {
      switch (sortBy) {
        case "name":
          return ((DarknetPeerNodeStatus) firstNode)
              .getName()
              .compareToIgnoreCase(((DarknetPeerNodeStatus) secondNode).getName());
        case "privnote":
          return ((DarknetPeerNodeStatus) firstNode)
              .getPrivateDarknetCommentNote()
              .compareToIgnoreCase(
                  ((DarknetPeerNodeStatus) secondNode).getPrivateDarknetCommentNote());
        case "trust":
          return ((DarknetPeerNodeStatus) firstNode)
              .getTrustLevel()
              .compareTo(((DarknetPeerNodeStatus) secondNode).getTrustLevel());
        case "visibility":
          int ret =
              ((DarknetPeerNodeStatus) firstNode)
                  .getOurVisibility()
                  .compareTo(((DarknetPeerNodeStatus) secondNode).getOurVisibility());
          if (ret != 0) return ret;
          return ((DarknetPeerNodeStatus) firstNode)
              .getTheirVisibility()
              .compareTo(((DarknetPeerNodeStatus) secondNode).getTheirVisibility());
        default:
          return super.customCompare(firstNode, secondNode, sortBy);
      }
    }

    /**
     * Default comparison after status-aware ordering has already been applied.
     *
     * <p>This tie-breaker compares peer names case-insensitively so that peers with identical
     * status and no distinguishing fields still sort deterministically. It is invoked only when
     * upstream comparisons report equality.
     *
     * @param firstNode first peer considered equal by previous comparators.
     * @param secondNode second peer considered equal by previous comparators.
     * @return ordering value based on lexicographic comparison of peer names.
     */
    @Override
    protected int lastResortCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      return ((DarknetPeerNodeStatus) firstNode)
          .getName()
          .compareToIgnoreCase(((DarknetPeerNodeStatus) secondNode).getName());
    }
  }

  /**
   * Returns a comparator tuned for Darknet peer lists with optional reversal.
   *
   * <p>The comparator enforces status-sensitive ordering inherited from the superclass and applies
   * Darknet-specific keys such as private notes and visibility. The returned instance is stateless
   * and may be reused by callers for sorting multiple collections.
   *
   * @param sortBy requested column key that influences comparator behavior; may be {@code null} to
   *     use default ordering.
   * @param reversed when {@code true}, the comparator inverts its result to support descending
   *     views.
   * @return comparator suitable for {@link DarknetPeerNodeStatus} arrays presented in the UI.
   */
  @Override
  protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
    return new DarknetComparator(sortBy, reversed);
  }

  /**
   * Indicates that the Darknet listing always includes a name column.
   *
   * <p>The column is required for both standard and advanced modes because the UI exposes noderef
   * downloads and message actions keyed by human-readable peer names. Hiding it would make the page
   * difficult to scan, especially when hash codes are long, and would break keyboard navigation
   * that expects the first column to be selectable text. Keeping the column present across modes
   * also preserves sort stability when users toggle between different column orders.
   *
   * @return {@code true} to signal presence of a name column in the table layout.
   */
  @Override
  protected boolean hasNameColumn() {
    return true;
  }

  /**
   * Renders the peer name cell, optionally attaching a noderef download link in advanced mode.
   *
   * <p>The method adds a link that opens the confidential messaging form and, when advanced mode is
   * enabled and a full noderef is present, appends a {@code .fref} download anchor. It assumes that
   * {@code peerRow} already belongs to the table row for this peer and mutates it in place.
   *
   * @param peerRow table row node that will receive the rendered cell; must not be {@code null}.
   * @param peerNodeStatus status snapshot for the peer being rendered; expected to be a {@link
   *     DarknetPeerNodeStatus}.
   * @param advanced whether the UI is in advanced mode, controlling visibility of the noderef link.
   */
  @Override
  protected void drawNameColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advanced) {
    // name column
    HTMLNode cell = peerRow.addChild("td", ATTR_CLASS, "peer-name");
    cell.addChild(
        "a",
        "href",
        "/send_n2ntm/?peernode_hashcode=" + peerNodeStatus.hashCode(),
        ((DarknetPeerNodeStatus) peerNodeStatus).getName());
    if (advanced && peerNodeStatus.hasFullNoderef) {
      cell.addChild("#", " (");
      cell.addChild(
          "a",
          "href",
          path() + FRIEND_PREFIX + peerNodeStatus.hashCode() + FREF_SUFFIX,
          l10n("noderefLink"));
      cell.addChild("#", ")");
    }
  }

  /**
   * Indicates that the Darknet table exposes a trust column for every peer.
   *
   * <p>Trust drives routing and bandwidth allocation decisions, so it must remain visible at all
   * times for operators to evaluate the health of their friend list. The column participates in
   * sorting and bulk actions, and hiding it would force users to drill into peer details to perform
   * common diagnostics.
   *
   * @return {@code true} because trust is always displayed.
   */
  @Override
  protected boolean hasTrustColumn() {
    return true;
  }

  /**
   * Renders the trust level column for a Darknet peer.
   *
   * <p>The trust value is shown verbatim using the enum name; no localization is applied here to
   * ensure consistency with the rest of the peer management UI. The method does not attempt to
   * derive explanatory text, keeping rendering fast for large peer lists and leaving deeper
   * explanations to tooltips elsewhere. Empty cells are never produced because every peer carries a
   * trust enum value.
   *
   * @param peerRow table row node that will receive the rendered cell; must not be {@code null}.
   * @param peerNodeStatus status snapshot for the peer being rendered; expected to be a {@link
   *     DarknetPeerNodeStatus}.
   */
  @Override
  protected void drawTrustColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    peerRow
        .addChild("td", ATTR_CLASS, "peer-trust")
        .addChild("#", ((DarknetPeerNodeStatus) peerNodeStatus).getTrustLevel().name());
  }

  /**
   * Indicates that the Darknet table exposes a visibility column.
   *
   * <p>Visibility reflects how peers present themselves to one another and whether we reveal our
   * node identity back. Showing the column in all modes avoids surprising users when a peer appears
   * unreachable due to restrictive visibility. It also supports sorting, letting users quickly list
   * peers configured with stricter policies.
   *
   * @return {@code true} because both our visibility and their visibility are shown to users.
   */
  @Override
  protected boolean hasVisibilityColumn() {
    return true;
  }

  /**
   * Renders the visibility column, optionally including the peer's view of our visibility.
   *
   * <p>When advanced mode is enabled the cell shows both sides of visibility; otherwise only our
   * visibility is displayed to keep the default view compact. The combined string is kept concise
   * so that columns remain aligned when many peers are listed, and values are rendered in enum form
   * to match the filters available in the rest of the UI.
   *
   * @param peerRow table row node that will receive the rendered cell; must not be {@code null}.
   * @param peerNodeStatus status snapshot for the peer being rendered; expected to be a {@link
   *     DarknetPeerNodeStatus}.
   * @param advancedModeEnabled whether to include the peer's perspective alongside ours.
   */
  @Override
  protected void drawVisibilityColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advancedModeEnabled) {
    String content = ((DarknetPeerNodeStatus) peerNodeStatus).getOurVisibility().name();
    if (advancedModeEnabled)
      content += " (" + ((DarknetPeerNodeStatus) peerNodeStatus).getTheirVisibility().name() + ")";
    peerRow.addChild("td", ATTR_CLASS, "peer-trust").addChild("#", content);
  }

  /**
   * Indicates that a private note column is available for every Darknet peer.
   *
   * <p>Private notes capture operator context that is not shared with the peer itself, such as when
   * the friend was added or whether troubleshooting is pending. Keeping the column always visible
   * ensures those notes remain actionable and prevents keyboard navigation from shifting when
   * advanced mode toggles.
   *
   * @return {@code true} because private notes are always shown.
   */
  @Override
  protected boolean hasPrivateNoteColumn() {
    return true;
  }

  /**
   * Renders the private note column, honoring whether FProxy JavaScript is available.
   *
   * <p>When JavaScript is enabled the input field registers a change handler so that updates can be
   * submitted without a full page refresh. Without JavaScript, a plain text input is rendered and
   * users save changes through explicit form submission.
   *
   * @param peerRow table row node that will receive the rendered cell; must not be {@code null}.
   * @param peerNodeStatus status snapshot for the peer being rendered; expected to be a {@link
   *     DarknetPeerNodeStatus}.
   * @param fProxyJavascriptEnabled flag indicating whether client-side JavaScript helpers should be
   *     wired.
   */
  @Override
  protected void drawPrivateNoteColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean fProxyJavascriptEnabled) {
    // private darknet node comment note column
    DarknetPeerNodeStatus status = (DarknetPeerNodeStatus) peerNodeStatus;
    if (fProxyJavascriptEnabled) {
      peerRow
          .addChild("td", ATTR_CLASS, "peer-private-darknet-comment-note")
          .addChild(
              ELEMENT_INPUT,
              new String[] {ATTR_TYPE, ATTR_NAME, "size", "maxlength", "onChange", ATTR_VALUE},
              new String[] {
                "text",
                PRIVATE_NOTE_PREFIX + peerNodeStatus.hashCode(),
                "16",
                "250",
                "peerNoteChange();",
                status.getPrivateDarknetCommentNote()
              });
    } else {
      peerRow
          .addChild("td", ATTR_CLASS, "peer-private-darknet-comment-note")
          .addChild(
              ELEMENT_INPUT,
              new String[] {ATTR_TYPE, ATTR_NAME, "size", "maxlength", ATTR_VALUE},
              new String[] {
                "text",
                PRIVATE_NOTE_PREFIX + peerNodeStatus.hashCode(),
                "16",
                "250",
                status.getPrivateDarknetCommentNote()
              });
    }
  }

  /**
   * Returns the noderef representing this node's Darknet identity.
   *
   * <p>The exported {@link SimpleFieldSet} is typically embedded into the page so users can share
   * their reference with trusted peers. Callers should treat the returned object as immutable and
   * avoid retaining it beyond the current request.
   *
   * @return the Darknet noderef for the local node; never {@code null} but may be empty if export
   *     fails upstream.
   */
  @Override
  protected SimpleFieldSet getNoderef() {
    return node.exportDarknetPublicFieldSet();
  }

  /**
   * Retrieves a snapshot of Darknet peer statuses with optional lightweight mode.
   *
   * <p>The array is produced by the peer manager and reflects the moment of invocation; it is not
   * live-updating. When {@code noHeavy} is {@code true}, expensive computations such as bandwidth
   * accounting may be skipped to keep page rendering responsive on large friend sets. Callers
   * should treat the returned array as read-only and re-query if subsequent actions depend on
   * up-to-date metrics.
   *
   * @param noHeavy whether to request a lightweight status snapshot that avoids heavy refresh work.
   * @return statuses for each configured Darknet peer; never {@code null} but possibly empty.
   */
  @Override
  protected PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
    return node.getPeers().getDarknetPeerNodeStatuses(noHeavy);
  }

  /**
   * Returns the localized page title including peer counts.
   *
   * <p>The title uses the {@code counts} placeholder understood by {@link NodeL10n} to insert a
   * short count string that includes the number of active and disabled peers. Providing the title
   * here keeps localization keys scoped to the Darknet page and lets future UI tweaks reuse the
   * counting logic without duplicating string handling.
   *
   * @param titleCountString formatted count string provided by the superclass.
   * @return localized title string for the Darknet friends page.
   */
  @Override
  protected String getPageTitle(String titleCountString) {
    return NodeL10n.getBase()
        .getString(
            "DarknetConnectionsToadlet.fullTitle",
            new String[] {"counts"},
            new String[] {titleCountString});
  }

  /**
   * Determines whether the noderef box should be rendered for the current request.
   *
   * <p>Advanced users often exchange noderefs manually, so the box is shown only in advanced mode
   * to avoid confusing newcomers who typically rely on invitation workflows. Keeping this decision
   * centralized ensures GET and POST handlers agree on what the page should render, avoiding
   * flickering between navigation steps.
   *
   * @param advancedModeEnabled whether the user has enabled advanced UI mode.
   * @return {@code true} when advanced mode is active, enabling direct noderef display.
   */
  @Override
  protected boolean shouldDrawNoderefBox(boolean advancedModeEnabled) {
    // Convenient for advanced users, but normally we will use the "Add a friend" box.
    return advancedModeEnabled;
  }

  /**
   * Indicates that the peer actions box should always be shown.
   *
   * <p>The actions box collects bulk operations such as enabling/disabling peers and changing trust
   * or visibility. Showing it consistently avoids layout jumps and ensures keyboard shortcuts (like
   * submitting selected actions) remain valid regardless of advanced mode or viewport. It also
   * keeps the page aligned with legacy behavior expected by power users.
   *
   * @return {@code true} to render the actions form beneath the peer list.
   */
  @Override
  protected boolean showPeerActionsBox() {
    return true;
  }

  /**
   * Populates the action selector and related controls for bulk peer operations.
   *
   * <p>The selector mixes always-available actions (note updates, removal) with advanced controls
   * (enable/disable, burst/listen-only, local address allowances, routing flags). Submissions are
   * routed to {@link #handleAltPost(URI, HTTPRequest, ToadletContext, boolean)} for processing.
   *
   * @param peerForm form node to which inputs and selects are appended; must not be {@code null}.
   * @param advancedModeEnabled whether advanced-only options should be included in the selector.
   */
  @Override
  protected void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled) {
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "doSendMessageToPeers", l10n("sendConfidentialMessage")});
    peerForm.addChild("br");

    HTMLNode actionSelect =
        peerForm.addChild(
            ELEMENT_SELECT, new String[] {ATTR_ID, ATTR_NAME}, new String[] {ACTION, ACTION});
    actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "", l10n("selectAction"));
    actionSelect.addChild(
        ELEMENT_OPTION, ATTR_VALUE, "update_notes", l10n("updateChangedPrivnotes"));
    if (advancedModeEnabled) {
      actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "enable", l10n("peersEnable"));
      actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "disable", l10n("peersDisable"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "set_burst_only", l10n("peersSetBurstOnly"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "clear_burst_only", l10n("peersClearBurstOnly"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "set_listen_only", l10n("peersSetListenOnly"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "clear_listen_only", l10n("peersClearListenOnly"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "set_allow_local", l10n("peersSetAllowLocal"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "clear_allow_local", l10n("peersClearAllowLocal"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "set_ignore_source_port", l10n("peersSetIgnoreSourcePort"));
      actionSelect.addChild(
          ELEMENT_OPTION,
          ATTR_VALUE,
          "clear_ignore_source_port",
          l10n("peersClearIgnoreSourcePort"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "set_dont_route", l10n("peersSetDontRoute"));
      actionSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, "clear_dont_route", l10n("peersClearDontRoute"));
    }
    actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, "", l10n("separator"));
    actionSelect.addChild(ELEMENT_OPTION, ATTR_VALUE, REMOVE, l10n("removePeers"));
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, DO_ACTION, l10n("go")});
    peerForm.addChild("br");
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "doChangeTrust", l10n("changeTrustButton")});
    HTMLNode changeTrustLevelSelect =
        peerForm.addChild(
            ELEMENT_SELECT,
            new String[] {ATTR_ID, ATTR_NAME},
            new String[] {CHANGE_TRUST, CHANGE_TRUST});
    for (FRIEND_TRUST trust : FRIEND_TRUST.valuesBackwards()) {
      changeTrustLevelSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, trust.name(), l10n("peerTrust." + trust.name()));
    }
    peerForm.addChild("br");
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "doChangeVisibility", l10n("changeVisibilityButton")});
    HTMLNode changeVisibilitySelect =
        peerForm.addChild(
            ELEMENT_SELECT,
            new String[] {ATTR_ID, ATTR_NAME},
            new String[] {CHANGE_VISIBILITY, CHANGE_VISIBILITY});
    for (FRIEND_VISIBILITY trust : FRIEND_VISIBILITY.values()) {
      changeVisibilitySelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, trust.name(), l10n("peerVisibility." + trust.name()));
    }
  }

  /**
   * Provides the heading label for the Darknet peer list.
   *
   * <p>The title is localized through the internal {@code l10n(...)} helper and remains concise so
   * it fits inside the standard page header without wrapping. Keeping the value in a dedicated
   * method allows subclasses or future variants to override the label while reusing rendering
   * logic.
   *
   * @return localized string used as the peer list title.
   */
  @Override
  protected String getPeerListTitle() {
    return l10n("myFriends");
  }

  /**
   * Signals that this toadlet accepts noderef uploads in POST bodies.
   *
   * <p>The feature enables the "Add a friend" workflow to ingest references provided by users or
   * remote peers. Accepting POSTs here avoids forcing users to navigate to a dedicated endpoint and
   * keeps the connection form self-contained. The return value stays constant so callers can rely
   * on consistent capabilities regardless of advanced mode.
   *
   * @return {@code true} to allow reference POSTs for Darknet peer onboarding.
   */
  @Override
  protected boolean acceptRefPosts() {
    return true;
  }

  /**
   * Provides the default redirect location for this toadlet.
   *
   * <p>Redirects point to the friends listing so that users land on the canonical page after
   * actions such as removals or bulk edits. Keeping a stable target prevents open redirect risks
   * and ensures the browser refreshes the latest peer state after mutations. The path includes both
   * leading and trailing slashes to match routing expectations in upstream handlers.
   *
   * @return {@code "/friends/"} path with leading and trailing slashes.
   */
  @Override
  protected String defaultRedirectLocation() {
    return FRIENDS_PATH; // Previously redirected to /friends/
  }

  /**
   * Handles POST actions other than adding new peers.
   *
   * <p>This method routes form submissions for sending confidential messages, updating notes,
   * toggling peer flags, changing trust/visibility, removing peers, and accepting or rejecting
   * transfers. Each action delegates to a specialized helper and typically ends with a redirect to
   * avoid duplicate submissions. Actions are silently ignored when required parts are missing,
   * keeping behavior consistent with the legacy UI.
   *
   * @param uri original request URI; used only for fallback GET handling; must not be {@code null}.
   * @param request parsed POST request containing form parameters and multipart parts; must not be
   *     {@code null}.
   * @param ctx toadlet context providing page rendering, redirect helpers, and environment flags;
   *     must not be {@code null}.
   * @param logMINOR legacy flag retained from superclass to control logging verbosity; advanced
   *     callers may pass {@code true} to emit additional diagnostics.
   * @throws ToadletContextClosedException if the client connection is closed while generating a
   *     response.
   * @throws IOException if reading request data or writing responses fails.
   * @throws RedirectException when the operation triggers an explicit redirect handled by the
   *     superclass.
   */
  @Override
  protected void handleAltPost(URI uri, HTTPRequest request, ToadletContext ctx, boolean logMINOR)
      throws ToadletContextClosedException, IOException, RedirectException {
    DarknetPeerNode[] peerNodes = node.getDarknetConnections();

    if (request.isPartSet("doSendMessageToPeers")) {
      handleSendMessageToPeers(request, ctx, peerNodes);
      return;
    }

    String action = extractAction(request);

    if (handleUpdateNotes(action, request, peerNodes)) {
      redirectHere(ctx);
      return;
    }

    if (handlePeerToggleActions(action, request, peerNodes)) {
      redirectHere(ctx);
      return;
    }

    if (handleChangeTrust(request, peerNodes)) {
      redirectHere(ctx);
      return;
    }

    if (handleChangeVisibility(request, peerNodes)) {
      redirectHere(ctx);
      return;
    }

    if (handleRemove(action, request, ctx, peerNodes)) {
      return;
    }

    if (handleTransfer(request, peerNodes, "acceptTransfer", DarknetPeerNode::acceptTransfer)) {
      redirectHere(ctx);
      return;
    }

    if (handleTransfer(request, peerNodes, "rejectTransfer", DarknetPeerNode::rejectTransfer)) {
      redirectHere(ctx);
      return;
    }

    this.handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
  }

  private String extractAction(HTTPRequest request) {
    if (!request.isPartSet(DO_ACTION)) {
      return null;
    }
    return request.getPartAsStringFailsafe(ACTION, 25);
  }

  private void handleSendMessageToPeers(
      HTTPRequest request, ToadletContext ctx, DarknetPeerNode[] peerNodes)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("sendMessageTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HashMap<String, String> peers = new HashMap<>();
    for (DarknetPeerNode pn : peerNodes) {
      if (request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        String peerHash = String.valueOf(pn.hashCode());
        peers.putIfAbsent(peerHash, pn.getName());
      }
    }
    N2NTMToadlet.createN2NTMSendForm(ctx.isAdvancedModeEnabled(), contentNode, ctx, peers);
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void applyToSelectedPeers(
      HTTPRequest request, DarknetPeerNode[] peerNodes, Consumer<DarknetPeerNode> action) {
    for (DarknetPeerNode pn : peerNodes) {
      if (request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        action.accept(pn);
      }
    }
  }

  private boolean handleUpdateNotes(
      String action, HTTPRequest request, DarknetPeerNode[] peerNodes) {
    if (!"update_notes".equals(action)) {
      return false;
    }
    for (DarknetPeerNode pn : peerNodes) {
      if (request.isPartSet(PRIVATE_NOTE_PREFIX + pn.hashCode())) {
        String note = request.getPartAsStringFailsafe(PRIVATE_NOTE_PREFIX + pn.hashCode(), 250);
        if (!note.equals(pn.getPrivateDarknetCommentNote())) {
          pn.setPrivateDarknetCommentNote(note);
        }
      }
    }
    return true;
  }

  private boolean handlePeerToggleActions(
      String action, HTTPRequest request, DarknetPeerNode[] peerNodes) {
    if (action == null) {
      return false;
    }
    return switch (action) {
      case "enable" -> {
        applyToSelectedPeers(request, peerNodes, DarknetPeerNode::enablePeer);
        yield true;
      }
      case "disable" -> {
        applyToSelectedPeers(request, peerNodes, DarknetPeerNode::disablePeer);
        yield true;
      }
      case "set_burst_only" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setBurstOnly(true));
        yield true;
      }
      case "clear_burst_only" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setBurstOnly(false));
        yield true;
      }
      case "set_ignore_source_port" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setIgnoreSourcePort(true));
        yield true;
      }
      case "clear_ignore_source_port" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setIgnoreSourcePort(false));
        yield true;
      }
      case "clear_dont_route" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setRoutingStatus(true, true));
        yield true;
      }
      case "set_dont_route" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setRoutingStatus(false, true));
        yield true;
      }
      case "set_listen_only" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setListenOnly(true));
        yield true;
      }
      case "clear_listen_only" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setListenOnly(false));
        yield true;
      }
      case "set_allow_local" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setAllowLocalAddresses(true));
        yield true;
      }
      case "clear_allow_local" -> {
        applyToSelectedPeers(request, peerNodes, pn -> pn.setAllowLocalAddresses(false));
        yield true;
      }
      default -> false;
    };
  }

  private boolean handleChangeTrust(HTTPRequest request, DarknetPeerNode[] peerNodes) {
    if (!request.isPartSet(CHANGE_TRUST) || !request.isPartSet("doChangeTrust")) {
      return false;
    }
    FRIEND_TRUST trust = FRIEND_TRUST.valueOf(request.getPartAsStringFailsafe(CHANGE_TRUST, 10));
    applyToSelectedPeers(request, peerNodes, pn -> pn.setTrustLevel(trust));
    return true;
  }

  private boolean handleChangeVisibility(HTTPRequest request, DarknetPeerNode[] peerNodes) {
    if (!request.isPartSet(CHANGE_VISIBILITY) || !request.isPartSet("doChangeVisibility")) {
      return false;
    }
    FRIEND_VISIBILITY trust =
        FRIEND_VISIBILITY.valueOf(request.getPartAsStringFailsafe(CHANGE_VISIBILITY, 10));
    applyToSelectedPeers(request, peerNodes, pn -> pn.setVisibility(trust));
    return true;
  }

  private boolean handleRemove(
      String action, HTTPRequest request, ToadletContext ctx, DarknetPeerNode[] peerNodes)
      throws ToadletContextClosedException, IOException {
    boolean requested = request.isPartSet(REMOVE) || REMOVE.equals(action);
    if (!requested) {
      return false;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Remove node");
    }
    for (DarknetPeerNode pn : peerNodes) {
      if (!request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        if (LOG.isDebugEnabled()) LOG.debug("Part not set: node_{}", pn.hashCode());
        continue;
      }
      if (canRemovePeer(request, pn)) {
        node.removePeerConnection(pn);
        if (LOG.isDebugEnabled()) LOG.debug("Removed node: node_{}", pn.hashCode());
      } else {
        showRemoveWarning(ctx, pn);
        return true;
      }
    }
    redirectHere(ctx);
    return true;
  }

  private boolean canRemovePeer(HTTPRequest request, DarknetPeerNode pn) {
    return pn.timeLastConnectionCompleted() < (System.currentTimeMillis() - WEEK_MILLIS)
        || pn.getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED
        || request.isPartSet("forceit");
  }

  private void showRemoveWarning(ToadletContext ctx, DarknetPeerNode pn)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmRemoveNodeTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                "infobox-warning",
                l10n("confirmRemoveNodeWarningTitle"),
                contentNode,
                "darknet-remove-node",
                true);
    content
        .addChild("p")
        .addChild(
            "#",
            NodeL10n.getBase()
                .getString(
                    "DarknetConnectionsToadlet.confirmRemoveNode",
                    new String[] {"name"},
                    new String[] {pn.getName()}));
    HTMLNode removeForm = ctx.addFormChild(content, FRIENDS_PATH, "removeConfirmForm");
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {"hidden", NODE_PREFIX + pn.hashCode(), REMOVE});
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, REMOVE, l10n(REMOVE)});
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {"hidden", "forceit", l10n("forceRemove")});

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean handleTransfer(
      HTTPRequest request,
      DarknetPeerNode[] peerNodes,
      String partName,
      ObjLongConsumer<DarknetPeerNode> handler) {
    if (!request.isPartSet(partName)) {
      return false;
    }
    long id = Long.parseLong(request.getPartAsStringFailsafe("id", 32));
    for (DarknetPeerNode pn : peerNodes) {
      if (request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        handler.accept(pn, id);
        break;
      }
    }
    return true;
  }

  private void redirectHere(ToadletContext ctx) throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", FRIENDS_PATH);
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  /**
   * Reports whether this toadlet serves the Opennet peer set.
   *
   * <p>The Darknet view deliberately returns {@code false} so callers and upstream routing can
   * differentiate between friend-based and open connectivity modes. Keeping the override explicit
   * guards against accidental reuse of Opennet-only code paths that assume untrusted peers or
   * different invitation flows.
   *
   * @return {@code false} because this toadlet represents the Darknet (friend-to-friend) interface.
   */
  @Override
  protected boolean isOpennet() {
    return false;
  }

  /**
   * Supplies any trailing columns after the standard set; Darknet uses none.
   *
   * <p>Returning an empty array preserves layout expectations in the superclass while signaling
   * that no additional columns are needed for this network type.
   *
   * @param advancedMode whether the caller requested advanced-mode columns; unused.
   * @return an empty array indicating no extra columns.
   */
  @Override
  SimpleColumn[] endColumnHeaders(boolean advancedMode) {
    return new SimpleColumn[0];
  }

  /**
   * Returns the HTTP path served by this toadlet.
   *
   * <p>The value anchors all relative links generated within the page, including noderef download
   * anchors and form submission targets. Using a trailing slash avoids needless redirects from the
   * servlet container and keeps bookmark URLs stable across releases. The path is intentionally
   * lowercase to match existing navigation entries and to remain case-insensitive on filesystems
   * where that matters.
   *
   * @return constant {@code "/friends/"} path with a trailing slash.
   */
  @Override
  public String path() {
    return FRIENDS_PATH;
  }

  /**
   * Handles GET requests for the friends page or noderef downloads.
   *
   * <p>Requests for {@code /friends/friend-<hash>.fref} are intercepted and served as downloadable
   * noderef files; all other paths are delegated to the superclass for standard rendering. The
   * method is idempotent and does not persist state beyond peer-specific view updates performed
   * inside the delegated helpers.
   *
   * @param uri request URI, including path used to detect noderef downloads; must not be {@code
   *     null}.
   * @param request HTTP request wrapper carrying headers and parameters; must not be {@code null}.
   * @param ctx toadlet context for building responses; must not be {@code null}.
   * @throws ToadletContextClosedException if the client disconnects during response writing.
   * @throws IOException if generating the HTML or download response fails.
   * @throws RedirectException if upstream handlers choose to redirect the request.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (tryHandlePeerNoderef(uri, ctx)) return;
    super.handleMethodGET(uri, request, ctx);
  }

  private boolean tryHandlePeerNoderef(URI uri, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String path = uri.getPath();
    if (!path.endsWith(FREF_SUFFIX) || !path.startsWith(path() + FRIEND_PREFIX)) {
      return false;
    }

    String hashcodePart =
        path.substring((path() + FRIEND_PREFIX).length(), path.length() - FREF_SUFFIX.length());
    int inputHashcode;
    try {
      inputHashcode = Integer.parseInt(hashcodePart);
    } catch (NumberFormatException e) {
      return false;
    }

    DarknetPeerNode peerNode = findPeerNodeByHash(inputHashcode);
    if (peerNode == null) {
      return false;
    }

    String filename = FileUtil.sanitizeFileNameWithExtras(peerNode.getName() + FREF_SUFFIX, "\" ");
    SimpleFieldSet noderef = peerNode.getFullNoderef();
    if (noderef == null) {
      // We have no stored noderef for this peer yet; do not treat as an error.
      return false;
    }
    String content = noderef.toString();
    MultiValueTable<String, String> extraHeaders =
        MultiValueTable.from(
            // Force download to disk
            "Content-Disposition", "attachment; filename=" + filename);
    this.writeReply(ctx, 200, "application/x-freenet-reference", "OK", extraHeaders, content);
    return true;
  }

  private DarknetPeerNode findPeerNodeByHash(int inputHashcode) {
    if (inputHashcode == -1) {
      return null;
    }
    for (DarknetPeerNode pn : node.getDarknetConnections()) {
      if (pn.hashCode() == inputHashcode) {
        return pn;
      }
    }
    return null;
  }
}
