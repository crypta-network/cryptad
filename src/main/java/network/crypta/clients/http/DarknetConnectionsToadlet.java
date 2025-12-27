package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
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
 * Toadlet that renders and manages the darknet "friends" page and its form actions.
 *
 * <p>This toadlet presents the list of trusted darknet peers, allows users to adjust trust and
 * visibility settings, and exposes bulk actions such as enabling, disabling, or removing peers. It
 * reuses the shared table rendering logic from {@link ConnectionsToadlet} but specializes it for
 * darknet-only concepts like private notes, friend references, and transfer confirmations. Typical
 * callers route HTTP GET and POST traffic from the node's web interface to this class, which then
 * populates HTML structures using {@link network.crypta.support.HTMLNode} builders and performs
 * side effects against {@link network.crypta.node.DarknetPeerNode} instances. The class is stateful
 * only through its reference to the owning {@link network.crypta.node.Node}, and operations are
 * expected to run on the single request-handling thread that invoked the toadlet; no internal
 * synchronization is performed.
 *
 * <ul>
 *   <li>Renders friend metadata, noderef download links, and private notes.
 *   <li>Handles bulk updates for trust, visibility, and routing flags.
 *   <li>Redirects or replies with downloadable references when appropriate.
 * </ul>
 *
 * @see ConnectionsToadlet
 * @see network.crypta.node.DarknetPeerNode
 */
public class DarknetConnectionsToadlet extends ConnectionsToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(DarknetConnectionsToadlet.class);
  private static final String ATTR_CLASS = "class";
  private static final String ELEMENT_INPUT = "input";
  private static final String ELEMENT_SELECT = "select";
  private static final String ELEMENT_OPTION = "option";
  private static final String ATTR_VALUE = "value";
  private static final String PEER_PRIVATE_NOTE_PREFIX = "peerPrivateNote_";
  private static final String FRIEND_PREFIX = "friend-";
  private static final String FREF_SUFFIX = ".fref";
  private static final String SUBMIT = "submit";
  private static final String ACTION = "action";
  private static final String DO_ACTION = "doAction";
  private static final String CHANGE_TRUST = "changeTrust";
  private static final String CHANGE_VISIBILITY = "changeVisibility";
  private static final String REMOVE = "remove";
  private static final char PATH_SEPARATOR = '/';
  private static final String FRIENDS_PATH = PATH_SEPARATOR + "friends" + PATH_SEPARATOR;
  private static final String NODE_PREFIX = "node_";
  private static final Map<String, Consumer<DarknetPeerNode>> SIMPLE_ACTIONS =
      Map.ofEntries(
          Map.entry("enable", DarknetPeerNode::enablePeer),
          Map.entry("disable", DarknetPeerNode::disablePeer),
          Map.entry("set_burst_only", pn -> pn.setBurstOnly(true)),
          Map.entry("clear_burst_only", pn -> pn.setBurstOnly(false)),
          Map.entry("set_ignore_source_port", pn -> pn.setIgnoreSourcePort(true)),
          Map.entry("clear_ignore_source_port", pn -> pn.setIgnoreSourcePort(false)),
          Map.entry("set_dont_route", pn -> pn.setRoutingStatus(false, true)),
          Map.entry("clear_dont_route", pn -> pn.setRoutingStatus(true, true)),
          Map.entry("set_listen_only", pn -> pn.setListenOnly(true)),
          Map.entry("clear_listen_only", pn -> pn.setListenOnly(false)),
          Map.entry("set_allow_local", pn -> pn.setAllowLocalAddresses(true)),
          Map.entry("clear_allow_local", pn -> pn.setAllowLocalAddresses(false)));

  DarknetConnectionsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
    super(n, core, client);
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  /**
   * Comparator that extends the base status ordering with darknet-specific columns.
   *
   * <p>The comparator first honors the configured sort key and reversal flag inherited from {@link
   * ComparatorByStatus}. When the caller requests name, private note, trust, or visibility
   * ordering, this comparator extracts the corresponding values from {@link DarknetPeerNodeStatus}
   * instances, falling back to the parent comparison rules for other columns. Ties on visibility
   * resolve by comparing both local and remote visibility preferences to provide deterministic
   * ordering. Instances are short-lived and created per request to avoid storing mutable sorting
   * preferences globally.
   */
  protected class DarknetComparator extends ComparatorByStatus {

    DarknetComparator(String sortBy, boolean reversed) {
      super(sortBy, reversed);
    }

    @Override
    protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      switch (this.sortBy) {
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
          return super.customCompare(firstNode, secondNode);
      }
    }

    /** Default comparison, after taking into account status. */
    @Override
    protected int lastResortCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      return ((DarknetPeerNodeStatus) firstNode)
          .getName()
          .compareToIgnoreCase(((DarknetPeerNodeStatus) secondNode).getName());
    }
  }

  /**
   * Build a comparator that orders darknet peers according to the chosen column.
   *
   * <p>The comparator encapsulates the caller's sorting preference instead of mutating shared
   * state, ensuring concurrent page renders cannot influence each other's ordering. Supported sort
   * keys include the generic status columns provided by the parent and darknet-specific fields such
   * as private notes, trust, and visibility. The {@code reversed} flag flips the natural ordering
   * so both ascending and descending views are available without recomputing the source data.
   *
   * @param sortBy column identifier accepted by {@link DarknetComparator}, including name,
   *     privnote, trust, visibility, or the inherited defaults.
   * @param reversed whether to invert the comparator to produce descending order results.
   * @return a stateless comparator instance tuned to the requested ordering.
   */
  @Override
  protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
    return new DarknetComparator(sortBy, reversed);
  }

  /**
   * Indicate that the darknet table always displays a peer name column.
   *
   * <p>The name column serves as the primary identifier for friends, enabling both navigation to
   * the confidential messaging form and, in advanced mode, access to downloadable references.
   * Hiding it would prevent users from distinguishing peers, so the method consistently returns
   * {@code true} regardless of UI mode or configuration.
   *
   * @return {@code true}, signalling that a name column must be rendered for every row.
   */
  @Override
  protected boolean hasNameColumn() {
    return true;
  }

  /**
   * Render the peer name cell with an optional noderef download link for advanced users.
   *
   * <p>The method writes a table cell containing the peer's display name and a link to the
   * confidential messaging endpoint. When advanced mode is active and a full noderef is available,
   * it also exposes a secondary link that triggers a download of the sanitized friend reference.
   * The cell contents remain purely presentational; selection and bulk actions are handled
   * elsewhere in the form.
   *
   * @param peerRow table row receiving the name content; must be non-null and part of the page.
   * @param peerNodeStatus status wrapper for the darknet peer whose name is shown.
   * @param advanced whether to include the noderef download link beside the name.
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
   * Signal that the trust column should always be rendered for darknet peers.
   *
   * <p>Trust is a primary tuning mechanism for darknet routing, so the column remains visible in
   * both basic and advanced modes. The consistent presence of the column also keeps the table
   * layout stable when users toggle feature flags.
   *
   * @return {@code true}, indicating the trust column is required in the output table.
   */
  @Override
  protected boolean hasTrustColumn() {
    return true;
  }

  /**
   * Populate the trust column with the peer's configured trust enum value.
   *
   * <p>The method writes a simple text cell that mirrors the underlying {@link FRIEND_TRUST} value
   * so users can quickly scan relative trust levels. No editing controls are embedded here;
   * adjustments are performed through the bulk actions box to avoid per-row form sprawl.
   *
   * @param peerRow row node that will receive the trust cell; must already exist in the DOM.
   * @param peerNodeStatus status describing the peer whose trust value is being rendered.
   */
  @Override
  protected void drawTrustColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
    peerRow
        .addChild("td", ATTR_CLASS, "peer-trust")
        .addChild("#", ((DarknetPeerNodeStatus) peerNodeStatus).getTrustLevel().name());
  }

  /**
   * Declare that visibility settings should always be displayed for darknet peers.
   *
   * <p>Visibility reflects whether peers may reveal each other's identity to others, making it a
   * critical safety control. Showing it unconditionally keeps the user aware of both inbound and
   * outbound sharing preferences and avoids layout shifts between basic and advanced views.
   *
   * @return {@code true}, ensuring the visibility column is rendered.
   */
  @Override
  protected boolean hasVisibilityColumn() {
    return true;
  }

  /**
   * Render local and optionally remote visibility settings in a compact text cell.
   *
   * <p>The local visibility always appears so users can confirm how their node shares the
   * connection. When advanced mode is enabled, the peer's visibility toward this node is appended
   * in parentheses to highlight asymmetries. No formatting or icons are used to keep the table
   * printable and screen-reader friendly.
   *
   * @param peerRow destination row that receives the visibility cell.
   * @param peerNodeStatus status object containing local and remote visibility values.
   * @param advancedModeEnabled whether to append the peer's visibility toward this node.
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
   * Indicate that the private note column should always be present on the friends table.
   *
   * <p>Private notes allow operators to annotate friends with context or trust cues; keeping the
   * column consistently visible avoids data loss and maintains table alignment across modes.
   *
   * @return {@code true}, signalling that note inputs should be rendered for each peer.
   */
  @Override
  protected boolean hasPrivateNoteColumn() {
    return true;
  }

  /**
   * Render the editable private note field for a peer, enabling JS onchange when available.
   *
   * <p>The method emits an {@code input type="text"} element sized for short annotations and limits
   * user input to 250 characters. When the FProxy JavaScript helpers are enabled, an {@code
   * onChange} hook triggers the client-side note tracking logic; otherwise a plain input is
   * provided so accessibility and non-scripted environments remain functional.
   *
   * @param peerRow row node to which the note input cell is appended.
   * @param peerNodeStatus status describing the peer whose note value is being edited.
   * @param fProxyJavascriptEnabled whether to attach the JavaScript change handler attribute.
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
              new String[] {"type", "name", "size", "maxlength", "onChange", ATTR_VALUE},
              new String[] {
                "text",
                PEER_PRIVATE_NOTE_PREFIX + peerNodeStatus.hashCode(),
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
              new String[] {"type", "name", "size", "maxlength", ATTR_VALUE},
              new String[] {
                "text",
                PEER_PRIVATE_NOTE_PREFIX + peerNodeStatus.hashCode(),
                "16",
                "250",
                status.getPrivateDarknetCommentNote()
              });
    }
  }

  /**
   * Export the local node's public darknet reference for distribution.
   *
   * <p>The exported field set omits private data and contains only the values needed for a remote
   * peer to add this node as a friend. Callers typically embed the returned structure in the
   * noderef download box so users can save or transmit it securely.
   *
   * @return a {@link SimpleFieldSet} containing the sanitized public darknet reference.
   */
  @Override
  protected SimpleFieldSet getNoderef() {
    return node.exportDarknetPublicFieldSet();
  }

  /**
   * Collect status snapshots for all darknet peers, optionally skipping heavy calculations.
   *
   * <p>When {@code noHeavy} is true, the returned statuses avoid expensive metrics so lightweight
   * pages can render quickly. The array ordering matches that provided by the node's peer manager
   * and is later sorted by {@link #comparator(String, boolean)} according to user preferences.
   *
   * @param noHeavy whether to omit heavy computations such as aggregated statistics.
   * @return array of {@link DarknetPeerNodeStatus} instances representing current darknet peers.
   */
  @Override
  protected PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
    return node.getPeers().statusBook().getDarknetPeerNodeStatuses(noHeavy);
  }

  /**
   * Build a localized page title that embeds the formatted friend count.
   *
   * <p>The title text is fetched from localization resources and accepts the {@code counts}
   * placeholder, allowing the caller to present short summaries such as "(5 friends)" without
   * duplicating translation keys. Returning the fully interpolated string keeps the template logic
   * centralized within the toadlet rather than scattering title construction throughout the UI
   * layer.
   *
   * @param titleCountString localized or numeric friend count already formatted for display.
   * @return localized title string ready for insertion into the page header.
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
   * Determine whether the page should include the self noderef download box.
   *
   * <p>The box is useful for power users distributing their own references but can overwhelm new
   * users. By tying visibility to the advanced mode flag, the method keeps the standard workflow
   * simple while still giving experienced operators quick access to their public noderef without
   * navigating away from the friends page.
   *
   * @param advancedModeEnabled whether the user interface is currently in advanced mode.
   * @return {@code true} when the noderef box should be rendered alongside the friends table.
   */
  @Override
  protected boolean shouldDrawNoderefBox(boolean advancedModeEnabled) {
    // Convenient for advanced users, but normally we will use the "Add a friend" box.
    return advancedModeEnabled;
  }

  /**
   * Indicate that the bulk peer actions form must always be visible.
   *
   * <p>Even in simplified mode, operators benefit from quick access to note updates and removals,
   * so the actions box is never hidden. The contained controls gate advanced operations internally
   * rather than being removed from the DOM.
   *
   * @return {@code true}, signalling callers to render the actions box unconditionally.
   */
  @Override
  protected boolean showPeerActionsBox() {
    return true;
  }

  /**
   * Append the select box and buttons that drive bulk peer operations for the friends list.
   *
   * <p>The method constructs a form section containing send-message, note-update, trust,
   * visibility, and removal actions. When advanced mode is active, additional toggles expose
   * routing and transport flags that may disrupt connectivity; these options are intentionally
   * hidden from basic users. The controls rely on the parent form to provide checkbox selections
   * whose names follow the {@code node_<hashcode>} convention.
   *
   * @param peerForm form node to which controls are appended; must already exist in the page.
   * @param advancedModeEnabled whether to include advanced-only routing and security options.
   */
  @Override
  protected void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled) {
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {SUBMIT, "doSendMessageToPeers", l10n("sendConfidentialMessage")});
    peerForm.addChild("br");

    HTMLNode actionSelect =
        peerForm.addChild(
            ELEMENT_SELECT, new String[] {"id", "name"}, new String[] {ACTION, ACTION});
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
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {SUBMIT, DO_ACTION, l10n("go")});
    peerForm.addChild("br");
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {SUBMIT, "doChangeTrust", l10n("changeTrustButton")});
    HTMLNode changeTrustLevelSelect =
        peerForm.addChild(
            ELEMENT_SELECT, new String[] {"id", "name"}, new String[] {CHANGE_TRUST, CHANGE_TRUST});
    for (FRIEND_TRUST trust : FRIEND_TRUST.valuesBackwards()) {
      changeTrustLevelSelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, trust.name(), l10n("peerTrust." + trust.name()));
    }
    peerForm.addChild("br");
    peerForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {SUBMIT, "doChangeVisibility", l10n("changeVisibilityButton")});
    HTMLNode changeVisibilitySelect =
        peerForm.addChild(
            ELEMENT_SELECT,
            new String[] {"id", "name"},
            new String[] {CHANGE_VISIBILITY, CHANGE_VISIBILITY});
    for (FRIEND_VISIBILITY trust : FRIEND_VISIBILITY.values()) {
      changeVisibilitySelect.addChild(
          ELEMENT_OPTION, ATTR_VALUE, trust.name(), l10n("peerVisibility." + trust.name()));
    }
  }

  /**
   * Return the localized heading that labels the darknet friends table.
   *
   * <p>The title is intentionally short to keep table layouts compact while still providing clear
   * context when embedded inside larger pages or infoboxes. It is reused by multiple rendering
   * paths so the same wording appears in both standard and advanced layouts, reducing localization
   * overhead and preserving consistency when the table is refreshed after POST actions.
   *
   * @return localized string representing the section title for friends.
   */
  @Override
  protected String getPeerListTitle() {
    return l10n("myFriends");
  }

  /**
   * State that the toadlet processes POST requests containing friend references.
   *
   * <p>Returning {@code true} allows the base class to accept reference submissions alongside the
   * other actions handled here, enabling a single endpoint to cover both add-friend and bulk
   * maintenance flows. This keeps user bookmarks stable and ensures any CSRF protections or
   * authentication checks configured on the friends endpoint automatically apply to noderef
   * submissions as well.
   *
   * @return {@code true}, enabling noderef POST handling by the superclass.
   */
  @Override
  protected boolean acceptRefPosts() {
    return true;
  }

  /**
   * Provide the redirect target used after completing POST actions.
   *
   * <p>Using a single canonical location ensures browsers follow a standard post-redirect-get
   * cycle, preventing form resubmission warnings and keeping the navigation consistent with the
   * friends table URL. It also centralizes cache headers and content negotiation on one endpoint,
   * simplifying upstream proxy configuration and logging.
   *
   * @return canonical friends path used for redirect responses.
   */
  @Override
  protected String defaultRedirectLocation() {
    return path();
  }

  /**
   * Implement POST-side actions that are not covered by noderef submission.
   *
   * <p>The handler orchestrates bulk operations based on the submitted form parts: sending
   * confidential messages, toggling routing flags, updating trust or visibility, removing peers,
   * and handling transfer confirmations. Unrecognized submissions fall back to the GET view to
   * avoid user-visible errors. The method assumes form inputs follow the conventions established by
   * {@link #drawPeerActionSelectBox(HTMLNode, boolean)}.
   *
   * @param uri request URI used for contextual redirects after processing.
   * @param request multipart request containing action flags and selected peer identifiers.
   * @param ctx toadlet context that supplies page makers and is used to issue redirects.
   * @param logMINOR whether minor events should be logged by the superclass hooks.
   * @throws IOException if writing responses or redirects fails mid-stream.
   * @throws ToadletContextClosedException if the client disconnects while a reply is generated.
   * @throws RedirectException if the superclass chooses to redirect during fallback handling.
   */
  @Override
  protected void handleAltPost(URI uri, HTTPRequest request, ToadletContext ctx, boolean logMINOR)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (request.isPartSet("doSendMessageToPeers")) {
      handleSendMessageToPeers(request, ctx);
      return;
    }

    if (request.isPartSet(DO_ACTION)) {
      String action = request.getPartAsStringFailsafe(ACTION, 25);
      if (handleDoAction(action, request, ctx)) {
        return;
      }
    }

    if (request.isPartSet(CHANGE_TRUST) && request.isPartSet("doChangeTrust")) {
      handleChangeTrust(request);
      redirectHere(ctx);
      return;
    }

    if (request.isPartSet(CHANGE_VISIBILITY) && request.isPartSet("doChangeVisibility")) {
      handleChangeVisibility(request);
      redirectHere(ctx);
      return;
    }

    if (request.isPartSet(REMOVE)) {
      handleRemove(request, ctx);
      return;
    }

    if (request.isPartSet("acceptTransfer")) {
      handleTransfer(request, true);
      redirectHere(ctx);
      return;
    }

    if (request.isPartSet("rejectTransfer")) {
      handleTransfer(request, false);
      redirectHere(ctx);
      return;
    }

    this.handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
  }

  private void handleTransfer(HTTPRequest request, boolean acceptTransfer) {
    Long transferId = parseTransferId(request);
    if (transferId == null) {
      return;
    }
    DarknetPeerNode peer = findFirstSelectedPeer(request);
    if (peer == null) {
      return;
    }
    if (acceptTransfer) {
      peer.acceptTransfer(transferId);
    } else {
      peer.rejectTransfer(transferId);
    }
  }

  private Long parseTransferId(HTTPRequest request) {
    String idPart = request.getPartAsStringFailsafe("id", 32);
    try {
      return Long.parseLong(idPart);
    } catch (NumberFormatException _) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("Invalid transfer id: {}", idPart);
      }
      return null;
    }
  }

  private DarknetPeerNode findFirstSelectedPeer(HTTPRequest request) {
    for (DarknetPeerNode pn : node.getDarknetConnections()) {
      if (request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        return pn;
      }
    }
    return null;
  }

  private void handleChangeVisibility(HTTPRequest request) {
    FRIEND_VISIBILITY visibility =
        FRIEND_VISIBILITY.valueOf(request.getPartAsStringFailsafe(CHANGE_VISIBILITY, 10));
    forSelectedPeers(request, pn -> pn.setVisibility(visibility));
  }

  private void handleChangeTrust(HTTPRequest request) {
    FRIEND_TRUST trust = FRIEND_TRUST.valueOf(request.getPartAsStringFailsafe(CHANGE_TRUST, 10));
    forSelectedPeers(request, pn -> pn.setTrustLevel(trust));
  }

  private boolean handleDoAction(String action, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if ("update_notes".equals(action)) {
      handleUpdateNotes(request);
      redirectHere(ctx);
      return true;
    }

    Consumer<DarknetPeerNode> peerAction = SIMPLE_ACTIONS.get(action);
    if (peerAction != null) {
      forSelectedPeers(request, peerAction);
      redirectHere(ctx);
      return true;
    }

    if (REMOVE.equals(action)) {
      handleRemove(request, ctx);
      return true;
    }

    return false;
  }

  private void handleRemove(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Remove node");

    for (DarknetPeerNode pn : node.getDarknetConnections()) {
      if (!request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        if (LOG.isDebugEnabled()) LOG.debug("Part not set: node_{}", pn.hashCode());
      } else if (shouldRemovePeer(pn, request)) {
        node.removePeerConnection(pn);
        if (LOG.isDebugEnabled()) LOG.debug("Removed node: node_{}", pn.hashCode());
      } else {
        showRemovalConfirmation(ctx, pn);
        return;
      }
    }
    redirectHere(ctx);
  }

  private void showRemovalConfirmation(ToadletContext ctx, DarknetPeerNode pn)
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
    HTMLNode removeForm = ctx.addFormChild(content, path(), "removeConfirmForm");
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", NODE_PREFIX + pn.hashCode(), REMOVE});
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {SUBMIT, "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {SUBMIT, REMOVE, l10n(REMOVE)});
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "forceit", l10n("forceRemove")});

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean shouldRemovePeer(DarknetPeerNode pn, HTTPRequest request) {
    long oneWeekAgo = System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 7;
    return pn.timeLastConnectionCompleted() < oneWeekAgo
        || (pn.getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED)
        || request.isPartSet("forceit");
  }

  private void handleUpdateNotes(HTTPRequest request) {
    for (DarknetPeerNode pn : node.getDarknetConnections()) {
      String partName = PEER_PRIVATE_NOTE_PREFIX + pn.hashCode();
      if (!request.isPartSet(partName)) {
        continue;
      }
      String newNote = request.getPartAsStringFailsafe(partName, 250);
      if (!newNote.equals(pn.getPrivateDarknetCommentNote())) {
        pn.setPrivateDarknetCommentNote(newNote);
      }
    }
  }

  private void forSelectedPeers(HTTPRequest request, Consumer<DarknetPeerNode> action) {
    for (DarknetPeerNode pn : node.getDarknetConnections()) {
      if (request.isPartSet(NODE_PREFIX + pn.hashCode())) {
        action.accept(pn);
      }
    }
  }

  private void handleSendMessageToPeers(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("sendMessageTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HashMap<String, String> peers = new HashMap<>();
    for (DarknetPeerNode pn : node.getDarknetConnections()) {
      String nodePart = NODE_PREFIX + pn.hashCode();
      if (request.isPartSet(nodePart)) {
        String peerHash = String.valueOf(pn.hashCode());
        peers.putIfAbsent(peerHash, pn.getName());
      }
    }
    N2NTMToadlet.createN2NTMSendForm(ctx.isAdvancedModeEnabled(), contentNode, ctx, peers);
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void redirectHere(ToadletContext ctx) throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", FRIENDS_PATH);
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  /**
   * Identify the scope of this toadlet as darknet-only rather than opennet.
   *
   * <p>The return value informs the parent class which set of peers to query and which UI labels to
   * present. Returning {@code false} ensures opennet-specific options never appear on the friends
   * page.
   *
   * @return {@code false} because opennet peers are not handled here.
   */
  @Override
  protected boolean isOpennet() {
    return false;
  }

  /**
   * Provide additional column headers appended after the standard set.
   *
   * <p>Darknet connections do not require trailing columns beyond those defined in the base class,
   * so this implementation returns an empty array. Advanced mode status does not influence the
   * outcome, preserving a consistent column layout.
   *
   * @param advancedMode whether advanced mode is enabled for the current render.
   * @return an empty array, indicating no extra headers are added.
   */
  @Override
  SimpleColumn[] endColumnHeaders(boolean advancedMode) {
    return new SimpleColumn[0];
  }

  /**
   * Expose the URL path handled by this toadlet for routing purposes.
   *
   * <p>The path is shared across GET and POST handlers so form actions and links consistently
   * resolve to the friends' endpoint. Centralizing the path string here avoids duplication in
   * templates and makes it easy for callers to build absolute links when issuing redirects or
   * constructing downloadable noderef URLs.
   *
   * @return {@code "/friends/"}, the canonical path for darknet friend management.
   */
  @Override
  public String path() {
    return FRIENDS_PATH;
  }

  /**
   * Render the friends page or serve a peer noderef download when requested.
   *
   * <p>The method first checks whether the URI targets a specific friend reference ending in {@code
   * .fref}; if so, it streams the sanitized reference as an attachment. Otherwise, it defers to the
   * superclass to build the full darknet connections page. Callers are expected to provide a fully
   * populated {@link HTTPRequest} even when serving downloads so that advanced mode decisions
   * remain consistent.
   *
   * @param uri request URI to inspect for friend reference downloads.
   * @param request HTTP request wrapper carrying query parameters and advanced-mode state.
   * @param ctx toadlet context used to write the HTML page or attachment response.
   * @throws ToadletContextClosedException if the client disconnects during output.
   * @throws IOException if streaming the response fails.
   * @throws RedirectException if the superclass initiates a redirect during page handling.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (tryHandlePeerNoderef(uri, request, ctx)) return;
    super.handleMethodGET(uri, request, ctx);
  }

  private boolean tryHandlePeerNoderef(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (request == null) {
      return false;
    }
    return tryHandlePeerNoderef(uri, ctx);
  }

  private boolean tryHandlePeerNoderef(URI uri, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String path = uri.getPath();
    if (!path.endsWith(FREF_SUFFIX) || !path.startsWith(path() + FRIEND_PREFIX)) {
      return false;
    }

    String inputHashcodeString = path.substring((path() + FRIEND_PREFIX).length());
    inputHashcodeString =
        inputHashcodeString.substring(0, inputHashcodeString.length() - FREF_SUFFIX.length());
    int inputHashcode = parseHashcode(inputHashcodeString);
    if (inputHashcode == -1) {
      return false;
    }

    DarknetPeerNode peerNode = findPeerByHashcode(inputHashcode);
    if (peerNode == null) {
      return false;
    }

    SimpleFieldSet fs = peerNode.getFullNoderef();
    if (fs == null) return false;
    String filename = FileUtil.sanitizeFileNameWithExtras(peerNode.getName() + FREF_SUFFIX, "\" ");
    String content = fs.toString();
    MultiValueTable<String, String> extraHeaders =
        MultiValueTable.from(
            // Force download to disk
            "Content-Disposition", "attachment; filename=" + filename);
    this.writeReply(ctx, 200, "application/x-freenet-reference", "OK", extraHeaders, content);
    return true;
  }

  private int parseHashcode(String inputHashcodeString) {
    try {
      return Integer.parseInt(inputHashcodeString);
    } catch (NumberFormatException _) {
      return -1;
    }
  }

  private DarknetPeerNode findPeerByHashcode(int targetHashcode) {
    for (DarknetPeerNode peerNode : node.getDarknetConnections()) {
      if (peerNode.hashCode() == targetHashcode) {
        return peerNode;
      }
    }
    return null;
  }
}
