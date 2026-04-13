package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.UnknownPeerException;
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
 * <p>This toadlet presents the list of trusted darknet peers. It lets users adjust trust and
 * visibility settings and trigger bulk actions such as enabling, disabling, or removing peers. It
 * reuses the shared table rendering logic from {@link ConnectionsToadlet}. It also specializes the
 * page for darknet-only concepts like private notes, friend references, and transfer confirmations.
 *
 * <p>Typical callers route HTTP GET and POST traffic from the node's web interface to this class.
 * The toadlet builds HTML structures with {@link network.crypta.support.HTMLNode} helpers. It
 * delegates friends-page peer lookup, updates, removal, noderef export, and transfer decisions
 * through runtime SPI ports. The node-to-node message workflow itself remains in {@link
 * N2NTMToadlet}; this class only builds the detached target map that the legacy compose form still
 * expects.
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
  private static final Map<String, DarknetPeerSettingsUpdate> SIMPLE_ACTIONS =
      Map.ofEntries(
          Map.entry("enable", peerSettingsUpdate(Boolean.FALSE, null, null, null, null, null)),
          Map.entry("disable", peerSettingsUpdate(Boolean.TRUE, null, null, null, null, null)),
          Map.entry(
              "set_burst_only", peerSettingsUpdate(null, null, Boolean.TRUE, null, null, null)),
          Map.entry(
              "clear_burst_only", peerSettingsUpdate(null, null, Boolean.FALSE, null, null, null)),
          Map.entry(
              "set_ignore_source_port",
              peerSettingsUpdate(null, null, null, Boolean.TRUE, null, null)),
          Map.entry(
              "clear_ignore_source_port",
              peerSettingsUpdate(null, null, null, Boolean.FALSE, null, null)),
          Map.entry(
              "set_dont_route", peerSettingsUpdate(null, null, null, null, null, Boolean.FALSE)),
          Map.entry(
              "clear_dont_route", peerSettingsUpdate(null, null, null, null, null, Boolean.TRUE)),
          Map.entry(
              "set_listen_only", peerSettingsUpdate(null, Boolean.TRUE, null, null, null, null)),
          Map.entry(
              "clear_listen_only", peerSettingsUpdate(null, Boolean.FALSE, null, null, null, null)),
          Map.entry(
              "set_allow_local", peerSettingsUpdate(null, null, null, null, Boolean.TRUE, null)),
          Map.entry(
              "clear_allow_local",
              peerSettingsUpdate(null, null, null, null, Boolean.FALSE, null)));
  private final DarknetConnectionsPort darknetConnectionsPort;
  private final LifecyclePort lifecyclePort;
  private final PeerPort peerPort;

  DarknetConnectionsToadlet(
      ConnectionsToadletRuntimePorts runtimePorts, DarknetConnectionsPort darknetConnectionsPort) {
    super(runtimePorts);
    this.darknetConnectionsPort = darknetConnectionsPort;
    this.lifecyclePort = runtimePorts.lifecyclePort();
    this.peerPort = runtimePorts.peerPort();
  }

  private static DarknetPeerSettingsUpdate peerSettingsUpdate(
      Boolean disabled,
      Boolean listenOnly,
      Boolean burstOnly,
      Boolean ignoreSourcePort,
      Boolean allowLocalAddresses,
      Boolean routingEnabled) {
    return new DarknetPeerSettingsUpdate(
        disabled,
        listenOnly,
        burstOnly,
        ignoreSourcePort,
        allowLocalAddresses,
        routingEnabled,
        null,
        null);
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  /**
   * Select the local node's public darknet reference view for distribution.
   *
   * <p>The shared base class uses this selector to export a detached noderef snapshot through the
   * runtime SPI before rendering the noderef box or serving `myref.*` downloads.
   *
   * @return public darknet noderef view used by the Connections page.
   */
  @Override
  protected NodeReferenceView noderefView() {
    return NodeReferenceView.DARKNET_PUBLIC;
  }

  /**
   * Determine whether the page should include the self-noderef download box.
   *
   * <p>The box is useful for power users distributing their own references but can overwhelm new
   * users. By tying visibility to the advanced mode flag, the method keeps the standard workflow
   * simple while still giving experienced operators quick access to their public noderef without
   * navigating away from the Friends page.
   *
   * @param advancedModeEnabled whether the user interface is currently in advanced mode.
   * @return {@code true} when the noderef box should be rendered alongside the Friends table.
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
   * so the Actions box is never hidden. The contained controls gate advanced operations internally
   * rather than being removed from the DOM.
   *
   * @return {@code true}, signaling callers to render the Actions box unconditionally.
   */
  @Override
  protected boolean showPeerActionsBox() {
    return true;
  }

  /**
   * Append the select box and buttons that drive bulk peer operations for the Friends list.
   *
   * <p>The method constructs a form section containing send-message, note-update, trust,
   * visibility, and removal actions. When advanced mode is active, additional toggles expose
   * routing and transport flags that may disrupt connectivity; these options are intentionally
   * hidden from basic users. The controls rely on the parent form to provide checkbox selections
   * whose names follow the {@code node_<hashcode>} convention.
   *
   * @param peerForm the form node to which controls are appended; must already exist in the page.
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
    DarknetPeerFormOptions.addTrustOptions(changeTrustLevelSelect);
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
    DarknetPeerFormOptions.addVisibilityOptions(changeVisibilitySelect);
  }

  /**
   * State that the toadlet processes POST requests containing friend references.
   *
   * <p>Returning {@code true} allows the base class to accept reference submissions alongside the
   * other actions handled here, enabling a single endpoint to cover both add-friend and bulk
   * maintenance flows. This keeps user bookmarks stable and ensures any CSRF protections or
   * authentication checks configured on the Friends endpoint automatically apply to noderef
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
   * Friends table URL. It also centralizes cache headers and content negotiation on one endpoint,
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
    DarknetConnectionPeerSnapshot peer = findFirstSelectedPeer(request);
    if (peer == null) {
      return;
    }
    try {
      if (acceptTransfer) {
        darknetConnectionsPort.acceptTransfer(peer.nodeIdentifier(), transferId);
      } else {
        darknetConnectionsPort.rejectTransfer(peer.nodeIdentifier(), transferId);
      }
    } catch (UnknownPeerException | DarknetPeerRequiredException e) {
      LOG.warn(
          "Failed to {} transfer {} for darknet peer {}",
          acceptTransfer ? "accept" : "reject",
          transferId,
          peer.nodeIdentifier(),
          e);
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

  private DarknetConnectionPeerSnapshot findFirstSelectedPeer(HTTPRequest request) {
    for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
      if (request.isPartSet(NODE_PREFIX + peer.selectionToken())) {
        return peer;
      }
    }
    return null;
  }

  private void handleChangeVisibility(HTTPRequest request) {
    PeerVisibility visibility =
        PeerVisibility.valueOf(request.getPartAsStringFailsafe(CHANGE_VISIBILITY, 10));
    applyUpdateToSelectedPeers(
        request,
        new DarknetPeerSettingsUpdate(null, null, null, null, null, null, null, visibility));
  }

  private void handleChangeTrust(HTTPRequest request) {
    PeerTrust trust = PeerTrust.valueOf(request.getPartAsStringFailsafe(CHANGE_TRUST, 10));
    applyUpdateToSelectedPeers(
        request, new DarknetPeerSettingsUpdate(null, null, null, null, null, null, trust, null));
  }

  private boolean handleDoAction(String action, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if ("update_notes".equals(action)) {
      handleUpdateNotes(request);
      redirectHere(ctx);
      return true;
    }

    DarknetPeerSettingsUpdate peerAction = SIMPLE_ACTIONS.get(action);
    if (peerAction != null) {
      applyUpdateToSelectedPeers(request, peerAction);
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

    boolean forceRemoval = request.isPartSet("forceit");
    for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
      if (!request.isPartSet(NODE_PREFIX + peer.selectionToken())) {
        logUnselectedPeer(peer);
      } else if (forceRemoval || peer.removableWithoutForce()) {
        removePeer(peer);
      } else {
        showRemovalConfirmation(ctx, peer);
        return;
      }
    }
    redirectHere(ctx);
  }

  private void logUnselectedPeer(DarknetConnectionPeerSnapshot peer) {
    if (LOG.isDebugEnabled()) LOG.debug("Part not set: node_{}", peer.selectionToken());
  }

  private void removePeer(DarknetConnectionPeerSnapshot peer) {
    try {
      peerPort.removeByIdentity(peer.nodeIdentifier());
      if (LOG.isDebugEnabled()) LOG.debug("Removed node: node_{}", peer.selectionToken());
    } catch (UnknownPeerException e) {
      LOG.warn("Failed to remove darknet peer {}", peer.nodeIdentifier(), e);
    }
  }

  private void showRemovalConfirmation(ToadletContext ctx, DarknetConnectionPeerSnapshot peer)
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
                    new String[] {peer.displayName()}));
    HTMLNode removeForm = ctx.addFormChild(content, path(), "removeConfirmForm");
    removeForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", NODE_PREFIX + peer.selectionToken(), REMOVE});
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

  private void handleUpdateNotes(HTTPRequest request) {
    for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
      String partName = PEER_PRIVATE_NOTE_PREFIX + peer.selectionToken();
      if (!request.isPartSet(partName)) {
        continue;
      }
      String newNote = request.getPartAsStringFailsafe(partName, 250);
      if (!newNote.equals(peer.privateNoteText())) {
        writePrivateDarknetCommentByIdentity(peer.nodeIdentifier(), newNote);
      }
    }
  }

  private void forSelectedPeers(
      HTTPRequest request, Consumer<DarknetConnectionPeerSnapshot> action) {
    for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
      if (request.isPartSet(NODE_PREFIX + peer.selectionToken())) {
        action.accept(peer);
      }
    }
  }

  private void applyUpdateToSelectedPeers(HTTPRequest request, DarknetPeerSettingsUpdate update) {
    if (update.isEmpty()) {
      return;
    }
    forSelectedPeers(request, peer -> updateDarknetPeerByIdentity(peer.nodeIdentifier(), update));
  }

  private void updateDarknetPeerByIdentity(String peerIdentity, DarknetPeerSettingsUpdate update) {
    try {
      peerPort.updateDarknetPeerByIdentity(peerIdentity, update);
    } catch (UnknownPeerException | DarknetPeerRequiredException | RuntimeException e) {
      LOG.warn("Failed to update darknet peer {}", peerIdentity, e);
    }
  }

  private void writePrivateDarknetCommentByIdentity(String peerIdentity, String newNote) {
    try {
      peerPort.writePrivateDarknetCommentByIdentity(peerIdentity, newNote);
    } catch (UnknownPeerException | DarknetPeerRequiredException | RuntimeException e) {
      LOG.warn("Failed to update private note for darknet peer {}", peerIdentity, e);
    }
  }

  private void handleSendMessageToPeers(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("sendMessageTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    Map<String, String> peers = new LinkedHashMap<>();
    for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
      String nodePart = NODE_PREFIX + peer.selectionToken();
      if (request.isPartSet(nodePart)) {
        String peerHash = String.valueOf(peer.selectionToken());
        peers.putIfAbsent(peerHash, peer.displayName());
      }
    }
    N2NTMToadlet.createN2NTMSendForm(
        ctx.isAdvancedModeEnabled(), contentNode, ctx, peers, lifecyclePort.memoryLimitBytes());
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
   * present. Returning {@code false} ensures opennet-specific options never appear on the Friends
   * page.
   *
   * @return {@code false} because opennet peers are not handled here.
   */
  @Override
  protected boolean isOpennet() {
    return false;
  }

  /**
   * Expose the URL path handled by this toadlet for routing purposes.
   *
   * <p>The path is shared across GET and POST handlers, so form actions and links consistently
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
   * Render the Friends page or serve a peer noderef download when requested.
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
   * @throws IOException if streaming, the response fails.
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

    DarknetConnectionPeerSnapshot peer = findPeerByHashcode(inputHashcode);
    if (peer == null) {
      return false;
    }

    NodeReferenceSnapshot snapshot =
        darknetConnectionsPort.exportPeerReference(inputHashcode).orElse(null);
    if (snapshot == null) {
      return false;
    }

    SimpleFieldSet fs = toSimpleFieldSet(snapshot.root());
    String filename = FileUtil.sanitizeFileNameWithExtras(peer.displayName() + FREF_SUFFIX, "\" ");
    String content = fs.toString();
    MultiValueTable<String, String> extraHeaders =
        MultiValueTable.from(
            // Force download to disk
            "Content-Disposition", "attachment; filename=" + filename);
    this.writeReply(
        ctx, ReplyHeaders.of(200, "OK", "application/x-freenet-reference", extraHeaders), content);
    return true;
  }

  private int parseHashcode(String inputHashcodeString) {
    try {
      return Integer.parseInt(inputHashcodeString);
    } catch (NumberFormatException _) {
      return -1;
    }
  }

  private DarknetConnectionPeerSnapshot findPeerByHashcode(int targetHashcode) {
    for (DarknetConnectionPeerSnapshot peer : darknetConnectionsPort.listPeers()) {
      if (peer.selectionToken() == targetHashcode) {
        return peer;
      }
    }
    return null;
  }

  private static SimpleFieldSet toSimpleFieldSet(NodeFieldSet source) {
    SimpleFieldSet target = new SimpleFieldSet(true);
    for (Map.Entry<String, String> entry : source.directValues().entrySet()) {
      target.putSingle(entry.getKey(), entry.getValue());
    }
    for (Map.Entry<String, NodeFieldSet> entry : source.directSubsets().entrySet()) {
      target.tput(entry.getKey(), toSimpleFieldSet(entry.getValue()));
    }
    return target;
  }
}
