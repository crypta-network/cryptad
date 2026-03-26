package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessageSendStatus;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetUploadedFile;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles HTTP requests for sending node-to-node text messages from the web UI.
 *
 * <p>This toadlet renders the message composition form, validates inputs, and routes outgoing
 * messages to selected darknet peers. It also supports optional file offers, either by selecting a
 * local file on the node or by uploading a small file through the HTTP request. Requests are
 * redirected back to the friends page when the flow is not recognized or when permission checks
 * fail. Error responses are rendered as infoboxes so the user can retry without losing context.
 *
 * <p>The class delegates file browsing to {@link LocalFileN2NMToadlet} and routes peer lookup and
 * delivery through detached runtime SPI ports. It relies on the toadlet framework for request
 * threading and performs no additional synchronization. Message size and upload size are bounded,
 * and UI feedback is localized through {@link NodeL10n}.
 *
 * <ul>
 *   <li>Builds and serves the N2NTM compose form for selected peers.
 *   <li>Validates message size and optional file attachments.
 *   <li>Sends messages and records per-peer delivery status.
 * </ul>
 *
 * @see LocalFileN2NMToadlet
 * @see FProxyToadlet
 */
public class N2NTMToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(N2NTMToadlet.class);
  private static final String L10N_PREFIX = "N2NTMToadlet.";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_HREF = "href";
  private static final String ATTR_TITLE = "title";
  private static final String ATTR_VALUE = "value";
  private static final String INFOBOX_CONTENT_CLASS = "infobox-content";
  private static final String L10N_RETURN_TO_FRIENDS = "returnToFriends";
  private static final String L10N_FRIENDS = "friends";
  private static final String UPLOAD_PART = "n2nm-upload";
  private static final String TAG_INPUT = "input";
  private static final long DEFAULT_MAX_SIZE_BYTES = 1024L * 1024L;
  private static final int MESSAGE_HEAD_LIMIT = 1024;
  private static final int MESSAGE_LIMIT = 1024 * 128;

  private final DarknetConnectionsPort darknetConnections;
  private final DarknetMessagingPort darknetMessaging;
  private final LocalFileN2NMToadlet browser;

  /**
   * Creates the toadlet with access to node state and HTTP utilities.
   *
   * <p>The instance keeps references to the detached runtime ports and its browser toadlet so it
   * can resolve peers, send messages, open the local file browser, and emit localized responses.
   * Callers should provide the same {@link HighLevelSimpleClient} used by other toadlets to keep
   * configuration and permissions consistent. The constructor performs no I/O and does not register
   * itself; registration is managed elsewhere by the HTTP subsystem.
   *
   * @param runtimePorts runtime aggregate that exposes detached peer lookup and messaging ports.
   * @param browser browser toadlet used for local file selection.
   * @param client HTTP client wrapper used by the base {@link Toadlet}.
   */
  protected N2NTMToadlet(
      RuntimePorts runtimePorts, LocalFileN2NMToadlet browser, HighLevelSimpleClient client) {
    super(client);
    RuntimePorts ports = Objects.requireNonNull(runtimePorts, "runtimePorts");
    this.darknetConnections = Objects.requireNonNull(ports.darknetConnections());
    this.darknetMessaging = Objects.requireNonNull(ports.darknetMessaging());
    this.browser = Objects.requireNonNull(browser, "browser");
  }

  /**
   * Returns the file-browsing toadlet used for local file selection.
   *
   * <p>This exposes a companion toadlet that provides the UI for selecting a local file on the
   * node. Callers typically register the returned instance alongside this toadlet so the "Browse"
   * button can redirect users to a compatible endpoint. The returned instance is created during
   * construction and is stable for the lifetime of this toadlet.
   *
   * @return the associated browser toadlet instance, owned by this class.
   */
  public Toadlet getBrowser() {
    return browser;
  }

  /**
   * Handles GET requests for the N2NTM send page.
   *
   * <p>The handler first enforces full-access permissions. If the request includes a peer hashcode
   * parameter, it renders a pre-targeted sending form or a peer-not-found error when the hash does
   * not resolve. Otherwise, it redirects to the friends page so the normal N2N navigation remains
   * consistent. This method does not mutate a persistent state; it only renders HTML responses or
   * performs a redirect.
   *
   * @param uri request URI used for trace logging and path introspection.
   * @param request HTTP request containing query parameters and parts.
   * @param ctx toadlet context used for permissions and response handling.
   * @throws ToadletContextClosedException if the HTTP context closes mid-response.
   * @throws IOException if response writing fails due to I/O issues.
   * @throws RedirectException if a redirect is required for the request flow.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (LOG.isTraceEnabled()) {
      LOG.trace("handleMethodGET path={}", uri == null ? null : uri.getPath());
    }
    if (!ctx.checkFullAccess(this)) return;

    if (request.isParameterSet("peernode_hashcode")) {
      handlePeerHashcodeRequest(request, ctx);
      return;
    }
    sendFriendsRedirect(ctx);
  }

  private void handlePeerHashcodeRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("sendMessage"), ctx);
    HTMLNode contentNode = page.getContentNode();

    String inputHashcodeString = request.getParam("peernode_hashcode");
    int inputHashcode = -1;
    try {
      inputHashcode = Integer.parseInt(inputHashcodeString);
    } catch (NumberFormatException _) {
      // ignore here, handle below
    }
    DarknetConnectionPeerSnapshot peer =
        inputHashcode == -1 ? null : findPeerBySelectionToken(inputHashcode);
    if (peer == null) {
      contentNode.addChild(
          createPeerErrorInfobox(
              l10n("peerNotFoundTitle"), l10nPeerNotFoundWithHash(inputHashcodeString)));
      this.writeHTMLReply(ctx, 200, "OK", page.generate());
      return;
    }
    Map<String, String> peers = new LinkedHashMap<>();
    peers.put(inputHashcodeString, peer.displayName());
    createN2NTMSendForm(ctx.isAdvancedModeEnabled(), contentNode, ctx, peers);
    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private DarknetConnectionPeerSnapshot findPeerBySelectionToken(int selectionToken) {
    for (DarknetConnectionPeerSnapshot peer : darknetConnections.listPeers()) {
      if (peer.selectionToken() == selectionToken) {
        return peer;
      }
    }
    return null;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  private static String l10nPeerNotFoundWithHash(String hash) {
    return NodeL10n.getBase()
        .getString(
            L10N_PREFIX + "peerNotFoundWithHash", new String[] {"hash"}, new String[] {hash});
  }

  private static String l10nTooLarge(long attempt, long limit) {
    return NodeL10n.getBase()
        .getString(
            L10N_PREFIX + "tooLarge",
            new String[] {"attempt", "limit"},
            new String[] {SizeUtil.formatSize(attempt, true), SizeUtil.formatSize(limit, true)});
  }

  /*
   * File size limit is 1 MiB (1024*1024 bytes) or 5% of maximum Java memory, whichever is greater.
   */
  private static long maxSize() {
    long memory = NodeStarter.getMemoryLimitBytes();
    if (memory == Long.MAX_VALUE || memory <= 0) return DEFAULT_MAX_SIZE_BYTES;
    long maxMem = Math.round(0.05 * memory);
    return Math.max(maxMem, DEFAULT_MAX_SIZE_BYTES);
  }

  private static HTMLNode createPeerErrorInfobox(String header, String message) {
    HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, "infobox infobox-error");
    infobox.addChild("div", ATTR_CLASS, "infobox-header", header);
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    infoboxContent.addChild("#", message);
    HTMLNode list = infoboxContent.addChild("ul");
    Toadlet.addHomepageLink(list);
    list.addChild("li")
        .addChild(
            "a",
            new String[] {ATTR_HREF, ATTR_TITLE},
            new String[] {FProxyToadlet.FRIENDS_PATH, l10n(L10N_RETURN_TO_FRIENDS)},
            l10n(L10N_FRIENDS));
    return infobox;
  }

  /**
   * Handles POST requests for sending a node-to-node message.
   *
   * <p>The handler enforces full-access permissions, then checks which form action was submitted. A
   * browse action triggers a redirect to the local file browser. A send action validates the
   * message and optional attachment, sends file offers when applicable, and renders per-peer
   * delivery status. If the request does not match any supported action, it falls back to a
   * friends-page redirect. Responses are HTML, and failures are surfaced as localized infobox
   * messages without throwing user-visible exceptions.
   *
   * @param uri request URI used for trace logging and path introspection.
   * @param request HTTP request containing multipart data and parameters.
   * @param ctx toadlet context used for permissions and response handling.
   * @throws ToadletContextClosedException if the HTTP context closes mid-response.
   * @throws IOException if response writing fails due to I/O issues.
   * @throws RedirectException if a redirect is required for the request flow.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (LOG.isTraceEnabled()) {
      LOG.trace("handleMethodPOST path={}", uri == null ? null : uri.getPath());
    }
    if (!ctx.checkFullAccess(this)) return;

    // The browse button clicked. Redirect.
    if (request.isPartSet("n2nm-browse")) {
      handleBrowseRedirect();
      return;
    }

    if (isSendRequest(request)) {
      processSendRequest(request, ctx);
      return;
    }
    sendFriendsRedirect(ctx);
  }

  private boolean isSendRequest(HTTPRequest request) {
    return request.isPartSet(UPLOAD_PART)
        || request.isPartSet(LocalFileBrowserToadlet.SELECT_FILE)
        || request.isPartSet("send");
  }

  private void handleBrowseRedirect() throws RedirectException {
    try {
      throw new RedirectException(browser.path());
    } catch (URISyntaxException _) {
      // Should be impossible because the browser is registered with .PATH.
    }
  }

  private void processSendRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String message = getMessageOrReply(request, ctx);
    if (message == null) return;

    String messageHead = message.substring(0, Math.min(message.length(), MESSAGE_HEAD_LIMIT));
    PageNode page = ctx.getPageMaker().getPageNode(l10n("processingSend"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode peerTableInfobox = contentNode.addChild("div", ATTR_CLASS, "infobox infobox-normal");
    SendRequestContext sendRequestContext =
        new SendRequestContext(request, peerTableInfobox, page, ctx, message);
    List<DarknetConnectionPeerSnapshot> selectedPeers = listSelectedPeers(request);
    FileSelection selectedFile =
        resolveSelectedFile(
            sendRequestContext.request(),
            sendRequestContext.peerTableInfobox(),
            sendRequestContext.page(),
            sendRequestContext.ctx());
    if (selectedFile.handled()) {
      return;
    }
    UploadSelection uploadSelection =
        resolveUploadedFile(sendRequestContext, selectedFile.file(), selectedPeers.isEmpty());
    if (uploadSelection.handled()) {
      return;
    }
    HTMLNode peerTable = buildPeerStatusTable(peerTableInfobox);
    for (DarknetConnectionPeerSnapshot peer : selectedPeers) {
      try {
        DarknetMessageSendStatus status =
            sendComposedMessageOrWriteFailureResponse(
                sendRequestContext,
                peer,
                message,
                selectedFile.file(),
                uploadSelection.upload(),
                messageHead);
        if (status == null) {
          return;
        }
        addPeerStatusRow(peerTable, peer.displayName(), status, message);
      } catch (UnknownPeerException | DarknetPeerRequiredException e) {
        LOG.warn("Rendering queued N2NTM status for unresolved peer {}", peer.nodeIdentifier(), e);
        addPeerStatusRow(peerTable, peer.displayName(), DarknetMessageSendStatus.QUEUED, message);
      }
    }
    addMessageAndReturnLinks(peerTableInfobox, message);
    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private List<DarknetConnectionPeerSnapshot> listSelectedPeers(HTTPRequest request) {
    List<DarknetConnectionPeerSnapshot> selectedPeers = new ArrayList<>();
    for (DarknetConnectionPeerSnapshot peer : darknetConnections.listPeers()) {
      if (request.isPartSet("node_" + peer.selectionToken())) {
        selectedPeers.add(peer);
      }
    }
    return List.copyOf(selectedPeers);
  }

  private String getMessageOrReply(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String message = request.getPartAsStringFailsafe("message", 1024 * 1024).trim();
    if (message.length() > MESSAGE_LIMIT) {
      this.writeTextReply(ctx, 400, "Bad request", l10n("tooLong"));
      return null;
    }
    return message;
  }

  private FileSelection resolveSelectedFile(
      HTTPRequest request, HTMLNode peerTableInfobox, PageNode page, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet(LocalFileBrowserToadlet.SELECT_FILE)) {
      return new FileSelection(null, false);
    }
    String fnam = request.getPartAsStringFailsafe("filename", 1024);
    if (fnam != null && !fnam.isEmpty()) {
      File filename = new File(fnam);
      if (filename.exists() && filename.canRead()) {
        return new FileSelection(filename, false);
      }
      peerTableInfobox.addChild("#", l10n("noSuchFileOrCannotRead"));
      Toadlet.addHomepageLink(peerTableInfobox);
      this.writeHTMLReply(ctx, 400, "OK", page.generate());
      return new FileSelection(null, true);
    }
    return new FileSelection(null, false);
  }

  private UploadSelection resolveUploadedFile(
      SendRequestContext requestContext, File selectedFile, boolean noSelectedPeers)
      throws ToadletContextClosedException, IOException {
    if (selectedFile != null
        || noSelectedPeers
        || !requestContext.request().isPartSet(UPLOAD_PART)) {
      return new UploadSelection(null, false);
    }
    try {
      HTTPUploadedFile file = requestContext.request().getUploadedFile(UPLOAD_PART);
      if (file == null || file.getFilename().isEmpty()) {
        return new UploadSelection(null, false);
      }
      Bucket uploadData = file.getData();
      long size = uploadData.size();
      if (size <= 0) {
        return new UploadSelection(null, false);
      }
      long limit = maxSize();
      if (size > limit) {
        addTooLargeUploadResponse(
            requestContext.peerTableInfobox(),
            size,
            limit,
            requestContext.message(),
            requestContext.ctx(),
            requestContext.page());
        return new UploadSelection(null, true);
      }
      return new UploadSelection(
          new DarknetUploadedFile(
              file.getFilename(),
              file.getContentType(),
              size,
              uploadData::getInputStreamUnbuffered),
          false);
    } catch (IOException _) {
      return new UploadSelection(null, writeSendFailureResponse(requestContext, "uploadFailed"));
    }
  }

  private DarknetMessageSendStatus sendComposedMessageOrWriteFailureResponse(
      SendRequestContext requestContext,
      DarknetConnectionPeerSnapshot peer,
      String message,
      File filename,
      DarknetUploadedFile upload,
      String messageHead)
      throws ToadletContextClosedException,
          IOException,
          UnknownPeerException,
          DarknetPeerRequiredException {
    try {
      return darknetMessaging.sendComposedMessage(
          peer.nodeIdentifier(), message, filename, upload, messageHead);
    } catch (IOException e) {
      if (filename != null) {
        writeSendFailureResponse(requestContext, "noSuchFileOrCannotRead");
        return null;
      }
      if (upload != null) {
        writeSendFailureResponse(requestContext, "uploadFailed");
        return null;
      }
      throw e;
    }
  }

  private boolean writeSendFailureResponse(SendRequestContext requestContext, String l10nKey)
      throws ToadletContextClosedException, IOException {
    requestContext.peerTableInfobox().addChild("#", l10n(l10nKey));
    Toadlet.addHomepageLink(requestContext.peerTableInfobox());
    addUnsentMessageTextInfo(requestContext.peerTableInfobox(), requestContext.message());
    this.writeHTMLReply(requestContext.ctx(), 200, "OK", requestContext.page().generate());
    return true;
  }

  private void addTooLargeUploadResponse(
      HTMLNode peerTableInfobox,
      long size,
      long limit,
      String message,
      ToadletContext ctx,
      PageNode page)
      throws ToadletContextClosedException, IOException {
    peerTableInfobox.addChild("#", l10nTooLarge(size, limit));
    HTMLNode list = peerTableInfobox.addChild("ul");
    Toadlet.addHomepageLink(list);
    list.addChild("li")
        .addChild(
            "a",
            new String[] {ATTR_HREF, ATTR_TITLE},
            new String[] {FProxyToadlet.FRIENDS_PATH, l10n(L10N_RETURN_TO_FRIENDS)},
            l10n(L10N_FRIENDS));
    addUnsentMessageTextInfo(peerTableInfobox, message);
    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private HTMLNode buildPeerStatusTable(HTMLNode peerTableInfobox) {
    HTMLNode peerTable = peerTableInfobox.addChild("table", ATTR_CLASS, "n2ntm-send-statuses");
    HTMLNode peerTableHeaderRow = peerTable.addChild("tr");
    peerTableHeaderRow.addChild("th", l10n("peerName"));
    peerTableHeaderRow.addChild("th", l10n("sendStatus"));
    return peerTable;
  }

  private void addPeerStatusRow(
      HTMLNode peerTable, String peerDisplayName, DarknetMessageSendStatus status, String message) {
    SendStatusInfo statusInfo =
        switch (status) {
          case DELAYED ->
              new SendStatusInfo(
                  l10n("delayedTitle"), l10n("delayed"), "n2ntm-send-delayed", "Sent");
          case SENT ->
              new SendStatusInfo(l10n("sentTitle"), l10n("sent"), "n2ntm-send-sent", "Sent");
          default ->
              new SendStatusInfo(
                  l10n("queuedTitle"), l10n("queued"), "n2ntm-send-queued", "Queued");
        };
    LOG.info("{} N2NTM to '{}': {}", statusInfo.logAction(), peerDisplayName, message);
    HTMLNode peerRow = peerTable.addChild("tr");
    peerRow.addChild("td", ATTR_CLASS, "peer-name").addChild("#", peerDisplayName);
    peerRow
        .addChild("td", ATTR_CLASS, statusInfo.cssClass())
        .addChild(
            "span",
            new String[] {ATTR_TITLE, "style"},
            new String[] {statusInfo.longTitle(), "border-bottom: 1px dotted; cursor: help;"},
            statusInfo.shortTitle());
  }

  private void addMessageAndReturnLinks(HTMLNode peerTableInfobox, String message) {
    HTMLNode infoboxContent = peerTableInfobox.addChild("div", ATTR_CLASS, "n2ntm-message-text");
    infoboxContent.addChild("#", message);
    HTMLNode list = peerTableInfobox.addChild("ul");
    Toadlet.addHomepageLink(list);
    list.addChild("li")
        .addChild(
            "a",
            new String[] {ATTR_HREF, ATTR_TITLE},
            new String[] {FProxyToadlet.FRIENDS_PATH, l10n(L10N_RETURN_TO_FRIENDS)},
            l10n(L10N_FRIENDS));
  }

  private void sendFriendsRedirect(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers =
        MultiValueTable.from("Location", FProxyToadlet.FRIENDS_PATH);
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  /**
   * Appends explanatory text and the unsent message to the given node.
   *
   * <p>This helper renders a short localized explanation followed by the raw message body so the
   * user can copy or edit the content after a failed sending. The message is inserted as plain
   * text, not HTML, so any markup-like characters are treated as content. The caller owns the
   * container node and decides where the paragraphs appear within the page layout.
   *
   * @param node HTML container that receives the explanatory paragraphs.
   * @param message original message content to re-display verbatim.
   */
  public static void addUnsentMessageTextInfo(HTMLNode node, String message) {
    node.addChild("p", l10n("unsentMessageText"));
    node.addChild("p", message);
  }

  private record FileSelection(File file, boolean handled) {}

  private record UploadSelection(DarknetUploadedFile upload, boolean handled) {}

  private record SendRequestContext(
      HTTPRequest request,
      HTMLNode peerTableInfobox,
      PageNode page,
      ToadletContext ctx,
      String message) {}

  private record SendStatusInfo(
      String shortTitle, String longTitle, String cssClass, String logAction) {}

  /**
   * Builds the N2NTM send form and inserts it into the page content.
   *
   * <p>The form lists target peers, collects the message body, and optionally exposes file
   * attachment controls when advanced mode is enabled. Hidden fields encode the selected peers so
   * the later POST can map each checkbox to a peer hashcode. In advanced mode, the form shows both
   * a local file browser button and a file upload input, plus a size warning derived from the
   * runtime memory limit. The caller supplies the content node and toadlet context used to create a
   * correctly scoped form action.
   *
   * @param advancedMode whether to include file-attachment controls and size warning.
   * @param contentNode HTML container that receives the form and its infobox wrapper.
   * @param ctx toadlet context used to create a properly configured form.
   * @param peers map of peer hashcodes to display names for the target list.
   */
  public static void createN2NTMSendForm(
      boolean advancedMode, HTMLNode contentNode, ToadletContext ctx, Map<String, String> peers) {
    HTMLNode infobox =
        contentNode.addChild(
            "div", new String[] {ATTR_CLASS, "id"}, new String[] {"infobox", "n2nbox"});
    infobox.addChild("div", ATTR_CLASS, "infobox-header", l10n("sendMessage"));
    HTMLNode messageTargets = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    messageTargets.addChild("p", l10n("composingMessageLabel"));
    HTMLNode messageTargetList = messageTargets.addChild("ul");
    // Iterate peers
    for (String peerName : peers.values()) {
      messageTargetList.addChild("li", peerName);
    }
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    HTMLNode messageForm = ctx.addFormChild(infoboxContent, "/send_n2ntm/", "sendN2NTMForm");
    // Iterate peers
    for (String peerNodeHash : peers.keySet()) {
      messageForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"hidden", "node_" + peerNodeHash, "1"});
    }
    messageForm.addChild(
        "textarea",
        new String[] {"id", "name", "rows", "cols"},
        new String[] {"n2ntmtext", "message", "8", "74"});
    if (advancedMode) {
      messageForm.addChild("br");
      messageForm.addChild("#", NodeL10n.getBase().getString("N2NTMToadlet.mayAttachFile"));
      if (ctx.isAllowedFullAccess()) {
        messageForm.addChild("br");
        messageForm.addChild(
            "#", NodeL10n.getBase().getString("QueueToadlet.insertFileBrowseLabel") + ": ");
        messageForm.addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {
              "submit",
              "n2nm-browse",
              NodeL10n.getBase().getString("QueueToadlet.insertFileBrowseButton") + "..."
            });
        messageForm.addChild("br");
      }
      messageForm.addChild(
          "#",
          NodeL10n.getBase()
              .getString(
                  "N2NTMToadlet.sizeWarning", "limit", SizeUtil.formatSize(maxSize(), true)));
      messageForm.addChild("br");
      messageForm.addChild(
          "#", NodeL10n.getBase().getString("QueueToadlet.insertFileLabel") + ": ");
      messageForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"file", UPLOAD_PART, ""});
      messageForm.addChild("br");
    }
    messageForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "send", l10n("sendMessageShort")});
  }

  /**
   * Returns the base path handled by this toadlet.
   *
   * <p>The path is used by the HTTP framework to route requests to this toadlet and by form actions
   * created in {@link #createN2NTMSendForm(boolean, HTMLNode, ToadletContext, Map)}. The value is
   * constant and does not depend on node configuration or request state. Callers should treat it as
   * a stable routing key and avoid constructing variants with trailing segments, since those are
   * handled by separate toadlets or redirects.
   *
   * @return the URL path segment for the sending N2NTM endpoint.
   */
  @Override
  public String path() {
    return "/send_n2ntm/";
  }
}
