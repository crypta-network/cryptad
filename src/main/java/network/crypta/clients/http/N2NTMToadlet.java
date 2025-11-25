package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStarter;
import network.crypta.node.PeerManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Toadlet responsible for composing and sending node-to-node text messages (N2NTM) and optional
 * file offers to trusted peers through the web interface.
 *
 * <p>The handler renders a form where users pick darknet friends, type a message, and, in advanced
 * mode, attach either a local file or an uploaded payload. It enforces message length limits, caps
 * attachments to the larger of 1&nbsp;MiB or five percent of the memory ceiling, and invokes {@link
 * DarknetPeerNode#sendTextFeed(String)} plus the peer file-offer routine for each selected peer.
 * The UI records per-peer statuses so queued, sent, or delayed outcomes stay visible alongside the
 * original text.
 *
 * <p>State is limited to the embedded file browser toadlet and friends redirect path, so instances
 * stay safe to reuse across concurrent requests when the backing {@link Node} and {@link
 * HighLevelSimpleClient} are thread-safe. Use it when you need a simple web workflow that pairs
 * short text with optional binary offers without exposing transport details.
 */
public class N2NTMToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(N2NTMToadlet.class);

  private static final String L10N_PREFIX = "N2NTMToadlet.";
  private static final String ATTR_CLASS = "class";
  private static final String INFOBOX_CONTENT = "infobox-content";
  private static final String ATTR_TITLE = "title";
  private static final String ATTR_VALUE = "value";
  private static final String RETURN_TO_FRIENDS = "returnToFriends";
  private static final String FRIENDS = "friends";
  private static final String N2NM_UPLOAD = "n2nm-upload";
  private static final String INPUT_TAG = "input";
  private static final long ONE_MEBIBYTE = 1024L * 1024L;
  private static final int MESSAGE_HEAD_LIMIT = 1024;
  private static final int MESSAGE_MAX_LENGTH = 1024 * 128;
  private static final int MESSAGE_PART_LIMIT = 1024 * 1024;

  private final Node node;
  private final LocalFileN2NMToadlet browser;
  private final String friendsPath;

  /**
   * Builds a new N2NTM toadlet wired to the supplied node services and localization context.
   *
   * @param n owning {@link Node} exposing darknet peers; keep reachable while this lives.
   * @param core client core powering the file browser for attachment resolution; not {@code null}.
   * @param client HTTP client for the base {@link Toadlet}; must outlive this instance.
   * @param friendsPath path to the friends listing for redirects, typically with leading slash.
   */
  protected N2NTMToadlet(
      Node n, NodeClientCore core, HighLevelSimpleClient client, String friendsPath) {
    super(client);
    browser = new LocalFileN2NMToadlet(core, client);
    this.node = n;
    this.friendsPath = friendsPath;
  }

  /**
   * Returns the companion toadlet that renders the local file browser used for selecting
   * attachments.
   *
   * @return file browser toadlet sharing the client core; keep lifecycle stable during requests.
   */
  public Toadlet getBrowser() {
    return browser;
  }

  /**
   * Handles HTTP {@code GET} requests by rendering the message composition form or redirecting
   * unqualified calls back to the friends list.
   *
   * <p>When a specific peer hash code is present, the method resolves it to a darknet peer, renders
   * a pre-populated form targeting that peer, and responds with localized content. If the hash code
   * cannot be resolved, an error infobox with navigation links is returned instead. Requests
   * failing the full-access check receive no further processing. Calls without a peer selector are
   * sent to the friends page, preserving the expected navigation flow.
   *
   * @param uri request URI used for logging and routing; may be {@code null}.
   * @param request HTTP request wrapper providing parameters such as {@code peernode_hashcode}.
   * @param ctx context supplying localization, access checks, and response helpers; keep it open.
   * @throws ToadletContextClosedException if the response stream closes before writing completes.
   * @throws IOException if writing the generated HTML fails.
   * @throws RedirectException if a redirect is triggered by the underlying page maker.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (!ctx.checkFullAccess(this)) return;

    if (request.isParameterSet("peernode_hashcode")) {
      PageNode page = ctx.getPageMaker().getPageNode(l10n("sendMessage"), ctx);
      HTMLNode contentNode = page.getContentNode();

      String peerNodeName = null;
      String inputHashcodeString = request.getParam("peernode_hashcode");
      int inputHashcode = -1;
      try {
        inputHashcode = Integer.parseInt(inputHashcodeString);
      } catch (NumberFormatException e) {
        // ignore here, handle below
      }
      if (inputHashcode != -1) {
        DarknetPeerNode[] peerNodes = node.getDarknetConnections();
        for (DarknetPeerNode pn : peerNodes) {
          int peerHashcode = pn.hashCode();
          if (peerHashcode == inputHashcode) {
            peerNodeName = pn.getName();
            break;
          }
        }
      }
      if (peerNodeName == null) {
        contentNode.addChild(
            createPeerNotFoundInfobox(
                l10n("peerNotFoundTitle"),
                NodeL10n.getBase()
                    .getString(
                        L10N_PREFIX + "peerNotFoundWithHash",
                        new String[] {"hash"},
                        new String[] {inputHashcodeString})));
        this.writeHTMLReply(ctx, 200, "OK", page.generate());
        return;
      }
      HashMap<String, String> peers = new HashMap<>();
      peers.put(inputHashcodeString, peerNodeName);
      createN2NTMSendForm(ctx.isAdvancedModeEnabled(), contentNode, ctx, peers);
      this.writeHTMLReply(ctx, 200, "OK", page.generate());
      return;
    }
    sendFriendsRedirect(ctx);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  /*
   * File size limit is 1 MiB (1024*1024 bytes) or 5% of maximum Java memory, whichever is greater.
   */
  private static long maxSize() {
    long memory = NodeStarter.getMemoryLimitBytes();
    if (memory == Long.MAX_VALUE || memory <= 0) return ONE_MEBIBYTE;
    long maxMem = Math.round(0.05 * memory);
    return Math.max(maxMem, ONE_MEBIBYTE);
  }

  private HTMLNode createPeerNotFoundInfobox(String header, String message) {
    HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, "infobox infobox-error");
    infobox.addChild("div", ATTR_CLASS, "infobox-header", header);
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    infoboxContent.addChild("#", message);
    HTMLNode list = infoboxContent.addChild("ul");
    Toadlet.addHomepageLink(list);
    list.addChild("li")
        .addChild(
            "a",
            new String[] {"href", ATTR_TITLE},
            new String[] {friendsPath, l10n(RETURN_TO_FRIENDS)},
            l10n(FRIENDS));
    return infobox;
  }

  /**
   * Processes {@code POST} submissions for sending N2NTM messages or delegating to the local file
   * browser.
   *
   * <p>This handler first enforces full-access permissions, then honors browse requests by issuing
   * a redirect to the file browser toadlet. For send actions, it validates message length, resolves
   * both uploaded and locally selected files subject to size caps, and attempts to deliver text and
   * file offers to each chosen peer. Per-peer outcomes are rendered in a status table while the
   * original message body is echoed for confirmation. Invalid inputs (oversized payloads,
   * unreadable files, or missing peers) result in localized error infoboxes and do not mutate peer
   * state.
   *
   * @param uri request URI logged for observability; may be {@code null} internally.
   * @param request multipart HTTP request holding message text, peer selectors, and optional upload
   *     parts.
   * @param ctx active context used for access checks, page generation, and response dispatch; keep
   *     it open while processing.
   * @throws ToadletContextClosedException if the client disconnects while the response is being
   *     written.
   * @throws IOException if writing responses or reading uploads encounters an I/O failure.
   * @throws RedirectException if the method triggers a redirect (e.g., browse delegation) during
   *     processing.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {

    if (!ctx.checkFullAccess(this)) return;

    if (uri != null && LOG.isDebugEnabled()) {
      LOG.debug("handleMethodPOST for {}", uri);
    }

    if (handleBrowseRedirect(request)) {
      return;
    }

    if (isSendRequest(request)) {
      processSendRequest(request, ctx);
      return;
    }
    sendFriendsRedirect(ctx);
  }

  private boolean handleBrowseRedirect(HTTPRequest request) throws RedirectException {
    if (request.isPartSet("n2nm-browse")) {
      try {
        throw new RedirectException(LocalFileN2NMToadlet.PATH);
      } catch (URISyntaxException e) {
        LOG.error("Unexpected LocalFileN2NMToadlet path", e);
      }
      return true;
    }
    return false;
  }

  private boolean isSendRequest(HTTPRequest request) {
    return request.isPartSet(N2NM_UPLOAD)
        || request.isPartSet(LocalFileBrowserToadlet.selectFile)
        || request.isPartSet("send");
  }

  private void processSendRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String message = request.getPartAsStringFailsafe("message", MESSAGE_PART_LIMIT).trim();
    if (message.length() > MESSAGE_MAX_LENGTH) {
      this.writeTextReply(ctx, 400, "Bad request", l10n("tooLong"));
      return;
    }
    String messageHead = message.substring(0, Math.min(message.length(), MESSAGE_HEAD_LIMIT));

    PageNode page = ctx.getPageMaker().getPageNode(l10n("processingSend"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode peerTableInfobox = contentNode.addChild("div", ATTR_CLASS, "infobox infobox-normal");

    FileResolution fileResolution = resolveSelectedFile(request, peerTableInfobox, page, ctx);
    if (fileResolution.abortProcessing()) {
      return;
    }
    File filename = fileResolution.file();

    UploadResolution uploadResolution =
        resolveUploadedFile(request, peerTableInfobox, page, ctx, message);
    if (uploadResolution.abortProcessing()) {
      return;
    }
    HTTPUploadedFile uploadedFile = uploadResolution.file();

    DarknetPeerNode[] peerNodes = node.getDarknetConnections();

    HTMLNode peerTable = peerTableInfobox.addChild("table", ATTR_CLASS, "n2ntm-send-statuses");
    HTMLNode peerTableHeaderRow = peerTable.addChild("tr");
    peerTableHeaderRow.addChild("th", l10n("peerName"));
    peerTableHeaderRow.addChild("th", l10n("sendStatus"));

    SendContext sendContext =
        new SendContext(message, messageHead, filename, uploadedFile, peerTableInfobox, page, ctx);

    boolean aborted = sendToSelectedPeers(request, peerNodes, peerTable, sendContext);
    if (aborted) {
      return;
    }

    HTMLNode infoboxContent = peerTableInfobox.addChild("div", ATTR_CLASS, "n2ntm-message-text");
    infoboxContent.addChild("#", message);
    HTMLNode list = peerTableInfobox.addChild("ul");
    Toadlet.addHomepageLink(list);
    list.addChild("li")
        .addChild(
            "a",
            new String[] {"href", ATTR_TITLE},
            new String[] {friendsPath, l10n(RETURN_TO_FRIENDS)},
            l10n(FRIENDS));
    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean sendToSelectedPeers(
      HTTPRequest request, DarknetPeerNode[] peerNodes, HTMLNode peerTable, SendContext sendContext)
      throws ToadletContextClosedException, IOException {
    for (DarknetPeerNode pn : peerNodes) {
      if (request.isPartSet("node_" + pn.hashCode())) {
        if (sendFileOfferIfAny(pn, sendContext)) {
          return true;
        }
        int status = pn.sendTextFeed(sendContext.message());
        addPeerStatusRow(peerTable, pn, status, sendContext.message());
      }
    }
    return false;
  }

  private boolean sendFileOfferIfAny(DarknetPeerNode pn, SendContext sendContext)
      throws ToadletContextClosedException, IOException {
    if (sendContext.filename() != null) {
      try {
        pn.sendFileOffer(sendContext.filename(), sendContext.messageHead());
      } catch (IOException e) {
        sendContext.peerTableInfobox().addChild("#", l10n("noSuchFileOrCannotRead"));
        Toadlet.addHomepageLink(sendContext.peerTableInfobox());
        addUnsentMessageTextInfo(sendContext.peerTableInfobox(), sendContext.message());
        this.writeHTMLReply(sendContext.ctx(), 200, "OK", sendContext.page().generate());
        return true;
      }
    } else if (hasUploadedContent(sendContext.uploadedFile())) {
      try {
        pn.sendFileOffer(sendContext.uploadedFile(), sendContext.messageHead());
      } catch (IOException e) {
        sendContext.peerTableInfobox().addChild("#", l10n("uploadFailed"));
        Toadlet.addHomepageLink(sendContext.peerTableInfobox());
        addUnsentMessageTextInfo(sendContext.peerTableInfobox(), sendContext.message());
        this.writeHTMLReply(sendContext.ctx(), 200, "OK", sendContext.page().generate());
        return true;
      }
    }
    return false;
  }

  private static boolean hasUploadedContent(HTTPUploadedFile uploadedFile) {
    return uploadedFile != null
        && !uploadedFile.getFilename().isEmpty()
        && uploadedFile.getData().size() > 0;
  }

  private void addPeerStatusRow(
      HTMLNode peerTable, DarknetPeerNode pn, int status, String message) {
    SendStatus sendStatus =
        switch (status) {
          case PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF ->
              new SendStatus(l10n("delayedTitle"), l10n("delayed"), "n2ntm-send-delayed", "Sent");
          case PeerManager.PEER_NODE_STATUS_CONNECTED ->
              new SendStatus(l10n("sentTitle"), l10n("sent"), "n2ntm-send-sent", "Sent");
          default ->
              new SendStatus(l10n("queuedTitle"), l10n("queued"), "n2ntm-send-queued", "Queued");
        };
    LOG.info("{} N2NTM to '{}': {}", sendStatus.logPrefix(), pn.getName(), message);
    HTMLNode peerRow = peerTable.addChild("tr");
    peerRow.addChild("td", ATTR_CLASS, "peer-name").addChild("#", pn.getName());
    peerRow
        .addChild("td", ATTR_CLASS, sendStatus.cssClass())
        .addChild(
            "span",
            new String[] {ATTR_TITLE, "style"},
            new String[] {sendStatus.longLabel(), "border-bottom: 1px dotted; cursor: help;"},
            sendStatus.shortLabel());
  }

  private FileResolution resolveSelectedFile(
      HTTPRequest request, HTMLNode peerTableInfobox, PageNode page, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet(LocalFileBrowserToadlet.selectFile)) {
      return FileResolution.none();
    }
    String fnam = request.getPartAsStringFailsafe("filename", 1024);
    if (fnam == null || fnam.isEmpty()) {
      return FileResolution.none();
    }
    File filename = new File(fnam);
    if (filename.exists() && filename.canRead()) {
      return FileResolution.success(filename);
    }
    peerTableInfobox.addChild("#", l10n("noSuchFileOrCannotRead"));
    Toadlet.addHomepageLink(peerTableInfobox);
    this.writeHTMLReply(ctx, 400, "OK", page.generate());
    return FileResolution.abort();
  }

  private UploadResolution resolveUploadedFile(
      HTTPRequest request,
      HTMLNode peerTableInfobox,
      PageNode page,
      ToadletContext ctx,
      String message)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet(N2NM_UPLOAD)) {
      return UploadResolution.none();
    }
    try {
      HTTPUploadedFile file = request.getUploadedFile(N2NM_UPLOAD);
      if (!hasUploadedContent(file)) {
        return UploadResolution.none();
      }
      long size = file.getData().size();
      long limit = maxSize();
      if (size > limit) {
        peerTableInfobox.addChild(
            "#",
            NodeL10n.getBase()
                .getString(
                    L10N_PREFIX + "tooLarge",
                    new String[] {"attempt", "limit"},
                    new String[] {
                      SizeUtil.formatSize(size, true), SizeUtil.formatSize(limit, true)
                    }));
        HTMLNode list = peerTableInfobox.addChild("ul");
        Toadlet.addHomepageLink(list);
        list.addChild("li")
            .addChild(
                "a",
                new String[] {"href", ATTR_TITLE},
                new String[] {friendsPath, l10n(RETURN_TO_FRIENDS)},
                l10n(FRIENDS));
        addUnsentMessageTextInfo(peerTableInfobox, message);
        this.writeHTMLReply(ctx, 200, "OK", page.generate());
        return UploadResolution.abort();
      }
      return UploadResolution.success(file);
    } catch (IOException e) {
      peerTableInfobox.addChild("#", l10n("uploadFailed"));
      Toadlet.addHomepageLink(peerTableInfobox);
      addUnsentMessageTextInfo(peerTableInfobox, message);
      this.writeHTMLReply(ctx, 200, "OK", page.generate());
      return UploadResolution.abort();
    }
  }

  private void sendFriendsRedirect(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", friendsPath);
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  /**
   * Appends a short explanatory paragraph and the original message body to a supplied HTML node so
   * users can copy or retry sending.
   *
   * <p>The helper is used when sending fails due to validation or I/O issues and the UI needs to
   * preserve the composed text. The message content is inserted verbatim under two {@code <p>}
   * elements; callers should ensure the target node is properly escaped and not reused across
   * concurrent responses.
   *
   * @param node parent {@link HTMLNode} that receives the explanatory paragraphs; not {@code null}.
   * @param message message text that failed to send; inserted verbatim, may be empty.
   */
  public static void addUnsentMessageTextInfo(HTMLNode node, String message) {
    node.addChild("p", l10n("unsentMessageText"));
    node.addChild("p", message);
  }

  private record FileResolution(File file, boolean abortProcessing) {
    static FileResolution success(File file) {
      return new FileResolution(file, false);
    }

    static FileResolution abort() {
      return new FileResolution(null, true);
    }

    static FileResolution none() {
      return new FileResolution(null, false);
    }
  }

  private record UploadResolution(HTTPUploadedFile file, boolean abortProcessing) {
    static UploadResolution success(HTTPUploadedFile file) {
      return new UploadResolution(file, false);
    }

    static UploadResolution abort() {
      return new UploadResolution(null, true);
    }

    static UploadResolution none() {
      return new UploadResolution(null, false);
    }
  }

  private record SendContext(
      String message,
      String messageHead,
      File filename,
      HTTPUploadedFile uploadedFile,
      HTMLNode peerTableInfobox,
      PageNode page,
      ToadletContext ctx) {}

  private record SendStatus(
      String shortLabel, String longLabel, String cssClass, String logPrefix) {}

  /**
   * Renders the N2NTM send form within the provided content node for the given set of peers.
   *
   * <p>The form lists target peers, inserts hidden inputs keyed by each peer hash code, and builds
   * a textarea for composing the message body. When {@code advancedMode} is enabled and the caller
   * has full access, the form also exposes controls for browsing local files and uploading
   * attachments, including a localized size warning based on {@link #maxSize()}. Submit buttons are
   * labeled for both browsing and sending so the same handler can route requests appropriately. The
   * method assumes ownership of adding necessary line breaks and will not sanitize peer names;
   * callers should only pass trusted values.
   *
   * @param advancedMode whether advanced UI elements (file browse/upload) should be shown to the
   *     user.
   * @param contentNode container node that receives the form and infobox; unique per response.
   * @param ctx context generating form URLs and enforcing permissions; must match current request.
   * @param peers map of peer hash codes to display names; pass only selected peers.
   */
  public static void createN2NTMSendForm(
      boolean advancedMode, HTMLNode contentNode, ToadletContext ctx, Map<String, String> peers) {
    HTMLNode infobox =
        contentNode.addChild(
            "div", new String[] {ATTR_CLASS, "id"}, new String[] {"infobox", "n2nbox"});
    infobox.addChild("div", ATTR_CLASS, "infobox-header", l10n("sendMessage"));
    HTMLNode messageTargets = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    messageTargets.addChild("p", l10n("composingMessageLabel"));
    HTMLNode messageTargetList = messageTargets.addChild("ul");
    // Iterate peers
    for (String peer_name : peers.values()) {
      messageTargetList.addChild("li", peer_name);
    }
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    HTMLNode messageForm = ctx.addFormChild(infoboxContent, "/send_n2ntm/", "sendN2NTMForm");
    // Iterate peers
    for (String peerNodeHash : peers.keySet()) {
      messageForm.addChild(
          INPUT_TAG,
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
            INPUT_TAG,
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
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"file", N2NM_UPLOAD, ""});
      messageForm.addChild("br");
    }
    messageForm.addChild(
        INPUT_TAG,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "send", l10n("sendMessageShort")});
  }

  /**
   * Returns the root HTTP path served by this toadlet.
   *
   * @return path string {@code /send_n2ntm/} for registration and form actions.
   */
  @Override
  public String path() {
    return "/send_n2ntm/";
  }
}
