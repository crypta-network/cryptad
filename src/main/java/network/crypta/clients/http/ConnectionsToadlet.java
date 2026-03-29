package network.crypta.clients.http;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringTokenizer;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.AddPeer;
import network.crypta.config.ConfigException;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.Version;
import network.crypta.runtime.peers.html.PeerTrustInputForAddPeerBoxNode;
import network.crypta.runtime.peers.html.PeerVisibilityInputForAddPeerBoxNode;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPageKind;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsPageRequest;
import network.crypta.runtime.spi.ConnectionsPageSnapshot;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerAddFailureReason;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base HTTP toadlet used by both darknet and opennet connection pages.
 *
 * <p>This class renders peer connection state, accepts noderef submissions, and provides helpers
 * for subclasses that tailor per-network presentation. It centralizes sorting, pagination,
 * validation, and noderef ingestion so downstream pages can focus on the specifics of each
 * topology. Instances are long-lived and reused across requests; state comes from the injected
 * runtime ports rather than per-request mutability.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Rendering peer summaries, trust/visibility columns, and message-type breakdowns.
 *   <li>Parsing noderefs from form uploads, pasted text, or URLs, then delegating to the runtime
 *       SPI for peer creation.
 *   <li>Handling redirects and guidance when no peers exist or when access checks fail.
 * </ul>
 *
 * <p>Thread-safety: instances hold only long-lived collaborators and no mutable request-scoped
 * state except transient flags on the stack, so they can service concurrent requests when the
 * surrounding HTTP server invokes them in parallel. Subclasses should preserve this behavior when
 * adding fields or caching.
 */
public abstract class ConnectionsToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(ConnectionsToadlet.class);
  private static final String OPENNET = "opennet";
  private static final String DARKNET = "darknet";
  private static final String ATTR_CLASS = "class";
  private static final String ELEMENT_TABLE = "table";
  private static final String INFOBOX_CLASS = "infobox";
  private static final String INFOBOX_NORMAL_CLASS = "infobox infobox-normal";
  private static final String INFOBOX_HEADER_CLASS = "infobox-header";
  private static final String INFOBOX_CONTENT_CLASS = "infobox-content";
  private static final String DISPLAY_MESSAGE_TYPES = "displaymessagetypes.html";
  private static final String ELEMENT_INPUT = "input";
  private static final String TRUST = "trust";
  private static final String REF_FILE = "reffile";
  private static final String PEER_PRIVATE_NOTE = "peerPrivateNote";
  private static final String REPORT_OF_NODE_ADDITION = "reportOfNodeAddition";

  /**
   * Comparator that orders {@link PeerNodeStatus} instances for table rendering.
   *
   * <p>Sorting honors a user-selected column when present and otherwise falls back to status code
   * and peer hash for deterministic ordering. The {@code reversed} flag inverts the final result so
   * callers can reuse one comparator for ascending and descending views without allocating extra
   * helpers.
   */
  protected static class ComparatorByStatus implements Comparator<PeerNodeStatus> {
    /** Column key requested by the client, may be {@code null} for default ordering. */
    protected final String sortBy;

    /** Whether the comparator should invert its result for the descending presentation. */
    protected final boolean reversed;

    /**
     * Creates a comparator configured for a column and direction.
     *
     * @param sortBy column key requested by the HTTP client; may be {@code null} to use defaults.
     * @param reversed whether the ordering should be inverted for descending presentation.
     */
    ComparatorByStatus(String sortBy, boolean reversed) {
      this.sortBy = sortBy;
      this.reversed = reversed;
    }

    /**
     * Orders two peer rows using configured sort behavior.
     *
     * @param firstNode the first peer candidate; never mutated by this comparator.
     * @param secondNode the second peer candidate; never mutated by this comparator.
     * @return negative when the first precedes the second, positive when after, or zero when ties.
     */
    @Override
    public int compare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      int result = compareWithSort(firstNode, secondNode);
      if (result == 0) {
        result = compareByStatus(firstNode, secondNode);
      }
      return reversed ? -Integer.signum(result) : Integer.signum(result);
    }

    private int compareByStatus(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      int statusDifference =
          Integer.compare(firstNode.getStatusValue(), secondNode.getStatusValue());
      if (statusDifference != 0) {
        return statusDifference;
      }
      return lastResortCompare(firstNode, secondNode);
    }

    private int compareWithSort(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      if (sortBy == null) {
        return 0;
      }
      return customCompare(firstNode, secondNode);
    }

    // xor: check why we do not just return the result of (long1-long2)
    // j16sdiz: (Long.MAX_VALUE - (-1)) would overflow and become negative
    private int compareLongs(long long1, long long2) {
      int diff = Long.compare(long1, long2);
      if (diff == 0) return 0;
      else return (diff > 0 ? 1 : -1);
    }

    private int compareInts(int int1, int int2) {
      int diff = Integer.compare(int1, int2);
      if (diff == 0) return 0;
      else return (diff > 0 ? 1 : -1);
    }

    /**
     * Applies column-specific ordering chosen by the requester.
     *
     * <p>Each branch matches a sortable column and compares the corresponding values using
     * type-appropriate ordering. When the column key is unrecognised the method returns {@code 0}
     * so callers can rely on default or tie-breaker ordering.
     *
     * @param firstNode first peer candidate considered in the comparison.
     * @param secondNode second peer candidate considered in the comparison.
     * @return a negative number when the first node should precede the second, positive when it
     *     should follow, or zero when the column is not supported.
     */
    protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      return switch (sortBy) {
        case "address" ->
            firstNode.getPeerAddress().compareToIgnoreCase(secondNode.getPeerAddress());
        case "location" -> compareLocations(firstNode, secondNode);
        case "version" ->
            Version.compareBuildNumbers(
                Version.parseNodeNameFromVersionStr(firstNode.getVersion()),
                Version.parseBuildNumberFromVersionStr(firstNode.getVersion(), -1),
                Version.parseNodeNameFromVersionStr(secondNode.getVersion()),
                Version.parseBuildNumberFromVersionStr(secondNode.getVersion(), -1));
        case "backoffRT" ->
            Double.compare(
                firstNode.getBackedOffPercent(true), secondNode.getBackedOffPercent(true));
        case "backoffBulk" ->
            Double.compare(
                firstNode.getBackedOffPercent(false), secondNode.getBackedOffPercent(false));
        case "overload_p" -> Double.compare(firstNode.getPReject(), secondNode.getPReject());
        case "idle" ->
            compareLongs(
                firstNode.getTimeLastConnectionCompleted(),
                secondNode.getTimeLastConnectionCompleted());
        case "time_routable" ->
            Double.compare(
                firstNode.getPercentTimeRoutableConnection(),
                secondNode.getPercentTimeRoutableConnection());
        case "total_traffic" -> {
          long total1 = firstNode.getTotalInputBytes() + firstNode.getTotalOutputBytes();
          long total2 = secondNode.getTotalInputBytes() + secondNode.getTotalOutputBytes();
          yield compareLongs(total1, total2);
        }
        case "total_traffic_since_startup" -> {
          long total1 =
              firstNode.getTotalInputSinceStartup() + firstNode.getTotalOutputSinceStartup();
          long total2 =
              secondNode.getTotalInputSinceStartup() + secondNode.getTotalOutputSinceStartup();
          yield compareLongs(total1, total2);
        }
        case "selection_percentage" ->
            Double.compare(firstNode.getSelectionRate(), secondNode.getSelectionRate());
        case "time_delta" -> compareLongs(firstNode.getClockDelta(), secondNode.getClockDelta());
        case "uptime" ->
            compareInts(
                firstNode.getReportedUptimePercentage(), secondNode.getReportedUptimePercentage());
        default -> 0;
      };
    }

    private int compareLocations(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      double diff =
          firstNode.getLocation()
              - secondNode
                  .getLocation(); // Can occasionally be the same, and we must have a consistent
      // sort order
      if (Double.MIN_VALUE * 2 > Math.abs(diff)) return 0;
      return diff > 0 ? 1 : -1;
    }

    /**
     * Provides deterministic ordering after higher-priority comparisons tie.
     *
     * <p>This implementation compares the peer locations to ensure stable presentation across
     * renders. Subclasses can override by altering location calculation in {@link PeerNodeStatus}.
     *
     * @param firstNode first peer candidate to order.
     * @param secondNode second peer candidate to order.
     * @return negative when the first node is earlier, positive when later, zero when equal.
     */
    protected int lastResortCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      return compareLocations(firstNode, secondNode);
    }
  }

  /** Page-oriented runtime port used for detached GET-only connections page rendering. */
  private final ConnectionsPagePort connectionsPage;

  /** Runtime peer-management port used for peer additions and darknet note writes. */
  private final PeerPort peerPort;

  /** Runtime node-info port used to export this node's own noderef for the UI. */
  private final NodeInfoPort nodeInfoPort;

  /** Runtime config port used for add-peer flow overrides that previously hit daemon config. */
  private final ConfigPort configPort;

  /** Runtime support port used for opennet enablement and peer-offer noderef imports. */
  private final ConnectionsSupportPort connectionsSupportPort;

  /**
   * Outcomes returned when attempting to add a peer from a supplied noderef.
   *
   * <p>Values map directly to user-visible result codes in the add-peer report table. They
   * distinguish validation failures, parsing errors, identity clashes, and success.
   */
  public enum PeerAdditionReturnCodes {
    /** Peer was added successfully without warnings. */
    OK,
    /** Noderef contained malformed encoding or incorrect end marker. */
    WRONG_ENCODING,
    /** Parsing of the noderef failed before verification could run. */
    CANT_PARSE,
    /** Unexpected internal problem occurred during peer creation. */
    INTERNAL_ERROR,
    /** Noderef signature could not be validated against provided keys. */
    INVALID_SIGNATURE,
    /** Submitted noderef belongs to this node; self-adding is blocked. */
    TRY_TO_ADD_SELF,
    /** Peer already exists in the local peer set. */
    ALREADY_IN_REFERENCE
  }

  /**
   * Creates a toadlet bound to shared node infrastructure used by connection pages.
   *
   * @param client high-level client used to retrieve noderefs via Freenet or HTTP when users submit
   *     URLs instead of pasted references.
   * @param runtimePorts shared detached runtime ports backing page rendering, peer changes, noderef
   *     export, config lookups, and legacy page-support helpers.
   */
  ConnectionsToadlet(HighLevelSimpleClient client, ConnectionsToadletRuntimePorts runtimePorts) {
    super(client);
    ConnectionsToadletRuntimePorts ports = Objects.requireNonNull(runtimePorts);
    this.connectionsPage = ports.connectionsPage();
    this.peerPort = ports.peerPort();
    this.nodeInfoPort = ports.nodeInfoPort();
    this.configPort = ports.configPort();
    this.connectionsSupportPort = ports.connectionsSupportPort();
    refLink = HTMLNode.link(path() + "myref.fref").setReadOnly();
    reftextLink = HTMLNode.link(path() + "myref.txt").setReadOnly();
  }

  /**
   * Renders the connections page and optional message-type breakdowns.
   *
   * <p>The handler validates access, resolves download endpoints for the current node reference,
   * builds sorted peer tables, and writes the resulting HTML response. When no peers exist, it
   * still renders guidance and, depending on mode, may redirect to friend-adding flows. Download
   * requests for {@code myref.fref} or {@code myref.txt} are served directly with appropriate
   * headers.
   *
   * @param uri request target URI, used to detect message-type view and download paths.
   * @param request HTTP request wrapper supplying parameters such as {@code sortBy} and {@code
   *     reversed}.
   * @param ctx toadlet context providing authorization checks and HTML generation utilities.
   * @throws ToadletContextClosedException when the client connection is already closed while
   *     writing output.
   * @throws IOException when generating the page or serving downloads fails due to I/O errors.
   * @throws RedirectException when control flow chooses to redirect instead of rendering.
   */
  @Override
  public void handleMethodGET(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) return;

    String path = uri.getPath();
    if (serveReferenceDownload(path, ctx)) {
      return;
    }

    boolean drawMessageTypes = path.endsWith(DISPLAY_MESSAGE_TYPES);
    boolean advancedMode = ctx.isAdvancedModeEnabled();
    ConnectionsPageSnapshot snapshot =
        connectionsPage.render(
            new ConnectionsPageRequest(
                isOpennet() ? ConnectionsPageKind.OPENNET : ConnectionsPageKind.DARKNET,
                advancedMode,
                drawMessageTypes,
                request.getParam("sortBy", null),
                request.isParameterSet("reversed")));

    if (snapshot.peerCount() == 0 && !isOpennet()) {
      throw new RedirectException(URI.create("/addfriend/"));
    }

    PageNode page = ctx.getPageMaker().getPageNode(snapshot.pageTitle(), ctx);
    HTMLNode contentNode = page.getContentNode();

    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }

    contentNode.addChild("%", snapshot.contentHtmlBeforePeerTable());
    if (snapshot.peerActionsEnabled() && snapshot.peerCount() > 0) {
      HTMLNode peerForm = ctx.addFormChild(contentNode, ".", "peersForm");
      peerForm.addChild("%", snapshot.peerTableHtml());
    } else {
      contentNode.addChild("%", snapshot.peerTableHtml());
    }
    contentNode.addChild("%", snapshot.contentHtmlAfterPeerTable());

    if (shouldDrawNoderefBox(advancedMode)) {
      drawAddPeerBox(contentNode, ctx);
      drawNoderefBox(contentNode, exportOwnNoderef());
    }

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean serveReferenceDownload(String path, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (path.endsWith("myref.fref")) {
      SimpleFieldSet fs = exportOwnNoderef();
      String noderefString = fs.toOrderedStringWithBase64();
      MultiValueTable<String, String> extraHeaders =
          MultiValueTable.from("Content-Disposition", "attachment; filename=myref.fref");
      writeReply(
          ctx,
          ReplyHeaders.of(200, "OK", "application/x-freenet-reference", extraHeaders),
          noderefString);
      return true;
    }

    if (path.endsWith("myref.txt")) {
      SimpleFieldSet fs = exportOwnNoderef();
      String noderefString = fs.toOrderedStringWithBase64();
      writeTextReply(ctx, 200, "OK", noderefString);
      return true;
    }
    return false;
  }

  private record AddPeerRequestData(
      String urltext,
      String reftext,
      String privateComment,
      FRIEND_TRUST trust,
      FRIEND_VISIBILITY visibility) {}

  /**
   * Indicates whether noderef POST submissions are accepted for this toadlet.
   *
   * <p>Subclasses can deny uploads based on network mode or feature flags, in which case POST
   * requests are answered with an unauthorized page.
   *
   * @return {@code true} when reference uploads are allowed; {@code false} when they should be
   *     rejected.
   */
  protected abstract boolean acceptRefPosts();

  /**
   * Provides the destination used when POST processing opts to redirect instead of rendering.
   *
   * @return a relative or absolute path that receives the user after recoverable errors.
   */
  @SuppressWarnings("unused")
  protected abstract String defaultRedirectLocation();

  /**
   * Handles connection-related POST requests, including noderef uploads.
   *
   * <p>The handler verifies permissions, checks whether uploads are permitted, and dispatches to
   * add-peer logic or alternate actions based on submitted form parts. It logs debug detail only
   * when enabled and leaves the state unchanged if validation fails.
   *
   * @param uri target URI, used to route auxiliary POST actions.
   * @param request HTTP request containing multipart fields such as {@code add}, {@code ref}, or
   *     {@code reffile}.
   * @param ctx toadlet context supplying authorization checks and response builders.
   * @throws ToadletContextClosedException if the client connection is already closed.
   * @throws IOException on I/O failures while reading parts or writing responses.
   * @throws ConfigException when submitted, trust or visibility values violate constraints.
   * @throws RedirectException when processing elects to redirect instead of generating a page.
   */
  public void handleMethodPOST(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, ConfigException, RedirectException {
    boolean logMINOR = LOG.isDebugEnabled();

    if (!acceptRefPosts()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    if (!ctx.checkFullAccess(this)) return;

    if (request.isPartSet("add")) {
      handleAddPeer(request, ctx);
    } else {
      handleAltPost(uri, request, ctx, logMINOR);
    }
  }

  private void handleAddPeer(HTTPRequest request, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    AddPeerRequestData data = extractAddPeerRequestData(request);
    if (!validateTrustAndVisibility(ctx, data)) {
      return;
    }

    StringBuilder ref = fetchReference(data, ctx);
    if (ref == null) {
      return;
    }

    request.freeParts();
    processReferences(data, ref, ctx);
  }

  private AddPeerRequestData extractAddPeerRequestData(HTTPRequest request) throws IOException {
    String urltext = request.getPartAsStringFailsafe("url", 200).trim();
    String reftext = request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE).trim();
    if (reftext.length() < 200) {
      reftext = request.getPartAsStringFailsafe(REF_FILE, Integer.MAX_VALUE).trim();
    }
    String privateComment = null;
    if (!isOpennet()) {
      privateComment = request.getPartAsStringFailsafe(PEER_PRIVATE_NOTE, 250).trim();
    }

    if (Boolean.parseBoolean(request.getPartAsStringFailsafe("peers-offers-files", 5))) {
      String peersOffersRefs = readPeersOffersFiles();
      if (!peersOffersRefs.isBlank()) {
        reftext = peersOffersRefs;
      }
      configPort.applyOverrides(Map.of("node.peersOffersDismissed", "true"));
    }

    FRIEND_TRUST trust = parseTrust(request);
    FRIEND_VISIBILITY visibility = parseVisibility(request);

    return new AddPeerRequestData(urltext, reftext, privateComment, trust, visibility);
  }

  private String readPeersOffersFiles() throws IOException {
    return connectionsSupportPort.readPeerOfferReferencesText();
  }

  private FRIEND_TRUST parseTrust(HTTPRequest request) {
    String trustS = request.getPartAsStringFailsafe(TRUST, 10);
    if (trustS == null || trustS.isEmpty()) {
      return null;
    }
    return FRIEND_TRUST.valueOf(trustS);
  }

  private FRIEND_VISIBILITY parseVisibility(HTTPRequest request) {
    String visibilityS = request.getPartAsStringFailsafe("visibility", 10);
    if (visibilityS == null || visibilityS.isEmpty()) {
      return null;
    }
    return FRIEND_VISIBILITY.valueOf(visibilityS);
  }

  private boolean validateTrustAndVisibility(ToadletContext ctx, AddPeerRequestData data)
      throws ToadletContextClosedException, IOException {
    if (isOpennet()) {
      return true;
    }
    if (data.trust() == null) {
      this.sendErrorPage(
          ctx, 200, l10n("noTrustLevelAddingFriendTitle"), l10n("noTrustLevelAddingFriend"), true);
      return false;
    }
    if (data.visibility() == null) {
      this.sendErrorPage(
          ctx,
          200,
          l10n("noVisibilityLevelAddingFriendTitle"),
          l10n("noVisibilityLevelAddingFriend"),
          true);
      return false;
    }
    return true;
  }

  private StringBuilder fetchReference(AddPeerRequestData data, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!data.urltext().isEmpty()) {
      return fetchReferenceFromUrl(data.urltext(), ctx);
    }
    if (!data.reftext().isEmpty()) {
      return new StringBuilder(cleanReferenceText(data.reftext()));
    }
    this.sendErrorPage(ctx, 200, l10n("failedToAddNodeTitle"), l10n("noRefOrURL"), !isOpennet());
    return null;
  }

  private StringBuilder fetchReferenceFromUrl(String urltext, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      return fetchReferenceViaUrl(urltext);
    } catch (IOException _) {
      this.sendErrorPage(
          ctx,
          200,
          l10n("failedToAddNodeTitle"),
          NodeL10n.getBase()
              .getString(
                  "DarknetConnectionsToadlet.cantFetchNoderefURL",
                  new String[] {"url"},
                  new String[] {urltext}),
          !isOpennet());
      return null;
    }
  }

  private StringBuilder fetchReferenceViaUrl(String urltext) throws IOException {
    try {
      FreenetURI refUri = new FreenetURI(urltext);
      return AddPeer.getReferenceFromFreenetURI(refUri, client);
    } catch (MalformedURLException | FetchException _) {
      LOG.warn("Url cannot be used as Crypta URI, trying to fetch as URL: {}", urltext);
      URL url = buildUrl(urltext);
      return AddPeer.getReferenceFromURL(url);
    }
  }

  private URL buildUrl(String urltext) throws MalformedURLException {
    try {
      return URI.create(urltext).toURL();
    } catch (IllegalArgumentException uriException) {
      throw new MalformedURLException(uriException.getMessage());
    }
  }

  private void processReferences(AddPeerRequestData data, StringBuilder ref, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String[] nodesToAdd = splitReferences(new StringBuilder(ref.toString().trim()));
    Map<PeerAdditionReturnCodes, Integer> results = new EnumMap<>(PeerAdditionReturnCodes.class);
    for (String nodeToAdd : nodesToAdd) {
      if (nodeToAdd.isBlank()) {
        continue;
      }
      PeerAdditionReturnCodes result =
          addNewNode(
              nodeToAdd.trim().concat("\nEnd"),
              data.privateComment(),
              data.trust(),
              data.visibility());
      Integer prev = results.get(result);
      if (prev == null) prev = 0;
      results.put(result, prev + 1);
    }
    renderAddPeerResult(ctx, results);
  }

  private String[] splitReferences(StringBuilder ref) {
    replaceCarriageReturns(ref);
    String[] nodesToAdd = ref.toString().split("\nEnd\n");
    for (int i = 0; i < nodesToAdd.length; i++) {
      StringBuilder sb = new StringBuilder(nodesToAdd[i].length());
      boolean first = true;
      StringTokenizer tokenizer = new StringTokenizer(nodesToAdd[i], "\n");
      while (tokenizer.hasMoreTokens()) {
        String s = tokenizer.nextToken();
        if (s.equals("End")) {
          break;
        }
        if (s.indexOf('=') > -1 && !first) {
          sb.append('\n');
        }
        sb.append(s);
        first = false;
      }
      nodesToAdd[i] = sb.toString();
    }
    return nodesToAdd;
  }

  private void replaceCarriageReturns(StringBuilder ref) {
    int idx;
    while ((idx = ref.indexOf("\r\n")) > -1) {
      ref.deleteCharAt(idx);
    }
    while ((idx = ref.indexOf("\r")) > -1) {
      ref.setCharAt(idx, '\n');
    }
  }

  private void renderAddPeerResult(
      ToadletContext ctx, Map<PeerAdditionReturnCodes, Integer> results)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n(REPORT_OF_NODE_ADDITION), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode detailedStatusBox = new HTMLNode(ELEMENT_TABLE);
    detailedStatusBox
        .addChild(new HTMLNode("tr"))
        .addChildren(
            new HTMLNode[] {
              new HTMLNode("th", l10n("resultName")), new HTMLNode("th", l10n("numOfResults"))
            });
    HTMLNode statusBoxTable = detailedStatusBox.addChild(new HTMLNode("tbody"));
    for (PeerAdditionReturnCodes returnCode : PeerAdditionReturnCodes.values()) {
      if (results.containsKey(returnCode)) {
        statusBoxTable
            .addChild(
                new HTMLNode(
                    "tr",
                    "style",
                    "color:" + (returnCode == PeerAdditionReturnCodes.OK ? "green" : "red")))
            .addChildren(
                new HTMLNode[] {
                  new HTMLNode("td", l10n("peerAdditionCode." + returnCode.toString())),
                  new HTMLNode("td", results.get(returnCode).toString())
                });
      }
    }

    HTMLNode infoboxContent =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_CLASS, l10n(REPORT_OF_NODE_ADDITION), contentNode, "node-added", true);
    infoboxContent.addChild(detailedStatusBox);
    if (!isOpennet())
      infoboxContent.addChild("p").addChild("a", "href", "/addfriend/", l10n("addAnotherFriend"));
    infoboxContent.addChild("p").addChild("a", "href", path(), l10n("goFriendConnectionStatus"));
    addHomepageLink(infoboxContent.addChild("p"));

    writeHTMLReply(ctx, 500, l10n(REPORT_OF_NODE_ADDITION), page.generate());
  }

  private PeerAdditionReturnCodes addNewNode(
      String nodeReference,
      String privateComment,
      FRIEND_TRUST trust,
      FRIEND_VISIBILITY visibility) {
    SimpleFieldSet fs;

    try {
      fs = parseNoderefLiberally(nodeReference);
      if (!fs.getEndMarker().endsWith("End")) {
        LOG.error("Trying to add noderef with end marker \"{}\"", fs.getEndMarker());
        return PeerAdditionReturnCodes.WRONG_ENCODING;
      }
      fs.setEndMarker("End");
    } catch (IOException e) {
      LOG.error("IOException adding reference :{}", e.getMessage(), e);
      return PeerAdditionReturnCodes.CANT_PARSE;
    } catch (Exception e) {
      LOG.error("Internal error adding reference :{}", e.getMessage(), e);
      return PeerAdditionReturnCodes.INTERNAL_ERROR;
    }

    if (!matchesExpectedPeerType(fs)) {
      LOG.warn(
          "Rejecting {} noderef on {} connections page",
          fs.getBoolean(OPENNET, false) ? OPENNET : DARKNET,
          isOpennet() ? OPENNET : DARKNET);
      return PeerAdditionReturnCodes.CANT_PARSE;
    }

    try {
      PeerSnapshot addedPeer =
          peerPort.add(toPeerFieldSet(fs), toPeerTrust(trust), toPeerVisibility(visibility));
      maybeWritePrivateDarknetComment(addedPeer, privateComment);
      return PeerAdditionReturnCodes.OK;
    } catch (PeerAddRejectedException e) {
      return mapPeerAddFailure(e.reason());
    } catch (Exception e) {
      LOG.error("Internal error adding reference :{}", e.getMessage(), e);
      return PeerAdditionReturnCodes.INTERNAL_ERROR;
    }
  }

  private String cleanReferenceText(String reftext) {
    StringBuilder builder = new StringBuilder(reftext.length());
    StringTokenizer tokenizer = new StringTokenizer(reftext.replace('\r', '\n'), "\n");
    while (tokenizer.hasMoreTokens()) {
      String line = tokenizer.nextToken();
      String trimmed = line.trim();
      int equalsAt = trimmed.indexOf('=');
      boolean isFieldLine = equalsAt >= 0 || trimmed.equals("End");
      if (!trimmed.isEmpty() && isFieldLine) {
        builder.append(trimmed).append('\n');
      }
    }
    return builder.toString();
  }

  private static SimpleFieldSet parseNoderefLiberally(String nodeReference) throws IOException {
    nodeReference = Fields.trimLines(nodeReference);
    SimpleFieldSet fs = new SimpleFieldSet(nodeReference, false, true, true);
    if (fs.directKeys().contains("lastGoodVersion")) {
      return fs;
    } else {
      LOG.warn(
          "Cannot parse noderef: does not contain lastGoodVersion, trying to replace all spaces"
              + " with newlines and parsing again.");
      return new SimpleFieldSet(nodeReference.replace(" ", "\n"), false, true, true);
    }
  }

  /**
   * Indicates whether this toadlet represents the opennet view rather than the darknet view.
   *
   * <p>Opennet pages skip darknet-only controls (names, trust sliders) and relax some redirects.
   * Implementations should return a consistent value per instance; callers rely on it to decide UI
   * branches and validation rules.
   *
   * @return {@code true} when rendering the opennet connections page; {@code false} for darknet.
   */
  protected abstract boolean isOpennet();

  /**
   * Delegates POST actions not handled by {@link #handleMethodPOST} to subclass-specific logic.
   *
   * <p>Default behavior proxies the POST to the GET handler, so subclasses only implementing GET
   * still behave correctly. Override to support extra form actions such as bulk operations.
   *
   * @param uri original request URI that determines routing of alternative actions.
   * @param request HTTP request wrapper containing posted fields beyond add-peer.
   * @param ctx toadlet context used to render responses or perform redirects.
   * @param logMINOR whether debug/trace logging is enabled for the current request.
   * @throws IOException when rendering fails or forwarding to GET encounters I/O errors.
   * @throws ToadletContextClosedException if the client disconnects while responses are written.
   * @throws RedirectException when subclass logic chooses to redirect instead of rendering.
   */
  protected void handleAltPost(URI uri, HTTPRequest request, ToadletContext ctx, boolean logMINOR)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (logMINOR && LOG.isDebugEnabled()) {
      LOG.debug("Delegating POST to GET for {}", uri);
    }
    if (logMINOR && LOG.isTraceEnabled()) {
      LOG.trace("Original request snapshot: {}", request);
    }
    // Do nothing - we only support adding nodes
    handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
  }

  /**
   * Indicates whether bulk peer actions should be presented to the user.
   *
   * <p>When {@code true}, the renderer adds checkboxes next to each peer row and invokes {@link
   * #drawPeerActionSelectBox(HTMLNode, boolean)} to render action controls. Subclasses typically
   * enable this in advanced mode or when authenticated users manage darknet peers.
   *
   * @return {@code true} when bulk actions and selection controls should be displayed.
   */
  protected abstract boolean showPeerActionsBox();

  /**
   * Renders additional peer actions when {@link #showPeerActionsBox()} is enabled.
   *
   * <p>A form and per-peer checkboxes are already present. Implementations should add controls and
   * submit buttons appropriate for their network mode.
   *
   * @param peerForm form a node that already wraps the peer table and checkboxes; implementations
   *     add controls directly to this element.
   * @param advancedModeEnabled whether the UI is in advanced mode, enabling additional actions or
   *     diagnostics.
   */
  protected abstract void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled);

  /**
   * Determines whether the noderef textarea/download box should be displayed.
   *
   * <p>Darknet pages often show noderef exchange controls even for new users, whereas opennet pages
   * may hide them unless the advanced mode is active. Implementations should keep behavior stable
   * within a session so users are not surprised by disappearing controls.
   *
   * @param advancedModeEnabled whether the user requested advanced UI features.
   * @return {@code true} to render the noderef box; {@code false} to omit it for simpler layouts.
   */
  protected abstract boolean shouldDrawNoderefBox(boolean advancedModeEnabled);

  final HTMLNode refLink;
  final HTMLNode reftextLink;

  /**
   * @param contentNode Node to add noderef box to.
   * @param fs Noderef to render as text if requested.
   */
  void drawNoderefBox(HTMLNode contentNode, SimpleFieldSet fs) {
    HTMLNode referenceInfobox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL_CLASS);
    HTMLNode headerReferenceInfobox =
        referenceInfobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER_CLASS);
    // Better way to deal with this sort of thing???
    NodeL10n.getBase()
        .addL10nSubstitution(
            headerReferenceInfobox,
            "DarknetConnectionsToadlet.myReferenceHeader",
            new String[] {"linkref", "linktext"},
            new HTMLNode[] {refLink, reftextLink});
    HTMLNode referenceInfoboxContent =
        referenceInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);

    if (!isOpennet()) {
      HTMLNode myName = referenceInfoboxContent.addChild("p");
      myName.addChild(
          "span",
          NodeL10n.getBase()
              .getString("DarknetConnectionsToadlet.myName", "name", fs.get("myName")));
      myName.addChild("span", " [");
      myName
          .addChild("span")
          .addChild(
              "a",
              "href",
              "/config/node#name",
              NodeL10n.getBase().getString("DarknetConnectionsToadlet.changeMyName"));
      myName.addChild("span", "]");
    }

    HTMLNode warningSentence = referenceInfoboxContent.addChild("p");
    NodeL10n.getBase()
        .addL10nSubstitution(
            warningSentence,
            "DarknetConnectionsToadlet.referenceCopyWarning",
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    referenceInfoboxContent.addChild(
        "pre", "id", "reference", fs.toOrderedStringWithBase64() + '\n');

    if (!isOpennet()) {
      HTMLNode myIps = referenceInfoboxContent.addChild("p");
      myIps.addChild(
          "span",
          NodeL10n.getBase()
              .getString("DarknetConnectionsToadlet.myIps", "ips", fs.get("physical.udp")));
    }
  }

  /**
   * Draws the add-a-peer box that follows the main peers table.
   *
   * <p>The box includes textarea input, file upload control, and an optional private note field.
   * Subclasses may override to hide or extend the UI but should avoid altering form names to keep
   * POST handling compatible.
   *
   * @param contentNode container to which the infobox and form are appended.
   * @param ctx toadlet context providing form helpers and localization strings.
   */
  protected void drawAddPeerBox(HTMLNode contentNode, ToadletContext ctx) {
    drawAddPeerBox(contentNode, ctx, isOpennet(), path());
  }

  /**
   * Static helper that renders the add-peer form with configurable target and mode.
   *
   * <p>Used by both opennet and darknet views to avoid code duplication. The contents include
   * textarea paste input, file chooser, optional private note, and a Submit button. The form posts
   * to {@code formTarget} using multipart encoding.
   *
   * @param contentNode HTML container receiving the generated infobox and form.
   * @param ctx toadlet context used to build forms and resolve localization keys.
   * @param isOpennet whether the UI should hide darknet-only controls like private notes.
   * @param formTarget path that receives the POST submission for adding peers.
   */
  protected static void drawAddPeerBox(
      HTMLNode contentNode, ToadletContext ctx, boolean isOpennet, String formTarget) {
    // BEGIN PEER ADDITION BOX
    HTMLNode peerAdditionInfobox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL_CLASS);
    peerAdditionInfobox.addChild(
        "div",
        ATTR_CLASS,
        INFOBOX_HEADER_CLASS,
        l10n(isOpennet ? "addOpennetPeerTitle" : "addPeerTitle"));
    HTMLNode peerAdditionContent =
        peerAdditionInfobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT_CLASS);
    HTMLNode peerAdditionForm = ctx.addFormChild(peerAdditionContent, formTarget, "addPeerForm");
    peerAdditionForm.addChild("#", l10n("pasteReference"));
    peerAdditionForm.addChild("br");
    peerAdditionForm.addChild(
        "textarea",
        new String[] {"id", "name", "rows", "cols"},
        new String[] {"reftext", "ref", "8", "74"});
    peerAdditionForm.addChild("br");
    peerAdditionForm.addChild("#", (l10n("urlReference") + ' '));
    peerAdditionForm.addChild(
        ELEMENT_INPUT, new String[] {"id", "type", "name"}, new String[] {"refurl", "text", "url"});
    peerAdditionForm.addChild("br");
    peerAdditionForm.addChild("#", (l10n("fileReference") + ' '));
    peerAdditionForm.addChild(
        ELEMENT_INPUT,
        new String[] {"id", "type", "name"},
        new String[] {REF_FILE, "file", REF_FILE});
    peerAdditionForm.addChild("br");
    if (!isOpennet) {
      peerAdditionForm.addChild(new PeerTrustInputForAddPeerBoxNode());
      peerAdditionForm.addChild(new PeerVisibilityInputForAddPeerBoxNode());
    }

    if (!isOpennet) {
      peerAdditionForm.addChild("#", (l10n("enterDescription") + ' '));
      peerAdditionForm.addChild(
          ELEMENT_INPUT,
          new String[] {"id", "type", "name", "size", "maxlength", "value"},
          new String[] {PEER_PRIVATE_NOTE, "text", PEER_PRIVATE_NOTE, "16", "250", ""});
      peerAdditionForm.addChild("br");
    }
    peerAdditionForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", "value"},
        new String[] {"submit", "add", l10n("add")});
  }

  /**
   * Creates a comparator for peer listings using the requested column and direction.
   *
   * @param sortBy column key requested via HTTP parameter; may be {@code null} for default order.
   * @param reversed whether the comparator should invert the natural ordering to sort descending.
   * @return comparator suitable for {@link Arrays#sort(Object[])} on peer status arrays.
   */
  protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
    return new ComparatorByStatus(sortBy, reversed);
  }

  /**
   * Selects which runtime noderef view should back the local-reference UI for this page.
   *
   * @return runtime noderef view to export for this toadlet.
   */
  protected abstract NodeReferenceView noderefView();

  private SimpleFieldSet exportOwnNoderef() {
    return toSimpleFieldSet(nodeInfoPort.exportReference(noderefView(), false).root());
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

  private static PeerFieldSet toPeerFieldSet(SimpleFieldSet source) {
    if (source.isEmpty()) {
      return PeerFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(source.directKeyValues());
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : source.directSubsets().entrySet()) {
      PeerFieldSet subset = toPeerFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new PeerFieldSet(directValues, directSubsets);
  }

  private boolean matchesExpectedPeerType(SimpleFieldSet fieldSet) {
    return fieldSet.getBoolean(OPENNET, false) == isOpennet();
  }

  private static PeerTrust toPeerTrust(FRIEND_TRUST trust) {
    if (trust == null) {
      return PeerTrust.NORMAL;
    }
    return switch (trust) {
      case LOW -> PeerTrust.LOW;
      case NORMAL -> PeerTrust.NORMAL;
      case HIGH -> PeerTrust.HIGH;
    };
  }

  private static PeerVisibility toPeerVisibility(FRIEND_VISIBILITY visibility) {
    if (visibility == null) {
      return PeerVisibility.YES;
    }
    return switch (visibility) {
      case YES -> PeerVisibility.YES;
      case NAME_ONLY -> PeerVisibility.NAME_ONLY;
      case NO -> PeerVisibility.NO;
    };
  }

  private static PeerAdditionReturnCodes mapPeerAddFailure(PeerAddFailureReason reason) {
    return switch (reason) {
      case REF_PARSE_ERROR -> PeerAdditionReturnCodes.CANT_PARSE;
      case REF_SIGNATURE_INVALID -> PeerAdditionReturnCodes.INVALID_SIGNATURE;
      case CANNOT_PEER_WITH_SELF -> PeerAdditionReturnCodes.TRY_TO_ADD_SELF;
      case DUPLICATE_PEER_REF -> PeerAdditionReturnCodes.ALREADY_IN_REFERENCE;
      case OPENNET_DISABLED -> PeerAdditionReturnCodes.INTERNAL_ERROR;
    };
  }

  private void maybeWritePrivateDarknetComment(PeerSnapshot addedPeer, String privateComment) {
    if (isOpennet() || privateComment == null || privateComment.isBlank()) {
      return;
    }

    String identity = addedPeer.root().directValues().get("identity");
    if (identity == null || identity.isBlank()) {
      LOG.warn("Added darknet peer without identity in snapshot; skipping private note write");
      return;
    }

    try {
      peerPort.writePrivateDarknetComment(identity, privateComment);
    } catch (UnknownPeerException | DarknetPeerRequiredException | RuntimeException e) {
      LOG.warn(
          "Added darknet peer {} but failed to write private note; keeping peer addition",
          identity,
          e);
    }
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  /**
   * Sends a simple error page with optional navigation hints.
   *
   * @param ctx toadlet context used to build and send the HTML reply.
   * @param code HTTP status code to return to the client.
   * @param desc short description used as the page title and infobox heading.
   * @param message localized body text explaining the failure to the user.
   * @param returnToAddFriends whether to show a link back to the add-friend page or to the previous
   *     page.
   * @throws ToadletContextClosedException if the client connection is closed while sending output.
   * @throws IOException when writing the response fails.
   */
  protected void sendErrorPage(
      ToadletContext ctx, int code, String desc, String message, boolean returnToAddFriends)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(desc, ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode infoboxContent =
        ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
    infoboxContent.addChild("#", message);
    if (returnToAddFriends) {
      infoboxContent.addChild("br");
      infoboxContent.addChild(
          "a", "href", DarknetAddRefToadlet.PATH, l10n("returnToAddAFriendPage"));
      infoboxContent.addChild("br");
    } else {
      infoboxContent.addChild("br");
      infoboxContent.addChild("a", "href", ".", l10n("returnToPrevPage"));
      infoboxContent.addChild("br");
    }
    addHomepageLink(infoboxContent);

    writeHTMLReply(ctx, code, desc, page.generate());
  }
}
