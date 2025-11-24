package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.FilterMIMEType;
import network.crypta.client.filter.FoundURICallback;
import network.crypta.client.filter.PushingTagReplacerCallback;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.clients.http.updateableelements.ProgressBarElement;
import network.crypta.clients.http.updateableelements.ProgressInfoElement;
import network.crypta.clients.http.utils.UriFilterProxyHeaderParser;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.SHA256;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.HexUtil;
import network.crypta.support.MediaType;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SizeUtil;
import network.crypta.support.URIPreEncoder;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NoFreeBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serves as the primary HTTP toadlet for Crypta’s Freenet proxy, mapping incoming browser
 * navigation and download requests onto fetch operations inside the node. It routes GET/POST
 * traffic for the root path, progress pages, configuration shortcuts, and large-file workflows
 * while enforcing the node’s security posture and content-filtering rules.
 *
 * <p>The toadlet orchestrates request parsing, fetch context preparation, inline prefetch hooks,
 * and progressive rendering so that interactive users receive timely feedback even when data is
 * delayed. It respects gateway restrictions, threat levels, and MIME overrides while keeping
 * downloads and inline views within configured size limits. Typical usage is a single instance
 * created at startup and registered with the toadlet container.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Deriving user-visible URLs that encode size, retry, and filter preferences.
 *   <li>Dispatching fetches with optional WebPush progress updates and rendering interim pages.
 *   <li>Applying safety checks for dangerous RSS sniffing and content-type enforcement.
 *   <li>Redirecting legacy paths and serving small static endpoints such as Atom feeds.
 * </ul>
 *
 * <p>The class is not thread-safe; a single instance is reused by the container with per-request
 * state kept in {@link GetRequestWorkflow}. It is immutable aside from static size limits that may
 * be tuned at runtime by trusted code.
 *
 * @see Toadlet
 * @see QueueToadlet
 * @see FProxyFetchTracker
 */
public final class FProxyToadlet extends Toadlet implements RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(FProxyToadlet.class);

  private static final String L10N_PREFIX = "FProxyToadlet.";
  private static final String CLASS_ATTRIBUTE = "class";
  private static final String INFOBOX_HEADER_CLASS = "infobox-header";
  private static final String INFOBOX_CONTENT_CLASS = "infobox-content";
  private static final String INFOBOX_ERROR_CLASS = "infobox infobox-error";
  private static final String INFOBOX_INFORMATION_CLASS = "infobox infobox-information";
  private static final String HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
  private static final String NOSNIFF = "nosniff";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_TITLE = "title";
  private static final String TYPE_HIDDEN = "hidden";
  private static final String TYPE_SUBMIT = "submit";
  private static final String PARAM_FILTER_DATA = "filterData";
  private static final String PARAM_MAX_SIZE = "max-size";
  private static final String PARAM_FORCE = "force";
  private static final String PARAM_FORCED_DOWNLOAD = "forcedownload";
  private static final String DEFAULT_DOWNLOADS_PATH = defaultPath("downloads");
  private static final String DEFAULT_FRIENDS_PATH = defaultPath("friends");
  private static final String DEFAULT_CONFIG_PATH = defaultPath("config");
  private static final String DEFAULT_WELCOME_PATH = defaultPath("welcome");

  static final String DOWNLOADS_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.downloadsPath", DEFAULT_DOWNLOADS_PATH));
  static final String FRIENDS_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.friendsPath", DEFAULT_FRIENDS_PATH));
  static final String CONFIG_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.configPath", DEFAULT_CONFIG_PATH));
  static final String WELCOME_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.welcomePath", DEFAULT_WELCOME_PATH));

  private static final String CONFIG_NODE_PATH = CONFIG_PATH + "node";
  private static final String OBSOLETED_MESSAGE_KEY = "obsoleted";
  private static final String GO_BACK_TO_PREV_KEY = "goBackToPrev";
  private static final String TOADLET_HOMEPAGE_KEY = "Toadlet.homepage";
  private static final String ABORT_TO_HOMEPAGE_KEY = "abortToHomepage";
  private static final String OPEN_WITH_KEY_EXPLORER_KEY = L10N_PREFIX + "openWithKeyExplorer";
  static final String CATEGORY_BROWSING = L10N_PREFIX + "categoryBrowsing";
  static final String CATEGORY_QUEUE = L10N_PREFIX + "categoryQueue";
  static final String CATEGORY_FRIENDS = L10N_PREFIX + "categoryFriends";
  static final String CATEGORY_STATUS = L10N_PREFIX + "categoryStatus";
  static final String CATEGORY_CONFIG = L10N_PREFIX + "categoryConfig";

  static byte[] random;
  final NodeClientCore core;
  final ClientContext context;
  final FProxyFetchTracker fetchTracker;

  private static String defaultPath(String segment) {
    return "/" + segment + "/";
  }

  private static String normalizedPath(String path) {
    String normalized = path;
    if (!normalized.startsWith("/")) {
      normalized = "/" + normalized;
    }
    if (!normalized.endsWith("/")) {
      normalized = normalized + "/";
    }
    return normalized;
  }

  static final Set<String> prefetchAllowedTypes =
      new HashSet<>(
          Arrays.asList(
              "image/png",
              "image/jpeg",
              "image/gif",
              "image/webp",
              "audio/mp3",
              "audio/ogg",
              "video/ogg",
              "application/ogg"));

  // ?force= links become invalid after 2 hours.
  private static final long FORCE_GRAIN_INTERVAL = HOURS.toMillis(1);

  /** Maximum size for transparent pass-through. See config passthroughMaxSizeProgress */
  private static long maxLengthWithProgress =
      (100 * 1024 * 1024)
          * 11
          / 10; // 100MiB plus a bit due to buggy inserts, because our Windows installer is >70 MiB

  // nowadays

  private static long maxLengthNoProgress =
      (2 * 1024 * 1024) * 11 / 10; // 2MiB plus a bit due to buggy inserts

  static final URI welcome;

  /**
   * Default scheduling priority applied to user-facing FProxy fetches.
   *
   * <p>The value mirrors {@link RequestStarter#INTERACTIVE_PRIORITY_CLASS} so that progress pages,
   * inline views, and interactive downloads are treated as latency-sensitive work relative to
   * background tasks.
   */
  public static final short PRIORITY = RequestStarter.INTERACTIVE_PRIORITY_CLASS;

  static {
    try {
      welcome = new URI(WELCOME_PATH);
    } catch (URISyntaxException e) {
      throw new IllegalStateException("Broken URI constructor: " + e, e);
    }
  }

  // Legacy logMINOR removed; use LOG.isDebugEnabled() directly.

  // Prefetch support uses a fixed upper bound; adjust here if configuration is added.
  static final int MAX_PREFETCH = 50;

  /**
   * Returns the maximum payload length, in bytes, allowed when a progress page is available.
   *
   * <p>This limit controls how large a response can be streamed while the browser displays a
   * progress UI. It includes a small safety margin to accommodate inserts that slightly exceed the
   * configured ceiling due to encoding overhead.
   *
   * @return maximum response size in bytes when progress feedback is enabled.
   */
  public static long getMaxLengthWithProgress() {
    return maxLengthWithProgress;
  }

  /**
   * Sets the maximum payload length, in bytes, permitted when progress feedback is presented.
   *
   * <p>Callers should provide a positive value that reflects available memory and user experience
   * goals; values are applied globally for subsequent requests. No synchronization is performed, so
   * concurrent updates should be avoided.
   *
   * @param length new allowed size in bytes for progress-enabled transfers.
   */
  public static void setMaxLengthWithProgress(long length) {
    maxLengthWithProgress = length;
  }

  /**
   * Returns the maximum payload length, in bytes, allowed when no progress page is sent.
   *
   * <p>This smaller ceiling is used for plain downloads and programmatic clients that cannot render
   * progress UI, reducing resource usage for synchronous responses.
   *
   * @return maximum response size in bytes when progress feedback is disabled.
   */
  public static long getMaxLengthNoProgress() {
    return maxLengthNoProgress;
  }

  /**
   * Sets the maximum payload length, in bytes, for transfers without progress rendering.
   *
   * <p>Use this to cap synchronous or programmatic fetches; the value should remain conservative to
   * prevent accidental memory pressure when clients bypass the progress page workflow.
   *
   * @param length new allowed size in bytes for non-progress transfers.
   */
  public static void setMaxLengthNoProgress(long length) {
    maxLengthNoProgress = length;
  }

  /**
   * Creates a toadlet bound to the given client and node services.
   *
   * <p>The constructor wires the high-level client with size limits suitable for non-progress
   * transfers and caches references to the node core, client context, and fetch tracker. Instances
   * are expected to be registered once with the container and reused across requests.
   *
   * @param client high-level fetch client used to perform HTTP-facing retrievals.
   * @param core node core providing configuration, security levels, and download paths.
   * @param tracker shared fetch tracker coordinating progress reporting and reuse.
   */
  public FProxyToadlet(
      final HighLevelSimpleClient client, NodeClientCore core, FProxyFetchTracker tracker) {
    super(client);
    client.setMaxLength(getMaxLengthNoProgress());
    client.setMaxIntermediateLength(getMaxLengthNoProgress());
    this.core = core;
    this.context = core.getClientContext();
    fetchTracker = tracker;
  }

  @Override
  public boolean allowPOSTWithoutPassword() {
    return true;
  }

  /**
   * Handles POST requests to the toadlet entry point, redirecting to the welcome page when
   * applicable.
   *
   * <p>The method currently supports only root and servlet-prefixed paths, converting them into a
   * temporary redirect toward the welcome workflow. Validation is defensive: it rejects null inputs
   * and leaves other POST targets untouched.
   *
   * @param uri incoming request URI whose path determines redirect handling.
   * @param req parsed HTTP request object supplying parameters and headers.
   * @param ctx toadlet context for issuing redirects and access checks.
   * @throws RedirectException if the request should be redirected to another path.
   */
  public void handleMethodPOST(URI uri, HTTPRequest req, ToadletContext ctx)
      throws RedirectException {
    Objects.requireNonNull(req, "request");
    Objects.requireNonNull(ctx, "context");
    String ks = uri.getPath();

    if (ks.equals("/") || ks.startsWith("/servlet/")) {
      try {
        throw new RedirectException(WELCOME_PATH);
      } catch (URISyntaxException e) {
        // HUH!?!
      }
    }
  }

  static final HTMLNode DOWNLOADS_LINK = QueueToadlet.DOWNLOADS_LINK;

  private static void addDownloadOptions(
      ToadletContext ctx,
      HTMLNode optionList,
      FreenetURI key,
      String mimeType,
      boolean disableFiltration,
      boolean dontShowFilter,
      NodeClientCore core) {
    PHYSICAL_THREAT_LEVEL threatLevel = core.getNode().getSecurityLevels().getPhysicalThreatLevel();
    NETWORK_THREAT_LEVEL netLevel = core.getNode().getSecurityLevels().getNetworkThreatLevel();
    boolean filterChecked = shouldEnableFilter(mimeType, disableFiltration, threatLevel, netLevel);

    addDownloadToDiskOption(ctx, optionList, key, mimeType, filterChecked, dontShowFilter, core);
    addDirectFetchOption(ctx, optionList, key, mimeType, filterChecked, dontShowFilter, core);
  }

  private static boolean shouldEnableFilter(
      String mimeType,
      boolean disableFiltration,
      PHYSICAL_THREAT_LEVEL threatLevel,
      NETWORK_THREAT_LEVEL netLevel) {
    boolean filterChecked =
        !((threatLevel == PHYSICAL_THREAT_LEVEL.LOW && netLevel == NETWORK_THREAT_LEVEL.LOW)
            || disableFiltration);
    if (filterChecked
        && mimeType != null
        && !mimeType.equals("application/octet-stream")
        && !mimeType.isEmpty()) {
      FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
      if ((type == null || (!(type.safeToRead || type.readFilter != null)))
          && !(threatLevel == PHYSICAL_THREAT_LEVEL.HIGH
              || threatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM
              || netLevel == NETWORK_THREAT_LEVEL.HIGH
              || netLevel == NETWORK_THREAT_LEVEL.MAXIMUM)) {
        filterChecked = false;
      }
    }
    return filterChecked;
  }

  private static void addDownloadToDiskOption(
      ToadletContext ctx,
      HTMLNode optionList,
      FreenetURI key,
      String mimeType,
      boolean filterChecked,
      boolean dontShowFilter,
      NodeClientCore core) {
    PHYSICAL_THREAT_LEVEL threatLevel = core.getNode().getSecurityLevels().getPhysicalThreatLevel();
    if (threatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM || isDownloadDisabledOrUnsafe(ctx, core)) {
      return;
    }
    HTMLNode option = optionList.addChild("li");
    HTMLNode optionForm = ctx.addFormChild(option, DOWNLOADS_PATH, "tooBigQueueForm");
    optionForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_HIDDEN, "key", key.toString()});
    optionForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_HIDDEN, "return-type", "disk"});
    optionForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_HIDDEN, "persistence", "forever"});
    if (mimeType != null && !mimeType.isEmpty()) {
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_HIDDEN, "type", mimeType});
    }
    optionForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "download", l10n("downloadInBackgroundToDiskButton")});
    String downloadLocation = core.getDownloadsDir().getAbsolutePath();
    if (!core.allowDownloadTo(core.getDownloadsDir())) {
      downloadLocation = core.getAllowedDownloadDirs()[0].getAbsolutePath();
    }
    NodeL10n.getBase()
        .addL10nSubstitution(
            optionForm,
            "FProxyToadlet.downloadInBackgroundToDisk",
            new String[] {"dir", "page"},
            new HTMLNode[] {
              new HTMLNode(
                  TAG_INPUT,
                  new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, "maxlength", "size"},
                  new String[] {
                    "text",
                    "path",
                    downloadLocation,
                    Integer.toString(QueueToadlet.MAX_FILENAME_LENGTH),
                    String.valueOf(downloadLocation.length())
                  }),
              DOWNLOADS_LINK
            });
    optionForm.addChild("#", " ");
    NodeL10n.getBase()
        .addL10nSubstitution(
            optionForm,
            "FProxyToadlet.downloadToDiskWarningNotFiltered",
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    optionForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {
          TYPE_SUBMIT,
          "select-location",
          NodeL10n.getBase().getString("QueueToadlet.browseToChange") + "..."
        });
    if (!dontShowFilter) {
      addFilterControl(optionForm, filterChecked);
    }
    if (threatLevel == PHYSICAL_THREAT_LEVEL.HIGH) {
      optionForm.addChild("br");
      NodeL10n.getBase()
          .addL10nSubstitution(
              optionForm,
              "FProxyToadlet.downloadToDiskSecurityWarning",
              new String[] {"bold"},
              new HTMLNode[] {HTMLNode.STRONG});
    }
  }

  private static void addDirectFetchOption(
      ToadletContext ctx,
      HTMLNode optionList,
      FreenetURI key,
      String mimeType,
      boolean filterChecked,
      boolean dontShowFilter,
      NodeClientCore core) {
    PHYSICAL_THREAT_LEVEL threatLevel = core.getNode().getSecurityLevels().getPhysicalThreatLevel();
    if (threatLevel != PHYSICAL_THREAT_LEVEL.LOW || isDownloadDisabledOrUnsafe(ctx, core)) {
      HTMLNode option = optionList.addChild("li");
      HTMLNode optionForm = ctx.addFormChild(option, DOWNLOADS_PATH, "tooBigQueueForm");
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_HIDDEN, "key", key.toString()});
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_HIDDEN, "return-type", "direct"});
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_HIDDEN, "persistence", "forever"});
      if (mimeType != null && !mimeType.isEmpty()) {
        optionForm.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {TYPE_HIDDEN, "type", mimeType});
      }
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_SUBMIT, "download", l10n("downloadInBackgroundToTempSpaceButton")});
      NodeL10n.getBase()
          .addL10nSubstitution(
              optionForm,
              "FProxyToadlet.downloadInBackgroundToTempSpace",
              new String[] {"page", "bold"},
              new HTMLNode[] {DOWNLOADS_LINK, HTMLNode.STRONG});
      if (!dontShowFilter) {
        addFilterControl(optionForm, filterChecked);
      }
    }
  }

  private static void addFilterControl(HTMLNode optionForm, boolean filterChecked) {
    HTMLNode filterControl = optionForm.addChild("div", l10n(PARAM_FILTER_DATA));
    HTMLNode f =
        filterControl.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {"checkbox", PARAM_FILTER_DATA, PARAM_FILTER_DATA});
    if (filterChecked) {
      f.addAttribute("checked", "checked");
    }
    filterControl.addChild("div", l10n("filterDataMessage"));
  }

  static boolean isDownloadDisabledOrUnsafe(ToadletContext ctx, NodeClientCore core) {
    return
    // download is either disabled fully on this node
    core.isDownloadDisabled()
        // or we're accessing in public gateway mode and do not have full access
        || (ctx.getContainer().publicGatewayMode() && !ctx.isAllowedFullAccess());
  }

  /**
   * Resolves a localized string within the FProxy domain.
   *
   * @param msg localization key suffix to be prefixed with {@code FProxyToadlet.}.
   * @return resolved localized text, or a placeholder if no translation exists.
   */
  public static String l10n(String msg) {
    return NodeL10n.getBase().getString(L10N_PREFIX + msg);
  }

  /**
   * Checks whether the first 512 bytes resemble an RSS document as detected by Firefox’s sniffer.
   * This blacklist-style probe is a defensive workaround used before applying stricter MIME
   * handling, and may be removed once a whitelist is available. REDFLAG: expect future tightening.
   *
   * @param data bucket containing the fetched payload; only the first 512 bytes are inspected.
   * @return {@code true} when the leading bytes match Firefox’s RSS sniffing heuristics.
   * @throws IOException if the bucket stream cannot be read fully or is unexpectedly truncated.
   */
  private static boolean isSniffedAsFeed(Bucket data) throws IOException {
    int sz = (int) Math.min(data.size(), 512);
    if (sz == 0) return false;
    try (DataInputStream is = new DataInputStream(data.getInputStream())) {
      byte[] buf = new byte[sz];
      // Firefox currently doesn't detect RSS in UTF16 etc.
      is.readFully(buf);
      return RssSniffer.isSniffedAsFeed(buf);
    }
  }

  public void handleMethodGET(URI uri, HTTPRequest httprequest, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    innerHandleMethodGET(uri, httprequest, ctx, 0);
  }

  static final int MAX_RECURSION = 5;

  private void innerHandleMethodGET(
      URI uri, HTTPRequest httprequest, ToadletContext ctx, int recursion)
      throws ToadletContextClosedException, IOException, RedirectException {
    new GetRequestWorkflow(uri, httprequest, ctx, recursion).execute();
  }

  private final class GetRequestWorkflow {
    private final URI uri;
    private final HTTPRequest httprequest;
    private final ToadletContext ctx;
    private final int recursion;

    private String ks;
    private String ua;
    private String accept;
    private boolean canSendProgress;
    private long defaultMaxSize;
    private int maxRetries;
    private boolean restricted;
    private boolean overrideSize;
    private long maxSize;
    private long maxSizeDownload;
    private FreenetURI key;
    private FetchContext fctx;
    private String requestedMimeType;
    private String forceString;
    private String referer;
    private Bucket data;
    private String mimeType;
    private FetchException fetchException;
    private FProxyFetchResult fetchResult;
    private boolean forceDownloadRequested;

    GetRequestWorkflow(URI uri, HTTPRequest httprequest, ToadletContext ctx, int recursion) {
      this.uri = uri;
      this.httprequest = httprequest;
      this.ctx = ctx;
      this.recursion = recursion;
    }

    void execute() throws ToadletContextClosedException, IOException, RedirectException {
      initializeRequestMetadata();
      if (handleStaticPaths()) return;
      if (!validateRangeHeader()) return;
      if (!parseFreenetUri()) return;
      prepareFetchContext();
      performFetchWithProgress();
      finishResponse();
    }

    private void initializeRequestMetadata() {
      ks = uri.getPath();
      MultiValueTable<String, String> headers = ctx.getHeaders();
      ua = headers.getFirst("user-agent");
      accept = headers.getFirst("accept");
      if (LOG.isDebugEnabled()) LOG.debug("UA = {} accept = {}", ua, accept);
      forceDownloadRequested = httprequest.isParameterSet(PARAM_FORCED_DOWNLOAD);
      canSendProgress =
          isBrowser(ua)
              && !ctx.disableProgressPage()
              && (accept == null || accept.contains("text/html"))
              && !forceDownloadRequested;

      defaultMaxSize = canSendProgress ? getMaxLengthWithProgress() : getMaxLengthNoProgress();
      maxRetries = httprequest.getIntParam("max-retries", -2);
      restricted = (container.publicGatewayMode() && !ctx.isAllowedFullAccess());
      overrideSize = false;
      maxSize = defaultMaxSize;
      maxSizeDownload = getMaxLengthWithProgress();
      if (!restricted && httprequest.isParameterSet(PARAM_MAX_SIZE)) {
        maxSize = maxSizeDownload = httprequest.getLongParam(PARAM_MAX_SIZE, defaultMaxSize);
        overrideSize = true;
      }
    }

    private boolean handleStaticPaths()
        throws ToadletContextClosedException, IOException, RedirectException {
      switch (ks) {
        case "/" -> {
          handleRootWithoutKey();
          return true;
        }
        case "/favicon.ico" -> {
          return redirectTo(StaticToadlet.ROOT_URL + "favicon.ico");
        }
        case "/favicon.svg" -> {
          return redirectTo(StaticToadlet.ROOT_URL + "favicon.svg");
        }
        default -> {
          // fall through to additional path checks below
        }
      }
      if (ks.startsWith("/feed/") || ks.equals("/feed")) return handleFeedRequest();
      if (ks.equals("/robots.txt") && ctx.doRobots()) {
        writeTextReply(ctx, 200, "Ok", "User-agent: *\nDisallow: /");
        return true;
      }
      if (ks.startsWith("/darknet/") || ks.equals("/darknet")) {
        writePermanentRedirect(ctx, OBSOLETED_MESSAGE_KEY, FRIENDS_PATH);
        return true;
      }
      if (ks.startsWith("/opennet/") || ks.equals("/opennet")) {
        writePermanentRedirect(ctx, OBSOLETED_MESSAGE_KEY, "/strangers/");
        return true;
      }
      if (ks.startsWith("/queue/")) {
        writePermanentRedirect(ctx, OBSOLETED_MESSAGE_KEY, DOWNLOADS_PATH);
        return true;
      }
      if (ks.startsWith(CONFIG_PATH)) {
        writePermanentRedirect(ctx, OBSOLETED_MESSAGE_KEY, CONFIG_NODE_PATH);
        return true;
      }
      if (ks.startsWith("/")) ks = ks.substring(1);
      return false;
    }

    private void handleRootWithoutKey()
        throws RedirectException, ToadletContextClosedException, IOException {
      if (!httprequest.isParameterSet("key")) {
        redirectToWelcome();
        return;
      }

      String keyParam = httprequest.getParam("key");
      try {
        FreenetURI newURI = new FreenetURI(keyParam);
        if (LOG.isDebugEnabled()) LOG.debug("Redirecting to Crypta URI: {}", newURI);
        String requestedMime = httprequest.getParam("type");
        String location =
            getLink(
                newURI,
                requestedMime,
                maxSize,
                httprequest.getParam(PARAM_FORCE, null),
                httprequest.isParameterSet(PARAM_FORCED_DOWNLOAD),
                maxRetries,
                overrideSize);
        writeTemporaryRedirect(ctx, null, location);
      } catch (MalformedURLException e) {
        LOG.info("Invalid key: {} for {}", e, keyParam, e);
        sendErrorPage(
            ctx,
            404,
            l10n("notFoundTitle"),
            NodeL10n.getBase()
                .getString(
                    "FProxyToadlet.invalidKeyWithReason",
                    new String[] {"reason"},
                    new String[] {e.toString()}));
      }
    }

    private boolean redirectTo(String target) throws RedirectException {
      try {
        throw new RedirectException(target);
      } catch (URISyntaxException e) {
        throw new IllegalStateException(e);
      }
    }

    private void redirectToWelcome()
        throws RedirectException, IOException, ToadletContextClosedException {
      try {
        throw new RedirectException(
            new URI(null, null, null, -1, welcome.getPath(), uri.getQuery(), uri.getFragment()));
      } catch (URISyntaxException e) {
        LOG.error("Unexpected syntax error in URI: {}", e.getMessage(), e);
        writeTemporaryRedirect(
            ctx, "Internal error. Please check logs and report.", WelcomeToadlet.PATH);
      }
    }

    private boolean handleFeedRequest() throws ToadletContextClosedException, IOException {
      String schemeHostAndPort = getSchemeHostAndPort(ctx);
      String atom = ctx.getAlertManager().getAtom(schemeHostAndPort);
      byte[] buf = atom.getBytes(StandardCharsets.UTF_8);
      ctx.sendReplyHeadersFProxy(200, "OK", null, "application/atom+xml", buf.length);
      ctx.writeData(buf, 0, buf.length);
      return true;
    }

    private boolean validateRangeHeader() throws ToadletContextClosedException, IOException {
      String rangeStr = ctx.getHeaders().getFirst("range");
      if (rangeStr == null) return true;
      try {
        parseRange(rangeStr);
        return true;
      } catch (HTTPRangeException e) {
        LOG.info("Invalid Range Header: {}", rangeStr, e);
        ctx.sendReplyHeaders(416, "Requested Range Not Satisfiable", null, null, 0);
        return false;
      }
    }

    private boolean parseFreenetUri() throws ToadletContextClosedException, IOException {
      try {
        key = new FreenetURI(ks);
        return true;
      } catch (MalformedURLException e) {
        PageNode page = ctx.getPageMaker().getPageNode(l10n("invalidKeyTitle"), ctx);
        HTMLNode contentNode = page.getContentNode();

        HTMLNode errorInfobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_ERROR_CLASS);
        errorInfobox.addChild(
            "div",
            CLASS_ATTRIBUTE,
            INFOBOX_HEADER_CLASS,
            NodeL10n.getBase()
                .getString(
                    "FProxyToadlet.invalidKeyWithReason",
                    new String[] {"reason"},
                    new String[] {e.toString()}));
        HTMLNode errorContent =
            errorInfobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
        errorContent.addChild("#", l10n("expectedKeyButGot"));
        errorContent.addChild("code", ks);
        errorContent.addChild("br");
        errorContent.addChild(ctx.getPageMaker().createBackLink(ctx, l10n("goBack")));
        errorContent.addChild("br");
        addHomepageLink(errorContent);

        writeHTMLReply(ctx, 400, l10n("invalidKeyTitle"), page.generate());
        return false;
      }
    }

    private void prepareFetchContext() {
      fctx = getFetchContext(maxSize, getSchemeHostAndPort(ctx));
      maxSize = fctx.getMaxOutputLength();
      configureForceSettings();
      configureMimeOverrides();
      referer = sanitizeReferer(ctx);
    }

    private void configureForceSettings() {
      forceString = httprequest.getParam(PARAM_FORCE);
      long now = System.currentTimeMillis();
      boolean force =
          forceString != null
              && (forceString.equals(getForceValue(key, now))
                  || forceString.equals(getForceValue(key, now - FORCE_GRAIN_INTERVAL)));
      if (restricted) maxRetries = -2;
      if (maxRetries >= -1) {
        fctx.setMaxNonSplitfileRetries(maxRetries);
        fctx.setMaxSplitfileBlockRetries(maxRetries);
      }
      if (!force && !forceDownloadRequested) fctx.setFilterData(true);
      else if (LOG.isDebugEnabled()) LOG.debug("Content filter disabled via request parameter");
      if (container.enableInlinePrefetch()) {
        fctx.setPrefetchHook(createPrefetchHook());
      }
      if (container.isFProxyWebPushingEnabled()) {
        fctx.setTagReplacer(
            new PushingTagReplacerCallback(core.getFProxy().fetchTracker, defaultMaxSize, ctx));
      }
    }

    private void configureMimeOverrides() {
      requestedMimeType = httprequest.getParam("type", null);
      fctx.setOverrideMIME(requestedMimeType);
      String maybeCharset =
          httprequest.isParameterSet("maybecharset")
              ? httprequest.getParam("maybecharset", null)
              : null;
      fctx.setCharset(maybeCharset);
    }

    private FoundURICallback createPrefetchHook() {
      return new FoundURICallback() {

        final List<FreenetURI> uris = new ArrayList<>();

        @Override
        public void foundURI(FreenetURI uri) {
          // Ignore
        }

        @Override
        public void foundURI(FreenetURI uri, boolean inline) {
          if (!inline) return;
          if (LOG.isDebugEnabled()) LOG.debug("Prefetching {}", uri);
          synchronized (this) {
            if (uris.size() < MAX_PREFETCH) uris.add(uri);
          }
        }

        @Override
        public void onText(String text, String type, URI baseURI) {
          // Ignore
        }

        @Override
        public void onFinishedPage() {
          core.getNode()
              .getExecutor()
              .execute(
                  () -> {
                    for (FreenetURI uri1 : uris) {
                      client.prefetch(
                          uri1, SECONDS.toMillis(60), 512L * 1024, prefetchAllowedTypes);
                    }
                  });
        }
      };
    }

    private void performFetchWithProgress() throws ToadletContextClosedException, IOException {
      try {
        fetchContent();
      } catch (FetchException e) {
        fetchException = e;
      }
    }

    private void fetchContent() throws FetchException, ToadletContextClosedException, IOException {
      FProxyFetchWaiter fetch =
          fetchTracker.makeFetcher(key, maxSize, fctx, ctx.getReFilterPolicy());
      boolean waitingForFetch = true;
      while (waitingForFetch && fetch != null) {
        fetchResult = fetch.getResult(!canSendProgress);
        if (fetchResult.hasData()) {
          if (shouldRefetchLaterEdition(fetchResult, key)) {
            LOG.info("Loading later edition...");
            fetch.progress.requestImmediateCancel();
            fetchResult.close();
            fetch = fetchTracker.makeFetcher(key, maxSize, fctx, ctx.getReFilterPolicy());
            waitingForFetch = fetch != null;
          } else {
            cacheFetcherData(fetch);
            waitingForFetch = false;
          }
        } else if (fetchResult.failed != null) {
          fetchException = fetchResult.failed;
          fetch.close();
          waitingForFetch = false;
        } else if (canSendProgress) {
          renderProgressPage(fetch);
          return;
        } else {
          fetchResult.close();
        }
      }
    }

    private void cacheFetcherData(FProxyFetchWaiter fetch) {
      if (LOG.isDebugEnabled()) LOG.debug("Found data");
      data = new NoFreeBucket(fetchResult.data);
      mimeType = fetchResult.mimeType;
      fetch.close();
    }

    private void renderProgressPage(FProxyFetchWaiter fetch)
        throws ToadletContextClosedException, IOException {
      boolean isJsEnabled =
          ctx.getContainer().isFProxyJavascriptEnabled()
              && ua != null
              && !ua.contains("AppleWebKit/");
      boolean isWebPushingEnabled = false;
      PageNode page = ctx.getPageMaker().getPageNode(l10n("fetchingPageTitle"), ctx);
      String location =
          getLink(
              key,
              requestedMimeType,
              maxSize,
              httprequest.getParam(PARAM_FORCE, null),
              httprequest.isParameterSet(PARAM_FORCED_DOWNLOAD),
              maxRetries,
              overrideSize);
      HTMLNode headNode = page.getHeadNode();
      if (isJsEnabled) {
        isWebPushingEnabled = ctx.getContainer().isFProxyWebPushingEnabled();
        headNode
            .addChild("noscript")
            .addChild("meta", "http-equiv", "Refresh")
            .addAttribute("content", "2;URL=" + location);
        if (!isWebPushingEnabled) {
          HTMLNode scriptNode = headNode.addChild("script", "//abc");
          scriptNode.addAttribute("type", "text/javascript");
          scriptNode.addAttribute("src", "/static/js/progresspage.js");
        }
      } else {
        headNode
            .addChild("meta", "http-equiv", "Refresh")
            .addAttribute("content", "2;URL=" + location);
      }
      HTMLNode contentNode = page.getContentNode();
      HTMLNode infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_INFORMATION_CLASS);
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("fetchingPageBox"));
      HTMLNode infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
      infoboxContent.addAttribute("id", "infoContent");
      infoboxContent.addChild(
          new ProgressInfoElement(
              fetchTracker,
              key,
              fctx,
              maxSize,
              ctx.isAdvancedModeEnabled(),
              ctx,
              isWebPushingEnabled));

      HTMLNode table = infoboxContent.addChild("table", "border", "0");
      HTMLNode progressCell =
          table.addChild("tr").addChild("td", CLASS_ATTRIBUTE, "request-progress");
      if (fetchResult.totalBlocks <= 0)
        progressCell.addChild("#", NodeL10n.getBase().getString("QueueToadlet.unknown"));
      else {
        progressCell.addChild(
            new ProgressBarElement(fetchTracker, key, fctx, maxSize, ctx, isWebPushingEnabled));
      }

      infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_INFORMATION_CLASS);
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("fetchingPageOptions"));
      infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);

      HTMLNode optionList = infoboxContent.addChild("ul");
      optionList.addChild("li").addChild("p", l10n("progressOptionZero"));

      addDownloadOptions(ctx, optionList, key, mimeType, false, false, core);

      optionList
          .addChild("li")
          .addChild(ctx.getPageMaker().createBackLink(ctx, l10n(GO_BACK_TO_PREV_KEY)));
      optionList
          .addChild("li")
          .addChild(
              "a",
              new String[] {"href", ATTR_TITLE},
              new String[] {"/", NodeL10n.getBase().getString(TOADLET_HOMEPAGE_KEY)},
              l10n(ABORT_TO_HOMEPAGE_KEY));

      MultiValueTable<String, String> retHeaders = new MultiValueTable<>();
      writeHTMLReply(ctx, 200, "OK", retHeaders, page.generate());
      fetchResult.close();
      fetch.close();
    }

    private void finishResponse()
        throws ToadletContextClosedException, IOException, RedirectException {
      try {
        if (LOG.isDebugEnabled()) LOG.debug("FProxy fetching {} ({})", key, maxSize);
        ensureDataIsAvailable();
        sendDownloadResponse();
      } catch (FetchException e) {
        handleFetchException(e);
      } catch (SocketException e) {
        if ("Broken pipe".equals(e.getMessage())) {
          if (LOG.isDebugEnabled()) LOG.debug("Caught {} while handling GET", e.getMessage(), e);
        } else {
          LOG.info("Caught {}", e.getMessage(), e);
        }
        throw e;
      } catch (Exception t) {
        writeInternalError(t, ctx);
      } finally {
        if (fetchResult == null && data != null) data.free();
        if (fetchResult != null) fetchResult.close();
      }
    }

    private void ensureDataIsAvailable() throws FetchException {
      if (data == null && fetchException == null) {
        reuseInProgressFetch();
      }
      if (data == null && fetchException == null) {
        FetchResult result =
            fetch(key, maxSize, new RequestClientBuilder().realTime().build(), fctx);
        data = result.asBucket();
        mimeType = result.getMimeType();
      } else if (fetchException != null) {
        throw fetchException;
      }
    }

    private void sendDownloadResponse() throws ToadletContextClosedException, IOException {
      handleDownload(data, "&max-size=" + maxSizeDownload);
    }

    private void handleDownload(Bucket data, String extras)
        throws ToadletContextClosedException, IOException {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "handleDownload(data.size={}, mimeType={}, requestedMimeType={}, forceDownload={},"
                + " basePath={}, key={})",
            data.size(),
            mimeType,
            requestedMimeType,
            forceDownloadRequested,
            "/",
            key);
      }
      String updatedExtras = appendRequestedMimeType(extras, requestedMimeType, mimeType);
      long size = data.size();

      long now = System.currentTimeMillis();
      boolean force = isForceRequested(forceString, key, now);

      if (!force && !forceDownloadRequested) {
        mimeType = adjustMimeForBrowserWorkarounds(mimeType);
        if (handleDangerousRss(data, mimeType, now, extras, updatedExtras, referer)) {
          return;
        }
      }

      if (forceDownloadRequested) {
        sendForcedDownload(ctx, data, key, size);
        return;
      }

      sendRangeOrFullResponse(ctx, ctx.getBucketFactory(), mimeType, key, ctx, data, size);
    }

    private String adjustMimeForBrowserWorkarounds(String mimeType) {
      if ("application/xhtml+xml".equals(mimeType)) {
        return "text/html";
      }
      return mimeType;
    }

    private boolean handleDangerousRss(
        Bucket data,
        String mimeType,
        long now,
        String extras,
        String updatedExtras,
        String referrer)
        throws IOException, ToadletContextClosedException {
      if (!isSniffedAsFeed(data) || mimeType.startsWith("application/rss+xml")) {
        return false;
      }
      PageNode page = ctx.getPageMaker().getPageNode(l10n("dangerousRSSTitle"), ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, "infobox infobox-alert");
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("dangerousRSSSubtitle"));
      HTMLNode infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
      infoboxContent.addChild(
          "#",
          NodeL10n.getBase()
              .getString(
                  "FProxyToadlet.dangerousRSS", new String[] {"type"}, new String[] {mimeType}));
      infoboxContent.addChild("p", l10n("options"));
      HTMLNode optionList = infoboxContent.addChild("ul");
      HTMLNode option = optionList.addChild("li");

      NodeL10n.getBase()
          .addL10nSubstitution(
              option,
              "FProxyToadlet.openPossRSSAsPlainText",
              new String[] {"link", "bold"},
              new HTMLNode[] {
                HTMLNode.link(
                    "/"
                        + key.toString()
                        + "?type=text/plain&force="
                        + getForceValue(key, now)
                        + extras),
                HTMLNode.STRONG
              });
      option = optionList.addChild("li");
      NodeL10n.getBase()
          .addL10nSubstitution(
              option,
              "FProxyToadlet.openPossRSSForceDisk",
              new String[] {"link", "bold"},
              new HTMLNode[] {
                HTMLNode.link("/" + key.toString() + "?forcedownload" + updatedExtras),
                HTMLNode.STRONG
              });
      boolean mimeRss =
          mimeType.startsWith("application/xml+rss") || mimeType.startsWith("text/xml");
      if (!(mimeRss || mimeType.startsWith("text/plain"))) {
        option = optionList.addChild("li");
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                "FProxyToadlet.openRSSForce",
                new String[] {"link", "bold", "mime"},
                new HTMLNode[] {
                  HTMLNode.link(
                      "/" + key.toString() + "?force=" + getForceValue(key, now) + updatedExtras),
                  HTMLNode.STRONG,
                  HTMLNode.text(mimeType)
                });
      }
      option = optionList.addChild("li");
      NodeL10n.getBase()
          .addL10nSubstitution(
              option,
              "FProxyToadlet.openRSSAsRSS",
              new String[] {"link", "bold"},
              new HTMLNode[] {
                HTMLNode.link(
                    "/"
                        + key.toString()
                        + "?type=application/xml+rss&force="
                        + getForceValue(key, now)
                        + extras),
                HTMLNode.STRONG
              });
      addDownloadOptions(ctx, optionList, key, mimeType, true, false, core);
      if (referrer != null) {
        option = optionList.addChild("li");
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                "FProxyToadlet.backToReferrer",
                new String[] {"link"},
                new HTMLNode[] {HTMLNode.link(referrer)});
      }
      option = optionList.addChild("li");
      NodeL10n.getBase()
          .addL10nSubstitution(
              option,
              "FProxyToadlet.backToFProxy",
              new String[] {"link"},
              new HTMLNode[] {HTMLNode.link("/")});

      byte[] pageBytes = page.generate().getBytes(StandardCharsets.UTF_8);
      ctx.sendReplyHeaders(
          200, "OK", new MultiValueTable<>(), "text/html; charset=utf-8", pageBytes.length);
      ctx.writeData(pageBytes);
      return true;
    }

    private String appendRequestedMimeType(
        String extras, String requestedMimeType, String mimeType) {
      String updatedExtras = extras;
      if (requestedMimeType != null && !requestedMimeType.equals(mimeType)) {
        if (updatedExtras == null) {
          updatedExtras = "";
        }
        updatedExtras = updatedExtras + "&type=" + requestedMimeType;
      }
      return updatedExtras;
    }

    private boolean isForceRequested(String forceString, FreenetURI key, long now) {
      if (forceString == null) {
        return false;
      }
      return forceString.equals(getForceValue(key, now))
          || forceString.equals(getForceValue(key, now - FORCE_GRAIN_INTERVAL));
    }

    private void sendForcedDownload(ToadletContext context, Bucket data, FreenetURI key, long size)
        throws ToadletContextClosedException, IOException {
      MultiValueTable<String, String> headers = new MultiValueTable<>(4);
      headers.put(
          "Content-Disposition", "attachment; filename=\"" + key.getPreferredFilename() + '\"');
      headers.put("Cache-Control", "private");
      headers.put("Content-Transfer-Encoding", "binary");
      headers.put(HEADER_X_CONTENT_TYPE_OPTIONS, NOSNIFF);
      context.sendReplyHeadersFProxy(200, "OK", headers, "application/force-download", size);
      context.writeData(data);
    }

    private void sendRangeOrFullResponse(
        ToadletContext context,
        BucketFactory bucketFactory,
        String mimeType,
        FreenetURI key,
        ToadletContext ctx,
        Bucket data,
        long size)
        throws ToadletContextClosedException, IOException {
      MultiValueTable<String, String> hdr = context.getHeaders();

      /*
       * Firefox and its derivatives may use the MIME type implied by the filename extension for
       * plain text, unless a Content-Encoding is specified.
       *
       * See https://developer.mozilla.org/en-US/docs/Mozilla/How_Mozilla_determines_MIME_Types#HTTP
       */
      MultiValueTable<String, String> retHdr = MultiValueTable.from("Content-Encoding", "identity");

      String rangeStr = hdr.getFirst("range");
      if (rangeStr != null) {
        long[] range;
        try {
          range = parseRange(rangeStr);
        } catch (HTTPRangeException e) {
          ctx.sendReplyHeaders(416, "Requested Range Not Satisfiable", null, null, 0);
          return;
        }
        if (range[1] == -1 || range[1] >= size) {
          range[1] = size - 1;
        }
        Bucket tmpRange = bucketFactory.makeBucket(range[1] - range[0]);
        try (InputStream is = data.getInputStream();
            OutputStream os = tmpRange.getOutputStream()) {
          if (range[0] > 0) {
            FileUtil.skipFully(is, range[0]);
          }
          FileUtil.copy(is, os, range[1] - range[0] + 1);
        }
        retHdr.put("Content-Range", "bytes " + range[0] + "-" + range[1] + "/" + size);
        retHdr.put(HEADER_X_CONTENT_TYPE_OPTIONS, NOSNIFF);
        context.sendReplyHeadersFProxy(206, "Partial content", retHdr, mimeType, tmpRange.size());
        context.writeData(tmpRange);
        return;
      }

      retHdr.put(HEADER_X_CONTENT_TYPE_OPTIONS, NOSNIFF);
      if (container.enableCachingForChkAndSskKeys() && (key.isCHK() || key.isSSK())) {
        context.sendReplyHeadersStatic(200, "OK", retHdr, mimeType, size, new Date());
      } else {
        context.sendReplyHeadersFProxy(200, "OK", retHdr, mimeType, size);
      }
      context.writeData(data);
    }

    private void reuseInProgressFetch() {
      boolean needsFetch = true;
      FProxyFetchInProgress progress = fetchTracker.getFetchInProgress(key, maxSize, fctx);
      if (progress == null) {
        return;
      }
      FProxyFetchWaiter waiter = null;
      FProxyFetchResult result = null;
      try {
        waiter = progress.getWaiter();
        result = waiter.getResult(false);
        if (result.failed == null && result.data != null) {
          mimeType = result.mimeType;
          try {
            data = ctx.getBucketFactory().makeBucket(result.data.size());
            BucketTools.copy(result.data, data);
            needsFetch = false;
          } catch (IOException e) {
            LOG.warn("Failed to reuse in-progress fetch result: {}", e.getMessage(), e);
            data = null;
          }
        }
      } finally {
        if (waiter != null) {
          progress.close(waiter);
        }
        if (result != null) {
          progress.close(result);
        }
      }
      if (needsFetch) {
        data = null;
      }
    }

    private void handleFetchException(FetchException e)
        throws ToadletContextClosedException, IOException, RedirectException {
      String msg = e.getMessage();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Failed to fetch {} : {}", uri, e.getMessage(), e);
      }
      if (e.newURI != null) {
        handleRedirectException(e);
        return;
      }
      if (e.mode == FetchExceptionMode.TOO_BIG) {
        handleTooBigException(e);
        return;
      }
      handleGenericFetchException(e, msg);
    }

    private void handleRedirectException(FetchException e)
        throws ToadletContextClosedException, IOException, RedirectException {
      FreenetURI redirectUri = Objects.requireNonNull(e.newURI, "redirect URI is null");
      if (accept != null
          && (accept.startsWith("text/css") || accept.startsWith("image/"))
          && recursion + 1 < MAX_RECURSION) {
        followRedirectRecursively(redirectUri);
        return;
      }
      Toadlet.writePermanentRedirect(
          ctx,
          e.getMessage(),
          getLink(
              redirectUri,
              requestedMimeType,
              maxSize,
              httprequest.getParam(PARAM_FORCE, null),
              httprequest.isParameterSet(PARAM_FORCED_DOWNLOAD),
              maxRetries,
              overrideSize));
    }

    private void followRedirectRecursively(FreenetURI redirectUri)
        throws RedirectException, ToadletContextClosedException, IOException {
      String link =
          getLink(
              redirectUri,
              requestedMimeType,
              maxSize,
              httprequest.getParam(PARAM_FORCE, null),
              httprequest.isParameterSet(PARAM_FORCED_DOWNLOAD),
              maxRetries,
              overrideSize);
      try {
        URI redirected = new URI(link);
        innerHandleMethodGET(redirected, httprequest, ctx, recursion + 1);
      } catch (URISyntaxException e1) {
        LOG.error("Caught {} parsing new link {}", e1.getMessage(), link, e1);
      }
    }

    private void handleTooBigException(FetchException e)
        throws ToadletContextClosedException, IOException {
      PageNode page = ctx.getPageMaker().getPageNode(l10n("fileInformationTitle"), ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_INFORMATION_CLASS);
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("largeFile"));
      HTMLNode infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
      HTMLNode fileInformationList = infoboxContent.addChild("ul");
      HTMLNode option = fileInformationList.addChild("li");
      option.addChild("#", (l10n("filenameLabel") + ' '));
      option.addChild("a", "href", '/' + key.toString(), getFilename(key, e.getExpectedMimeType()));

      String mime = writeSizeAndMIME(fileInformationList, e);

      infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_INFORMATION_CLASS);
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("explanationTitle"));
      infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
      infoboxContent.addChild("#", l10n("largeFileExplanationAndOptions"));
      HTMLNode optionList = infoboxContent.addChild("ul");
      if (!restricted) {
        addLargeFileFetchForm(e, optionList, mime);
      }

      optionList
          .addChild("li")
          .addChild(
              "a",
              new String[] {"href", ATTR_TITLE},
              new String[] {"/", NodeL10n.getBase().getString(TOADLET_HOMEPAGE_KEY)},
              l10n(ABORT_TO_HOMEPAGE_KEY));
      optionList
          .addChild("li")
          .addChild(ctx.getPageMaker().createBackLink(ctx, l10n(GO_BACK_TO_PREV_KEY)));

      writeHTMLReply(ctx, 200, "OK", page.generate());
    }

    private void addLargeFileFetchForm(FetchException e, HTMLNode optionList, String mime) {
      HTMLNode option = optionList.addChild("li");
      HTMLNode optionForm =
          option.addChild(
              "form",
              new String[] {"action", "method"},
              new String[] {'/' + key.toString(), "get"});
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            TYPE_HIDDEN,
            PARAM_MAX_SIZE,
            String.valueOf(e.getExpectedSize() == -1 ? Long.MAX_VALUE : e.getExpectedSize() * 2)
          });
      if (requestedMimeType != null)
        optionForm.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {TYPE_HIDDEN, "type", requestedMimeType});
      if (maxRetries >= -1)
        optionForm.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {TYPE_HIDDEN, "max-retries", Integer.toString(maxRetries)});
      optionForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_SUBMIT, "fetch", l10n("fetchLargeFileAnywayAndDisplayButton")});
      optionForm.addChild("#", " - " + l10n("fetchLargeFileAnywayAndDisplay"));
      addDownloadOptions(ctx, optionList, key, mime, false, false, core);
    }

    private void handleGenericFetchException(FetchException e, String msg)
        throws ToadletContextClosedException, IOException {
      PageNode page = ctx.getPageMaker().getPageNode(e.getShortMessage(), ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_ERROR_CLASS);
      infobox.addChild(
          "div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10nErrorWithReason(e.getShortMessage()));
      HTMLNode infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
      HTMLNode fileInformationList = infoboxContent.addChild("ul");
      HTMLNode option = fileInformationList.addChild("li");
      option.addChild("#", (l10n("filenameLabel") + ' '));
      option.addChild("a", "href", '/' + key.toString(), getFilename(key, e.getExpectedMimeType()));

      String mime = writeSizeAndMIME(fileInformationList, e);
      UnsafeContentTypeException filterException = null;
      if (e.getCause() instanceof UnsafeContentTypeException cause) {
        filterException = cause;
      }
      addFetchExplanationSection(contentNode, msg, e, filterException);
      addFetchOptionsSection(contentNode, mime, filterException, e);

      writeHTMLReply(
          ctx,
          (e.mode == FetchExceptionMode.NOT_IN_ARCHIVE) ? 404 : 500,
          "Internal Error",
          page.generate());
    }

    private void addFetchExplanationSection(
        HTMLNode contentNode,
        String msg,
        FetchException e,
        UnsafeContentTypeException filterException) {
      HTMLNode infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_ERROR_CLASS);
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("explanationTitle"));
      HTMLNode infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
      if (filterException == null) infoboxContent.addChild("p", l10n("unableToRetrieve"));
      else infoboxContent.addChild("p", l10n("unableToSafelyDisplay"));
      if (e.isFatal() && filterException == null)
        infoboxContent.addChild("p", l10n("errorIsFatal"));
      infoboxContent.addChild("p", msg);
      if (filterException != null && filterException.details() != null) {
        HTMLNode detailList = infoboxContent.addChild("ul");
        for (String detail : filterException.details()) {
          detailList.addChild("li", detail);
        }
      }
      if (e.errorCodes != null) {
        infoboxContent.addChild("p").addChild("pre").addChild("#", e.errorCodes.toVerboseString());
      }
    }

    private void addFetchOptionsSection(
        HTMLNode contentNode,
        String mime,
        UnsafeContentTypeException filterException,
        FetchException e) {
      HTMLNode infobox = contentNode.addChild("div", CLASS_ATTRIBUTE, INFOBOX_ERROR_CLASS);
      infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, l10n("options"));
      HTMLNode infoboxContent = infobox.addChild("div", CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);

      HTMLNode optionList = infoboxContent.addChild("ul");
      appendPluginOptions(optionList, e);
      if (filterException != null) {
        addFilterRecoveryOptions(optionList, mime, e);
      }
      addRetryAndAbortOptions(optionList, e);
    }

    private void appendPluginOptions(HTMLNode optionList, FetchException e) {
      PluginInfoWrapper keyUtil;
      if (!(e.mode == FetchExceptionMode.NOT_IN_ARCHIVE
          || e.mode == FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS)) {
        return;
      }
      if ((keyUtil =
              core.getNode()
                  .getPluginManager()
                  .getPluginInfoByClassName("plugins.KeyUtils.KeyUtilsPlugin"))
          != null) {
        appendKeyUtilsOptions(optionList, keyUtil);
        return;
      }
      if ((keyUtil =
              core.getNode()
                  .getPluginManager()
                  .getPluginInfoByClassName("plugins.KeyExplorer.KeyExplorer"))
          != null) {
        appendKeyExplorerOptions(optionList, keyUtil);
      }
    }

    private void appendKeyUtilsOptions(HTMLNode optionList, PluginInfoWrapper keyUtil) {
      HTMLNode option = optionList.addChild("li");
      if (keyUtil.getPluginLongVersion() < 5010)
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                OPEN_WITH_KEY_EXPLORER_KEY,
                new String[] {"link"},
                new HTMLNode[] {HTMLNode.link("/KeyUtils/?automf=true&key=" + key.toString())});
      else {
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                OPEN_WITH_KEY_EXPLORER_KEY,
                new String[] {"link"},
                new HTMLNode[] {HTMLNode.link("/KeyUtils/?key=" + key.toString())});
        option = optionList.addChild("li");
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                "FProxyToadlet.openWithSiteExplorer",
                new String[] {"link"},
                new HTMLNode[] {HTMLNode.link("/KeyUtils/Site?key=" + key.toString())});
      }
    }

    private void appendKeyExplorerOptions(HTMLNode optionList, PluginInfoWrapper keyUtil) {
      HTMLNode option = optionList.addChild("li");
      if (keyUtil.getPluginLongVersion() > 4999)
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                OPEN_WITH_KEY_EXPLORER_KEY,
                new String[] {"link"},
                new HTMLNode[] {HTMLNode.link("/KeyExplorer/?automf=true&key=" + key.toString())});
      else
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                OPEN_WITH_KEY_EXPLORER_KEY,
                new String[] {"link"},
                new HTMLNode[] {
                  HTMLNode.link("/plugins/plugins.KeyExplorer.KeyExplorer/?key=" + key.toString())
                });
    }

    private void addFilterRecoveryOptions(HTMLNode optionList, String mime, FetchException e) {
      if ((mime.equals("application/x-freenet-index"))
          && (core.getNode()
              .getPluginManager()
              .isPluginLoaded("plugins.ThawIndexBrowser.ThawIndexBrowser"))) {
        HTMLNode option = optionList.addChild("li");
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                "FProxyToadlet.openAsThawIndex",
                new String[] {"link"},
                new HTMLNode[] {
                  HTMLNode.link(
                      "/plugins/plugins.ThawIndexBrowser.ThawIndexBrowser/?key=" + key.toString())
                });
      }
      HTMLNode option = optionList.addChild("li");
      try {
        MediaType textMediaType = new MediaType("text/plain");
        textMediaType.setParameter(
            "charset",
            (e.getExpectedMimeType() != null)
                ? MediaType.getCharsetRobust(e.getExpectedMimeType())
                : null);
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                "FProxyToadlet.openAsText",
                new String[] {"link"},
                new HTMLNode[] {
                  HTMLNode.link(
                      getLink(
                          key,
                          textMediaType.toString(),
                          maxSize,
                          null,
                          false,
                          maxRetries,
                          overrideSize))
                });
      } catch (MalformedURLException ex) {
        LOG.error("Failed to build text/plain media type: {}", ex.getMessage(), ex);
      }
      option = optionList.addChild("li");
      NodeL10n.getBase()
          .addL10nSubstitution(
              option,
              "FProxyToadlet.openForceDisk",
              new String[] {"link"},
              new HTMLNode[] {
                HTMLNode.link(getLink(key, mime, maxSize, null, true, maxRetries, overrideSize))
              });
      if (!(mime.equals("application/octet-stream")
          || mime.equals("application/x-msdownload")
          || !DefaultMIMETypes.isPlausibleMIMEType(mime))) {
        option = optionList.addChild("li");
        NodeL10n.getBase()
            .addL10nSubstitution(
                option,
                "FProxyToadlet.openForce",
                new String[] {"link", "mime"},
                new HTMLNode[] {
                  HTMLNode.link(
                      getLink(
                          key,
                          mime,
                          maxSize,
                          getForceValue(key, System.currentTimeMillis()),
                          false,
                          maxRetries,
                          overrideSize)),
                  HTMLNode.text(HTMLEncoder.encode(mime))
                });
      }
    }

    private void addRetryAndAbortOptions(HTMLNode optionList, FetchException e) {
      if ((!e.isFatal() || e.getCause() instanceof UnsafeContentTypeException)
          && (ctx.isAllowedFullAccess() || !container.publicGatewayMode())) {
        addDownloadOptions(
            ctx,
            optionList,
            key,
            mimeType,
            e.getCause() instanceof UnsafeContentTypeException,
            e.getCause() instanceof UnsafeContentTypeException,
            core);
        if (!(e.getCause() instanceof UnsafeContentTypeException)) {
          optionList
              .addChild("li")
              .addChild(
                  "a",
                  "href",
                  getLink(
                      key,
                      requestedMimeType,
                      maxSize,
                      httprequest.getParam(PARAM_FORCE, null),
                      httprequest.isParameterSet(PARAM_FORCED_DOWNLOAD),
                      maxRetries,
                      overrideSize))
              .addChild("#", l10n("retryNow"));
        }
      }
      optionList
          .addChild("li")
          .addChild(
              "a",
              new String[] {"href", ATTR_TITLE},
              new String[] {"/", NodeL10n.getBase().getString(TOADLET_HOMEPAGE_KEY)},
              l10n(ABORT_TO_HOMEPAGE_KEY));
      optionList
          .addChild("li")
          .addChild(ctx.getPageMaker().createBackLink(ctx, l10n(GO_BACK_TO_PREV_KEY)));
    }

    private boolean shouldRefetchLaterEdition(FProxyFetchResult result, FreenetURI key) {
      try {
        return result.getFetchCount() > 1
            && !result.hasWaited()
            && key.isUSK()
            && context.uskManager.lookupKnownGood(USK.create(key)) > key.getSuggestedEdition();
      } catch (MalformedURLException e) {
        LOG.warn("Unable to create USK for {}", key, e);
        return false;
      }
    }

    private String getSchemeHostAndPort(ToadletContext ctx) {
      // retrieve config from froxy
      SubConfig fProxyConfig = core.getNode().getConfig().get("fproxy");

      Option<?> fProxyPort = fProxyConfig.getOption("port");
      Option<?> fProxyBindTo = fProxyConfig.getOption("bindTo");

      // get uri host and headers
      MultiValueTable<String, String> headers = ctx.getHeaders();
      // Forwarded header parsing is handled by UriFilterProxyHeaderParser when present.
      String uriScheme = ctx.getUri().getScheme();
      String uriHost = ctx.getUri().getHost();

      return UriFilterProxyHeaderParser.parse(fProxyPort, fProxyBindTo, uriScheme, uriHost, headers)
          .toString();
    }

    private boolean isBrowser(String ua) {
      if (ua == null) return false;
      return (ua.contains("Mozilla/") || ua.contains("Opera/"));
    }

    private String writeSizeAndMIME(HTMLNode fileInformationList, FetchException e) {
      boolean finalized = e.finalizedSize();
      long size = e.getExpectedSize();
      String mime = e.getExpectedMimeType();
      writeSizeAndMIME(fileInformationList, size, mime, finalized);
      return mime;
    }

    private void writeSizeAndMIME(
        HTMLNode fileInformationList, long size, String mime, boolean finalized) {
      if (size > 0) {
        if (finalized) {
          fileInformationList.addChild("li", (l10n("sizeLabel") + ' ') + SizeUtil.formatSize(size));
        } else {
          fileInformationList.addChild(
              "li", (l10n("sizeLabel") + ' ') + SizeUtil.formatSize(size) + l10n("mayChange"));
        }
      } else {
        fileInformationList.addChild("li", l10n("sizeUnknown"));
      }
      if (mime != null) {
        fileInformationList.addChild(
            "li",
            NodeL10n.getBase()
                .getString(
                    L10N_PREFIX + (finalized ? "mimeType" : "expectedMimeType"),
                    new String[] {"mime"},
                    new String[] {mime}));
      } else {
        fileInformationList.addChild("li", l10n("unknownMIMEType"));
      }
    }

    private String l10n(String key) {
      return FProxyToadlet.l10n(key);
    }

    private String l10nErrorWithReason(String errorMessage) {
      return NodeL10n.getBase()
          .getString(
              L10N_PREFIX + "errorWithReason", new String[] {"error"}, new String[] {errorMessage});
    }

    private String getLink(
        FreenetURI uri,
        String requestedMimeType,
        long maxSize,
        String force,
        boolean forceDownload,
        int maxRetries,
        boolean appendMaxSize) {
      StringBuilder sb = new StringBuilder();
      sb.append("/");
      sb.append(uri.toASCIIString());
      char c = '?';
      if (requestedMimeType != null && !requestedMimeType.isEmpty()) {
        sb.append(c).append("type=").append(URLEncoder.encode(requestedMimeType, false));
        c = '&';
      }
      if (maxSize > 0 && appendMaxSize) {
        sb.append(c).append("max-size=").append(maxSize);
        c = '&';
      }
      if (force != null) {
        sb.append(c).append("force=").append(force);
        c = '&';
      }
      if (forceDownload) {
        sb.append(c).append("forcedownload=true");
        c = '&';
      }
      if (maxRetries >= -1) {
        sb.append(c).append("max-retries=").append(maxRetries);
      }
      return sb.toString();
    }

    private String sanitizeReferer(ToadletContext ctx) {
      // Similar logic exists in GenericFilterCallback; keep aligned if it changes.
      String sanitizedReferer = ctx.getHeaders().getFirst("referer");
      if (sanitizedReferer != null) {
        try {
          URI refererURI = new URI(URIPreEncoder.encode(sanitizedReferer));
          String path = refererURI.getPath();
          while (path.startsWith("/")) path = path.substring(1);
          if (path.isEmpty()) return "/";
          FreenetURI furi = new FreenetURI(path);
          HTTPRequest req = new HTTPRequestImpl(refererURI, "GET");
          String type = req.getParam("type");
          sanitizedReferer = "/" + furi;
          if (type != null && !type.isEmpty()) sanitizedReferer += "?type=" + type;
        } catch (MalformedURLException e) {
          sanitizedReferer = "/";
          LOG.info("Caught MalformedURLException on the referer : {}", e.getMessage());
        } catch (Exception t) {
          LOG.error("Caught handling referrer: {} for {}", t.getMessage(), sanitizedReferer, t);
          sanitizedReferer = null;
        }
      }
      return sanitizedReferer;
    }
  }

  /**
   * Returns a localized string using the FProxy prefix with pattern substitution.
   *
   * @param key localization key suffix combined with the {@code FProxyToadlet.} prefix.
   * @param pattern placeholder names expected by the localization bundle.
   * @param value replacement values matched positionally to {@code pattern}.
   * @return localized text after substitutions, preserving bundle formatting rules.
   */
  public static String l10n(String key, String[] pattern, String[] value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, pattern, value);
  }

  private static String getForceValue(FreenetURI key, long time) {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();

    try {
      bos.write(random);
      bos.write(key.toString().getBytes(StandardCharsets.UTF_8));
      bos.write(Long.toString(time / FORCE_GRAIN_INTERVAL).getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }

    return HexUtil.bytesToHex(SHA256.digest(bos.toByteArray()));
  }

  /**
   * Get expected filename for a file.
   *
   * @param uri The original URI.
   * @param expectedMimeType The expected MIME type.
   */
  private static String getFilename(FreenetURI uri, String expectedMimeType) {
    return DefaultMIMETypes.forceExtension(uri.getPreferredFilename(), expectedMimeType);
  }

  private static long[] parseRange(String hdrrange) throws HTTPRangeException {

    long[] result = new long[2];
    try {
      String[] units = hdrrange.split("=", 2);
      // If additional units (e.g. MBytes) should be supported, adjust parsing and normalize to
      // bytes
      // here.
      if (!"bytes".equals(units[0])) {
        throw new HTTPRangeException("Unknown unit, only 'bytes' supportet yet");
      }
      String[] range = units[1].split("-", 2);
      result[0] = Long.parseLong(range[0]);
      if (result[0] < 0) throw new HTTPRangeException("Negative 'from' value");
      if (!range[1].trim().isEmpty()) {
        result[1] = Long.parseLong(range[1]);
        if (result[1] <= result[0])
          throw new HTTPRangeException("'from' value must be less then 'to' value");
      } else {
        result[1] = -1;
      }
    } catch (NumberFormatException | IndexOutOfBoundsException e) {
      throw new HTTPRangeException(e);
    }
    return result;
  }

  @Override
  public boolean persistent() {
    return false;
  }

  @Override
  public String path() {
    return "/";
  }

  @Override
  public boolean realTimeFlag() {
    return true;
  }
}
