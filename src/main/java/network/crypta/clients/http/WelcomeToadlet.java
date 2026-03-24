package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import network.crypta.client.ClientMetadata;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.bookmark.BookmarkCategory;
import network.crypta.clients.http.bookmark.BookmarkItem;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.fs.AppEnv;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Version;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.WelcomePageSnapshot;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.URLDecoder;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.LineReadingInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Serves the FProxy welcome page and orchestrates user-facing maintenance actions such as restart,
 * shutdown, thread dumps, bookmark additions, and small upload flows. The toadlet renders the
 * landing page with alerts, bookmarks, search integration, and version/environment diagnostics so
 * users can assess node health at a glance.
 *
 * <p>The class is intentionally state-light: it uses a small runtime-port bundle for both detached
 * welcome-page reads and the remaining maintenance POST/action helpers. Requests are processed
 * sequentially by the container, so the toadlet itself does not create additional threads; any
 * asynchronous behavior is queued through the runtime layer. Form-password checks gate all actions
 * that mutate state or reveal privileged information, while public users see a trimmed bookmark
 * view.
 *
 * <ul>
 *   <li>Homepage rendering combines alerts, bookmark trees, fetch boxes, and version details.
 *   <li>Maintenance endpoints allow upgrades, restarts, thread dumps, and bandwidth tuning.
 *   <li>Log preview helpers surface wrapper logs for graceful shutdown/restart confirmation.
 * </ul>
 *
 * @see network.crypta.clients.http.Toadlet
 * @see network.crypta.clients.http.PageMaker
 */
public class WelcomeToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(WelcomeToadlet.class);

  /** Suffix {@link #path()} with "#" + BOOKMARKS_ANCHOR to deep link to the bookmark list */
  public static final String BOOKMARKS_ANCHOR = "bookmarks";

  private static final String ATTR_CLASS = "class";
  private static final String ATTR_STYLE = "style";
  private static final String ATTR_TARGET = "target";
  private static final String ATTR_TITLE = "title";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_VALUE = "value";
  private static final String HEADER_LOCATION = "Location";
  private static final String STATUS_FOUND = "Found";
  private static final String ELEMENT_INPUT = "input";
  private static final String INFOBOX_INFORMATION = "infobox-information";
  private static final String INFOBOX_QUERY = "infobox-query";
  private static final String INPUT_HIDDEN = "hidden";
  private static final String INPUT_SUBMIT = "submit";
  private static final String INPUT_TEXT = "text";
  private static final String INPUT_VALUE_CANCEL = "cancel";
  private static final String L10N_CANCEL_KEY = "Toadlet.cancel";
  private static final String PARAM_FORM_PASSWORD = "formPassword";
  private static final String PARAM_NEW_BOOKMARK = "newbookmark";
  private static final String PARAM_HAS_ACTIVE_LINK = "hasAnActivelink";
  private static final String PARAM_INPUT_BANDWIDTH_LIMIT = "inputBandwidthLimit";
  private static final String PARAM_OUTPUT_BANDWIDTH_LIMIT = "outputBandwidthLimit";
  private static final String PARAM_FILENAME = "filename";
  private static final String PARAM_RESTART = "restart";
  private static final String TAG_LABEL = "label";
  private static final String TEXTAREA_DESC_B = "descB";
  private static final String STYLE_BORDER_NONE = "border: none";
  private static final String TARGET_BLANK = "_blank";

  private final WelcomeToadletRuntimePorts runtimePorts;

  // Legacy Logger threshold callbacks removed; use LOG.isDebugEnabled() directly.

  WelcomeToadlet(HighLevelSimpleClient client, WelcomeToadletRuntimePorts runtimePorts) {
    super(client);
    this.runtimePorts = Objects.requireNonNull(runtimePorts, "runtimePorts");
  }

  void redirectToRoot(ToadletContext ctx) throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_LOCATION, ROOT_PATH);
    ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
  }

  private void addCategoryToList(
      BookmarkCategory cat, HTMLNode list, boolean noActiveLinks, ToadletContext ctx) {
    boolean disableActiveLinks = !ctx.getPageMaker().getTheme().forceActivelinks && noActiveLinks;

    addCategoryItems(cat, list, disableActiveLinks, ctx);
    addSubCategories(cat, list, disableActiveLinks, ctx);
  }

  private void addCategoryItems(
      BookmarkCategory cat, HTMLNode list, boolean noActiveLinks, ToadletContext ctx) {
    List<BookmarkItem> items = cat.getItems();
    if (items.isEmpty()) {
      return;
    }

    HTMLNode table =
        list.addChild("li")
            .addChild(
                "table",
                new String[] {"border", ATTR_STYLE},
                new String[] {"0", STYLE_BORDER_NONE});
    for (BookmarkItem item : items) {
      addBookmarkItemRow(noActiveLinks, table, item, ctx);
    }
  }

  private void addBookmarkItemRow(
      boolean noActiveLinks, HTMLNode table, BookmarkItem item, ToadletContext ctx) {
    HTMLNode row = table.addChild("tr");
    HTMLNode cell = row.addChild("td", ATTR_STYLE, STYLE_BORDER_NONE + ';');
    if (item.hasAnActivelink() && !noActiveLinks) {
      appendActiveLink(item, cell);
    } else {
      cell.addChild("#", " ");
    }
    cell = row.addChild("td", ATTR_STYLE, STYLE_BORDER_NONE);

    boolean updated = item.hasUpdated();
    String linkClass = updated ? "bookmark-title-updated" : "bookmark-title";
    cell.addChild(
        "a",
        new String[] {"href", ATTR_TITLE, ATTR_CLASS, ATTR_TARGET},
        new String[] {'/' + item.getKey(), item.getDescription(), linkClass, TARGET_BLANK},
        item.getVisibleName());

    appendBookmarkDescription(item, cell);

    if (updated) {
      HTMLNode alertCell = row.addChild("td", ATTR_STYLE, STYLE_BORDER_NONE);
      alertCell.addChild(
          ctx.getAlertManager()
              .renderDismissButton(item.getUserAlert(), path() + "#" + BOOKMARKS_ANCHOR));
    }
  }

  private void appendBookmarkDescription(BookmarkItem item, HTMLNode cell) {
    String explain = item.getShortDescription();
    if (explain != null && !explain.isEmpty()) {
      cell.addChild("#", " (");
      cell.addChild("#", explain);
      cell.addChild("#", ")");
    }
  }

  private void appendActiveLink(BookmarkItem item, HTMLNode cell) {
    String initialKey = item.getKey();
    String key = '/' + initialKey + (initialKey.endsWith("/") ? "" : "/") + "activelink.png";
    cell.addChild("div", ATTR_STYLE, "height: 36px; width: 108px;")
        .addChild(
            "a",
            new String[] {"href", ATTR_TARGET},
            new String[] {'/' + item.getKey(), TARGET_BLANK})
        .addChild(
            "img",
            new String[] {"src", "alt", ATTR_STYLE, ATTR_TITLE},
            new String[] {key, "activelink", "height: 36px; width: 108px", item.getDescription()});
  }

  private void addSubCategories(
      BookmarkCategory cat, HTMLNode list, boolean noActiveLinks, ToadletContext ctx) {
    List<BookmarkCategory> cats = cat.getSubCategories();
    for (BookmarkCategory bookmarkCategory : cats) {
      list.addChild("li", ATTR_CLASS, "cat", bookmarkCategory.getVisibleName());
      addCategoryToList(bookmarkCategory, list.addChild("li").addChild("ul"), noActiveLinks, ctx);
    }
  }

  /**
   * Allows the container to route POST requests to this toadlet even when the global form password
   * is not provided up front, enabling confirmation pages that collect the password themselves.
   *
   * <p>Handlers invoked from {@link #handleMethodPOST(URI, HTTPRequest, ToadletContext)} still call
   * {@link ToadletContext#checkFormPassword(network.crypta.support.api.HTTPRequest)} before they
   * perform any privileged operation such as restart, shutdown, or upgrades. This method is purely
   * declarative and introduces no side effects or security bypasses; it simply tells the container
   * to forward POST traffic so that later forms can validate credentials.
   *
   * @return {@code true} to permit POST routing without a pre-validated password while preserving
   *     per-action verification
   */
  @Override
  public boolean allowPOSTWithoutPassword() {
    // We need to show some confirmation pages.
    return true;
  }

  /**
   * Determines whether the full search box should be rendered on the welcome page.
   *
   * <p>The in-page search integration is currently unavailable. Callers use this to decide between
   * showing the search form and the fallback warning.
   *
   * @return always {@code false}.
   */
  public boolean showSearchBox() {
    return false;
  }

  /**
   * Indicates whether search integration is currently in a loading state.
   *
   * <p>Search integration is currently disabled, so this method always reports not-loading.
   *
   * @return always {@code false}.
   */
  public boolean showSearchBoxLoading() {
    return false;
  }

  /**
   * Renders the search UI panel into the supplied content node, selecting the appropriate message
   * or form based on search availability.
   *
   * <p>When {@link #showSearchBox()} is true, this method builds a text field and submit button
   * that post to {@code /library/} in a new tab so bookmark browsing remains uninterrupted.
   * Otherwise, it emits a localized “not available” warning. The method mutates only the provided
   * {@link HTMLNode} tree and performs no network or disk I/O, making it safe to call during page
   * rendering on the request thread.
   *
   * @param contentNode the container node within the welcome page that receives the search box
   *     markup; must be non-null and already attached to the page
   */
  public void addSearchBox(HTMLNode contentNode) {
    // Keep structure for potential future search integration restoration.
    HTMLNode searchBox = contentNode.addChild("div", ATTR_CLASS, "infobox infobox-normal");
    searchBox.addAttribute("id", "search-freenet");
    searchBox
        .addChild("div", ATTR_CLASS, "infobox-header")
        .addChild(
            "span",
            ATTR_CLASS,
            "search-title-label",
            NodeL10n.getBase().getString("WelcomeToadlet.searchBoxLabel"));
    HTMLNode searchBoxContent = searchBox.addChild("div", ATTR_CLASS, "infobox-content");
    // Search form
    if (showSearchBox()) {
      searchBoxContent.addChild(
          "span", ATTR_CLASS, "search-warning-text", l10n("searchBoxWarningSlow"));
      HTMLNode searchForm = container.addFormChild(searchBoxContent, "/library/", "searchform");
      searchForm.addChild(
          ELEMENT_INPUT,
          new String[] {ATTR_TYPE, "size", "name"},
          new String[] {INPUT_TEXT, "80", "search"});
      searchForm.addChild(
          ELEMENT_INPUT,
          new String[] {ATTR_TYPE, "name", ATTR_VALUE},
          new String[] {INPUT_SUBMIT, "find", l10n("searchCrypta")});
      // Search must be in a new window so that the user is able to browse the bookmarks.
      searchForm.addAttribute(ATTR_TARGET, TARGET_BLANK);
    } else if (showSearchBoxLoading()) {
      searchBoxContent.addChild(
          "span", ATTR_CLASS, "search-not-availible-warning", l10n("searchUnavailableLoading"));
    } else {
      searchBoxContent.addChild(
          "span", ATTR_CLASS, "search-not-availible-warning", l10n("searchUnavailable"));
    }
  }

  /**
   * Processes privileged POST actions on the welcome page, including updates, restarts, thread
   * dumps, alert dismissal, bookmark inserts from files, key redirects, graceful exits, and
   * bandwidth upgrades.
   *
   * <p>The method runs a short-circuit chain of handlers in priority order; the first handler that
   * recognizes the request writes a response and stops further processing. Full-access permission
   * is required up front, and each handler invokes {@link ToadletContext#checkFormPassword} before
   * mutating state or revealing sensitive data. Logging is limited to a DEBUG trace of the request
   * URI to avoid leaking parameters.
   *
   * @param uri the request URI being processed; may be {@code null} for synthetic invocations
   * @param request the parsed HTTP request containing parameters, parts, and form password
   * @param ctx context holding authentication state, localization, and reply helpers
   * @throws ToadletContextClosedException if the client connection closes before the response is
   *     fully written
   * @throws IOException if writing the response or reading request parts fails
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) return;
    if (LOG.isDebugEnabled() && uri != null) {
      LOG.debug("POST {}", uri);
    }

    if (handleUpdateConfirmation(request, ctx)) return;
    if (handleUpdateRequest(request, ctx)) return;
    if (handleThreadDump(request, ctx)) return;
    if (handleDisableAlert(request, ctx)) return;
    if (handleInsertWithFile(request, ctx)) return;
    if (handleKeyRedirect(request, ctx)) return;
    if (handleExitRequest(request, ctx)) return;
    if (handleShutdownConfirm(request, ctx)) return;
    if (handleRestartRequest(request, ctx)) return;
    if (handleRestartConfirm(request, ctx)) return;
    if (handleDismissEvents(request, ctx)) return;
    if (handleUpgradeConnectionSpeed(request, ctx)) return;

    redirectToRoot(ctx);
  }

  private boolean handleUpdateConfirmation(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (request.getPartAsStringFailsafe("updateconfirm", 32).isEmpty()) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    PageNode page = ctx.getPageMaker().getPageNode(l10n("updatingTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(INFOBOX_INFORMATION, l10n("updatingTitle"), contentNode, null, true);
    content.addChild("p").addChild("#", l10n("updating"));
    content.addChild("p").addChild("#", l10n("thanks"));
    writeHTMLReply(ctx, 200, "OK", page.generate());
    LOG.info("Node is updating/restarting");
    runtimePorts.welcomeActionPort().armNodeUpdate();
    return true;
  }

  private boolean handleUpdateRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (request.getPartAsStringFailsafe("update", 32).isEmpty()) {
      return false;
    }

    PageNode page = ctx.getPageMaker().getPageNode(l10n("nodeUpdateConfirmTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_QUERY,
                l10n("nodeUpdateConfirmTitle"),
                contentNode,
                "update-node-confirm",
                true);
    content.addChild("p").addChild("#", l10n("nodeUpdateConfirm"));
    HTMLNode updateForm = ctx.addFormChild(content, ROOT_PATH, "updateConfirmForm");
    updateForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT, INPUT_VALUE_CANCEL, NodeL10n.getBase().getString(L10N_CANCEL_KEY)
        });
    updateForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_SUBMIT, "updateconfirm", l10n("update")});
    writeHTMLReply(ctx, 200, "OK", page.generate());
    return true;
  }

  private boolean handleThreadDump(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("getThreadDump")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    PageNode page = ctx.getPageMaker().getPageNode(l10n("threadDumpTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    if (runtimePorts.lifecyclePort().isUsingWrapper()) {
      ctx.getPageMaker()
          .getInfobox("#", l10n("threadDumpSubTitle"), contentNode, "thread-dump-generation", true)
          .addChild(
              "#",
              l10n(
                  "threadDumpWithFilename",
                  PARAM_FILENAME,
                  WrapperManager.getProperties().getProperty("wrapper.logfile")));
      LOG.info("Thread Dump requested");
      WrapperManager.requestThreadDump();
    } else {
      ctx.getPageMaker()
          .getInfobox(
              "infobox-error",
              l10n("threadDumpSubTitle"),
              contentNode,
              "thread-dump-generation",
              true)
          .addChild("#", l10n("threadDumpNotUsingWrapper"));
    }
    this.writeHTMLReply(ctx, 200, "OK", page.generate());
    return true;
  }

  private boolean handleDisableAlert(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("disable")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    int validAlertsRemaining = 0;
    UserAlert[] alerts = ctx.getAlertManager().getAlerts();
    for (UserAlert alert : alerts) {
      if (request.getIntPart("disable", -1) == alert.hashCode()) {
        disableMatchingAlert(ctx, alert);
      } else if (alert.isValid()) {
        validAlertsRemaining++;
      }
    }
    writePermanentRedirect(
        ctx, l10n("disabledAlert"), (validAlertsRemaining > 0 ? "/alerts/" : "/"));
    return true;
  }

  private void disableMatchingAlert(ToadletContext ctx, UserAlert alert) {
    if (alert.userCanDismiss() && alert.shouldUnregisterOnDismiss()) {
      alert.onDismiss();
      LOG.info("Unregistering the userAlert {}", alert.hashCode());
      ctx.getAlertManager().unregister(alert);
    } else {
      LOG.info("Disabling the userAlert {}", alert.hashCode());
      alert.isValid(false);
    }
  }

  private boolean handleInsertWithFile(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!(request.isPartSet("key") && request.isPartSet(PARAM_FILENAME))) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }

    FreenetURI key = new FreenetURI(request.getPartAsStringFailsafe("key", Short.MAX_VALUE));
    String type = request.getPartAsStringFailsafe("content-type", 128);
    if (type == null) {
      type = "text/plain";
    }
    ClientMetadata contentType = new ClientMetadata(type);

    RandomAccessBucket bucket = request.getPart(PARAM_FILENAME);

    PageNode page = ctx.getPageMaker().getPageNode(l10n("insertedTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content;
    String filenameHint = extractFilenameHint(key);
    InsertBlock block = new InsertBlock(bucket, contentType, key);
    try {
      key = this.insert(block, filenameHint);
      content =
          ctx.getPageMaker()
              .getInfobox(
                  "infobox-success",
                  l10n("insertSucceededTitle"),
                  contentNode,
                  "successful-insert",
                  false);
      String u = key.toString();
      NodeL10n.getBase()
          .addL10nSubstitution(
              content,
              "WelcomeToadlet.keyInsertedSuccessfullyWithKeyAndName",
              new String[] {"link", "name"},
              new HTMLNode[] {HTMLNode.link("/" + u), HTMLNode.text(u)});
    } catch (InsertException e) {
      content =
          ctx.getPageMaker()
              .getInfobox(
                  "infobox-error", l10n("insertFailedTitle"), contentNode, "failed-insert", false);
      content.addChild("#", l10n("insertFailedWithMessage", "message", e.getMessage()));
      content.addChild("br");
      if (e.getUri() != null) {
        content.addChild("#", l10n("uriWouldHaveBeen", "uri", e.getUri().toString()));
      }
      appendInsertErrorDetails(content, e);
    }

    content.addChild("br");
    addHomepageLink(content);

    writeHTMLReply(ctx, 200, "OK", page.generate());
    request.freeParts();
    bucket.free();
    return true;
  }

  private static String extractFilenameHint(FreenetURI key) {
    if (!key.getKeyType().equals("CHK")) {
      return null;
    }

    String[] metas = key.getAllMetaStrings();
    if ((metas != null) && (metas.length > 1)) {
      return metas[0];
    }
    return null;
  }

  private void appendInsertErrorDetails(HTMLNode content, InsertException e) {
    InsertExceptionMode mode = e.getMode();
    if ((mode == InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS)
        || (mode == InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS)) {
      content.addChild("br");
      content.addChild("#", l10n("splitfileErrorLabel"));
      content.addChild("pre", e.getErrorCodes().toVerboseString());
    }
  }

  private boolean handleKeyRedirect(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("key")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    try {
      String key =
          URLDecoder.decode(
              new FreenetURI(request.getPartAsStringFailsafe("key", Short.MAX_VALUE))
                  .toURI("/")
                  .toString(),
              false);
      writeTemporaryRedirect(ctx, "OK", key);
    } catch (Exception e) {
      sendErrorPage(ctx, l10n("invalidURI"), l10n("invalidURILong"), e);
    }
    return true;
  }

  private boolean handleExitRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("exit")) {
      return false;
    }
    PageNode page = ctx.getPageMaker().getPageNode(l10n("shutdownConfirmTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_QUERY, l10n("shutdownConfirmTitle"), contentNode, "shutdown-confirm", true);
    content.addChild("p").addChild("#", l10n("shutdownConfirm"));
    HTMLNode shutdownForm =
        ctx.addFormChild(content.addChild("p"), ROOT_PATH, "confirmShutdownForm");
    shutdownForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT, INPUT_VALUE_CANCEL, NodeL10n.getBase().getString(L10N_CANCEL_KEY)
        });
    shutdownForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_SUBMIT, "shutdownconfirm", l10n("shutdown")});
    writeHTMLReply(ctx, 200, "OK", page.generate());
    return true;
  }

  private boolean handleShutdownConfirm(HTTPRequest request, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    if (!request.isPartSet("shutdownconfirm")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    MultiValueTable<String, String> headers =
        MultiValueTable.from(
            HEADER_LOCATION, "/?terminated&" + PARAM_FORM_PASSWORD + '=' + ctx.getFormPassword());
    ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
    runtimePorts.welcomeActionPort().queueShutdownFromWelcome();
    return true;
  }

  private boolean handleRestartRequest(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet(PARAM_RESTART)) {
      return false;
    }
    PageNode page = ctx.getPageMaker().getPageNode(l10n("restartConfirmTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_QUERY, l10n("restartConfirmTitle"), contentNode, "restart-confirm", true);
    content.addChild("p").addChild("#", l10n("restartConfirm"));
    HTMLNode restartForm = ctx.addFormChild(content.addChild("p"), ROOT_PATH, "confirmRestartForm");
    restartForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT, INPUT_VALUE_CANCEL, NodeL10n.getBase().getString(L10N_CANCEL_KEY)
        });
    restartForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_SUBMIT, "restartconfirm", l10n(PARAM_RESTART)});
    writeHTMLReply(ctx, 200, "OK", page.generate());
    return true;
  }

  private boolean handleRestartConfirm(HTTPRequest request, ToadletContext ctx)
      throws IOException, ToadletContextClosedException {
    if (!request.isPartSet("restartconfirm")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    MultiValueTable<String, String> headers =
        MultiValueTable.from(
            HEADER_LOCATION, "/?restarted&" + PARAM_FORM_PASSWORD + '=' + ctx.getFormPassword());
    ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
    runtimePorts.welcomeActionPort().queueRestartFromWelcome();
    return true;
  }

  private boolean handleDismissEvents(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("dismiss-events")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    String alertsToDump = request.getPartAsStringFailsafe("events", Integer.MAX_VALUE);
    String[] alertAnchors = alertsToDump.split(",");
    HashSet<String> toDump = new HashSet<>();
    Collections.addAll(toDump, alertAnchors);
    ctx.getAlertManager().dumpEvents(toDump);
    redirectToRoot(ctx);
    return true;
  }

  private boolean handleUpgradeConnectionSpeed(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!request.isPartSet("upgradeConnectionSpeed")) {
      return false;
    }
    if (!ctx.checkFormPassword(request)) {
      return true;
    }
    runtimePorts
        .welcomeActionPort()
        .applyUpgradeConnectionSpeed(
            request.getPartAsStringFailsafe(PARAM_INPUT_BANDWIDTH_LIMIT, Byte.MAX_VALUE),
            request.getPartAsStringFailsafe(PARAM_OUTPUT_BANDWIDTH_LIMIT, Byte.MAX_VALUE));

    redirectToRoot(ctx);
    return true;
  }

  /**
   * Serves GET requests for the welcome page, assembling user-facing sections and optionally
   * handling authenticated maintenance queries before rendering the standard layout.
   *
   * <p>If full access is granted, the method first checks for specialized parameters (log tail,
   * shutdown/restart confirmations, bookmark additions, or HTTP link checks) and handles them
   * directly. Otherwise, it builds the homepage by composing warnings, alerts, bookmark trees,
   * optional search box, fetch-key controls, and version/environment details, then sends a 200 OK
   * HTML reply. The routine is synchronous and performs only minimal file I/O when a log tail is
   * requested.
   *
   * @param uri the requested URI, used primarily for link-check redirects
   * @param request the HTTP request providing parameters and headers used during rendering
   * @param ctx the toadlet context supplying access control, localization, and HTML builders
   * @throws ToadletContextClosedException if the client disconnects before the response is sent
   * @throws IOException if writing the response fails
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (ctx.isAllowedFullAccess() && handleFullAccessGetRequests(uri, request, ctx)) {
      return;
    }

    PageNode page = ctx.getPageMaker().getPageNode(l10n("homepageFullTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    WelcomePageSnapshot welcomePageSnapshot = runtimePorts.welcomePagePort().snapshot();

    String userAgent = ctx.getHeaders().getFirst("user-agent");

    addUserAgentWarnings(ctx, contentNode, userAgent);
    addAlerts(ctx, contentNode);
    addFetchKeyBoxAboveBookmarks(ctx, contentNode, welcomePageSnapshot);
    addBookmarksSection(ctx, contentNode, userAgent);
    if (showSearchBox()) {
      addSearchBox(contentNode);
    }
    addFetchKeyBoxBelowBookmarks(ctx, contentNode, welcomePageSnapshot);
    addVersionInfoSection(ctx, contentNode);

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean handleFullAccessGetRequests(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (request.isParameterSet("latestlog")) {
      serveLatestLog(ctx);
      return true;
    }
    if (request.isParameterSet("terminated")) {
      if (isValidFormPassword(request, ctx)) {
        sendShutdownPage(ctx);
      } else {
        redirectToRoot(ctx);
      }
      return true;
    }
    if (request.isParameterSet("restarted")) {
      if (isValidFormPassword(request, ctx)) {
        sendRestartingPage(ctx);
      } else {
        redirectToRoot(ctx);
      }
      return true;
    }
    if (!request.getParam(PARAM_NEW_BOOKMARK).isEmpty()) {
      sendAddBookmarkConfirmation(request, ctx);
      return true;
    }
    if (uri.getQuery() != null && uri.getQuery().startsWith("_CHECKED_HTTP_=")) {
      super.writeTemporaryRedirect(
          ctx, "Depreciated", ExternalLinkToadlet.EXTERNAL_LINK_PATH + '?' + uri.getQuery());
      return true;
    }
    return false;
  }

  private void serveLatestLog(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    this.writeTextReply(ctx, 200, "OK", runtimePorts.welcomePagePort().latestNodeLogTail());
  }

  private boolean isValidFormPassword(HTTPRequest request, ToadletContext ctx) {
    return request.isParameterSet(PARAM_FORM_PASSWORD)
        && request.getParam(PARAM_FORM_PASSWORD).equals(ctx.getFormPassword());
  }

  private void sendShutdownPage(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page =
        ctx.getPageMaker()
            .getPageNode("Node Shutdown", ctx, new RenderParameters().renderNavigationLinks(false));
    HTMLNode contentNode = page.getContentNode();
    ctx.getPageMaker()
        .getInfobox(
            INFOBOX_INFORMATION, l10n("shutdownDone"), contentNode, "shutdown-progressing", true)
        .addChild("#", l10n("thanks"));

    WelcomeToadlet.maybeDisplayWrapperLogfile(ctx, contentNode);

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void sendAddBookmarkConfirmation(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmAddBookmarkTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode infoboxContent =
        ctx.getPageMaker()
            .getInfobox(
                "#", l10n("confirmAddBookmarkSubTitle"), contentNode, "add-bookmark-confirm", true);
    HTMLNode addForm = ctx.addFormChild(infoboxContent, "/bookmarkEditor/", "editBookmarkForm");
    addForm.addChild(
        "#", l10n("confirmAddBookmarkWithKey", "key", request.getParam(PARAM_NEW_BOOKMARK)));
    addForm.addChild("br");
    String key = request.getParam(PARAM_NEW_BOOKMARK);
    addForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, "key", key});
    if (request.isParameterSet(PARAM_HAS_ACTIVE_LINK)) {
      addForm.addChild(
          ELEMENT_INPUT,
          new String[] {ATTR_TYPE, "name", ATTR_VALUE},
          new String[] {
            INPUT_HIDDEN, PARAM_HAS_ACTIVE_LINK, request.getParam(PARAM_HAS_ACTIVE_LINK)
          });
    }
    addForm.addChild(
        TAG_LABEL,
        "for",
        "name",
        NodeL10n.getBase().getString("BookmarkEditorToadlet.nameLabel") + ' ');
    addForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_TEXT, "name", request.getParam("desc")});
    addForm.addChild("br");
    addForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, "bookmark", ROOT_PATH});
    addForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, "action", "addItem"});
    addForm.addChild(
        TAG_LABEL,
        "for",
        TEXTAREA_DESC_B,
        NodeL10n.getBase().getString("BookmarkEditorToadlet.descLabel") + ' ');
    addForm.addChild("br");
    addForm.addChild(
        "textarea",
        new String[] {"id", "name", "row", "cols"},
        new String[] {TEXTAREA_DESC_B, TEXTAREA_DESC_B, "3", "70"});
    appendDarknetPeersSection(ctx, addForm);
    addForm.addChild("br");

    addForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          "addbookmark",
          NodeL10n.getBase().getString("BookmarkEditorToadlet.addBookmark")
        });

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void appendDarknetPeersSection(ToadletContext ctx, HTMLNode addForm) {
    List<DarknetConnectionPeerSnapshot> peers = runtimePorts.darknetConnectionsPort().listPeers();
    if (peers.isEmpty()) {
      return;
    }
    addForm.addChild("br");
    addForm.addChild("br");
    boolean fProxyJavascriptEnabled = ctx.getContainer().isFProxyJavascriptEnabled();
    if (fProxyJavascriptEnabled) {
      addForm.addChild(
          "script",
          new String[] {ATTR_TYPE, "src"},
          new String[] {"text/javascript", "/static/js/checkall.js"});
    }

    HTMLNode peerTable = addForm.addChild("table", ATTR_CLASS, "darknet_connections");
    if (fProxyJavascriptEnabled) {
      HTMLNode headerRow = peerTable.addChild("tr");
      headerRow
          .addChild("th")
          .addChild(
              ELEMENT_INPUT,
              new String[] {ATTR_TYPE, "onclick"},
              new String[] {"checkbox", "checkAll(this, 'darknet_connections')"});
      headerRow.addChild("th", NodeL10n.getBase().getString("QueueToadlet.recommendToFriends"));
    } else {
      peerTable
          .addChild("tr")
          .addChild(
              "th",
              "colspan",
              "2",
              NodeL10n.getBase().getString("QueueToadlet.recommendToFriends"));
    }
    for (DarknetConnectionPeerSnapshot peer : peers) {
      HTMLNode peerRow = peerTable.addChild("tr", ATTR_CLASS, "darknet_connections_normal");
      peerRow
          .addChild("td", ATTR_CLASS, "peer-marker")
          .addChild(
              ELEMENT_INPUT,
              new String[] {ATTR_TYPE, "name"},
              new String[] {"checkbox", "node_" + peer.selectionToken()});
      peerRow.addChild("td", ATTR_CLASS, "peer-name").addChild("#", peer.displayName());
    }

    addForm.addChild(
        TAG_LABEL,
        "for",
        TEXTAREA_DESC_B,
        (NodeL10n.getBase().getString("BookmarkEditorToadlet.publicDescLabel") + ' '));
    addForm.addChild("br");
    addForm.addChild(
        "textarea",
        new String[] {"id", "name", "row", "cols"},
        new String[] {TEXTAREA_DESC_B, "publicDescB", "3", "70"},
        "");
  }

  private void addUserAgentWarnings(ToadletContext ctx, HTMLNode contentNode, String userAgent) {
    if (userAgent == null) {
      return;
    }
    String lowered = userAgent.toLowerCase(Locale.ROOT);
    if (lowered.contains("msie") && !lowered.contains("opera")) {
      ctx.getPageMaker()
          .getInfobox(
              "infobox-alert", l10n("ieWarningTitle"), contentNode, "internet-explorer-used", true)
          .addChild("#", l10n("ieWarning"));
    }
  }

  private void addAlerts(ToadletContext ctx, HTMLNode contentNode) {
    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }
  }

  private void addFetchKeyBoxAboveBookmarks(
      ToadletContext ctx, HTMLNode contentNode, WelcomePageSnapshot welcomePageSnapshot) {
    if (welcomePageSnapshot.fetchKeyBoxAboveBookmarks()) {
      this.putFetchKeyBox(ctx, contentNode);
    }
  }

  private void addFetchKeyBoxBelowBookmarks(
      ToadletContext ctx, HTMLNode contentNode, WelcomePageSnapshot welcomePageSnapshot) {
    if (!welcomePageSnapshot.fetchKeyBoxAboveBookmarks()) {
      this.putFetchKeyBox(ctx, contentNode);
    }
  }

  private void addBookmarksSection(ToadletContext ctx, HTMLNode contentNode, String userAgent) {
    HTMLNode bookmarkBox =
        contentNode.addChild("div", ATTR_CLASS, "infobox infobox-normal bookmarks-box");
    HTMLNode bookmarkBoxHeader = bookmarkBox.addChild("div", ATTR_CLASS, "infobox-header");
    bookmarkBoxHeader.addChild(
        "a",
        new String[] {ATTR_CLASS, ATTR_TITLE},
        new String[] {
          "bookmarks-header-text",
          NodeL10n.getBase().getString("BookmarkEditorToadlet.myBookmarksExplanation")
        },
        NodeL10n.getBase().getString("BookmarkEditorToadlet.myBookmarksTitle"));
    if (ctx.isAllowedFullAccess()) {
      bookmarkBoxHeader.addChild("span", ATTR_CLASS, "edit-bracket", "[");
      bookmarkBoxHeader
          .addChild("span", "id", "bookmarkedit")
          .addChild(
              "a",
              new String[] {"href", ATTR_CLASS},
              new String[] {"/bookmarkEditor/", "interfacelink"},
              NodeL10n.getBase().getString("BookmarkEditorToadlet.edit"));
      bookmarkBoxHeader.addChild("span", ATTR_CLASS, "edit-bracket", "]");
    }

    HTMLNode bookmarkBoxContent = bookmarkBox.addChild("div", ATTR_CLASS, "infobox-content");

    HTMLNode bookmarksList = bookmarkBoxContent.addChild("ul", "id", BOOKMARKS_ANCHOR);
    String loweredAgent = userAgent == null ? null : userAgent.toLowerCase(Locale.ROOT);
    boolean disableActivelinks =
        !container.enableActivelinks()
            || (loweredAgent != null
                && loweredAgent.contains("khtml")
                && !loweredAgent.contains("chrome"));
    BookmarkCategory category =
        ctx.isAllowedFullAccess() || !ctx.getContainer().publicGatewayMode()
            ? BookmarkManager.MAIN_CATEGORY
            : BookmarkManager.DEFAULT_CATEGORY;
    addCategoryToList(category, bookmarksList, disableActivelinks, ctx);
  }

  private void addVersionInfoSection(ToadletContext ctx, HTMLNode contentNode) {
    HTMLNode versionContent =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_INFORMATION, l10n("versionHeader"), contentNode, "freenet-version", true);
    versionContent.addChild(
        "span",
        ATTR_CLASS,
        "freenet-full-version",
        NodeL10n.getBase()
            .getString(
                "WelcomeToadlet.version",
                new String[] {"fullVersion", "build", "rev"},
                new String[] {
                  Long.toString(Version.currentBuildNumber()),
                  Integer.toString(Version.currentBuildNumber()),
                  Version.gitRevision()
                }));
    appendEnvironmentSummary(versionContent);
    versionContent.addChild("br");
    if (ctx.isAllowedFullAccess()) {
      addShutdownAndRestartForms(ctx, versionContent);
    }
  }

  private void appendEnvironmentSummary(HTMLNode versionContent) {
    try {
      AppEnv env = new AppEnv();
      AppEnv.EnvDetection det = env.detectEnvironment();
      String os = det.getOs().toString();
      String arch = det.getArch();
      ArrayList<String> tags = new ArrayList<>();
      if (env.isFlatpak()) tags.add("flatpak");
      if (env.isSnap()) tags.add("snap");
      if (env.isDocker()) tags.add("docker");
      if (env.isServiceMode()) tags.add("service");
      String tagStr = tags.isEmpty() ? "" : " [" + String.join(",", tags) + "]";
      String envText = " • Env: " + os + "/" + arch + tagStr;
      versionContent.addChild("span", ATTR_CLASS, "freenet-env", envText);
    } catch (Exception _) {
      // avoid breaking the page if environment detection fails
    }
  }

  private void addShutdownAndRestartForms(ToadletContext ctx, HTMLNode versionContent) {
    HTMLNode shutdownForm = ctx.addFormChild(versionContent, ".", "shutdownForm");
    shutdownForm.addChild(
        ELEMENT_INPUT, new String[] {ATTR_TYPE, "name"}, new String[] {INPUT_HIDDEN, "exit"});

    shutdownForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, l10n("shutdownNode")});
    if (runtimePorts.lifecyclePort().isUsingWrapper()) {
      HTMLNode restartForm = ctx.addFormChild(versionContent, ".", "restartForm");
      restartForm.addChild(
          ELEMENT_INPUT,
          new String[] {ATTR_TYPE, "name"},
          new String[] {INPUT_HIDDEN, PARAM_RESTART});
      restartForm.addChild(
          ELEMENT_INPUT,
          new String[] {ATTR_TYPE, "name", ATTR_VALUE},
          new String[] {INPUT_SUBMIT, "restart2", l10n("restartNode")});
      // Remove outdated cron-based autostart note on Linux (we do not use cronjob anymore).
    }
  }

  private void putFetchKeyBox(ToadletContext ctx, HTMLNode contentNode) {
    // Fetch-a-key box
    HTMLNode fetchKeyContent =
        ctx.getPageMaker()
            .getInfobox("infobox-normal", l10n("fetchKeyLabel"), contentNode, "fetch-key", true);
    fetchKeyContent.addAttribute("id", "keyfetchbox");
    HTMLNode fetchKeyForm =
        fetchKeyContent
            .addChild("form", new String[] {"method"}, new String[] {"POST"})
            .addChild("div");
    fetchKeyForm.addChild("span", ATTR_CLASS, "fetch-key-label", l10n("keyRequestLabel") + ' ');
    fetchKeyForm.addChild(
        ELEMENT_INPUT, new String[] {"type", "size", "name"}, new String[] {"text", "80", "key"});
    fetchKeyForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, "name", ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_FORM_PASSWORD, ctx.getFormPassword()});
    fetchKeyForm.addChild(
        ELEMENT_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, l10n("fetch")});
  }

  private void sendRestartingPage(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writeHTMLReply(ctx, 200, "OK", sendRestartingPageInner(ctx).generate());
  }

  static HTMLNode sendRestartingPageInner(ToadletContext ctx) {
    // Tell the user that the node is restarting
    PageNode page =
        ctx.getPageMaker()
            .getPageNode("Node Restart", ctx, new RenderParameters().renderNavigationLinks(false));
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode headNode = page.getHeadNode();
    headNode.addChild(
        "meta", new String[] {"http-equiv", "content"}, new String[] {"refresh", "20; url="});
    HTMLNode contentNode = page.getContentNode();
    ctx.getPageMaker()
        .getInfobox(
            INFOBOX_INFORMATION, l10n("restartingTitle"), contentNode, "shutdown-progressing", true)
        .addChild("#", l10n("restarting"));
    LOG.info("Node is restarting");
    return pageNode;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("WelcomeToadlet." + key);
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase()
        .getString("WelcomeToadlet." + key, new String[] {pattern}, new String[] {value});
  }

  /**
   * Appends a tail of {@code wrapper.log} to the supplied content area when the wrapper log file is
   * present and readable.
   *
   * <p>The method reads up to 2,000 lines (respecting the byte cap in {@link
   * FileUtil#getLogTailReader(File, long)}) and streams them into an infobox labeled “Current
   * status”. It is safe to call even when the file is absent or unreadable; failures are logged at
   * DEBUG, and the page continues rendering without interruption. No locks are taken beyond
   * standard file reads, and the caller retains ownership of the provided {@link HTMLNode}.
   *
   * @param ctx toadlet context used to create localized infobox markup
   * @param contentNode the page node that receives the log output if available
   */
  public static void maybeDisplayWrapperLogfile(ToadletContext ctx, HTMLNode contentNode) {
    final File logs = new File("wrapper.log");
    long logSize = logs.length();
    if (logs.exists() && logs.isFile() && logs.canRead() && (logSize > 0)) {
      HTMLNode logInfoboxContent =
          ctx.getPageMaker()
              .getInfobox("infobox-info", "Current status", contentNode, "start-progress", true);
      try (LineReadingInputStream logreader = FileUtil.getLogTailReader(logs, 2000)) {
        String line;
        while ((line = logreader.readLine(100000, 200, true)) != null) {
          logInfoboxContent.addChild("#", line);
          logInfoboxContent.addChild("br");
        }
      } catch (IOException e) {
        LOG.debug("Failed to read wrapper log tail", e);
      }
    }
  }

  /**
   * Canonical welcome-page route used by FProxy navigation and bookmark creation flows; all welcome
   * toadlet links resolve relative to this root path.
   */
  public static final String ROOT_PATH = "/";

  /**
   * Returns the public entry path for the welcome toadlet so the container can route requests to
   * this implementation.
   *
   * <p>The value is always {@value #ROOT_PATH} to align with the “Browse Freenet” navigation link
   * and to make deep links (such as {@link #BOOKMARKS_ANCHOR}) stable. No computation or state
   * lookup occurs, making this method safe to call repeatedly during registration or request
   * handling.
   *
   * @return the string {@code "/"} representing the root of the welcome page
   */
  @Override
  public String path() {
    // So it matches "Browse Freenet" on the menu
    return ROOT_PATH;
  }
}
