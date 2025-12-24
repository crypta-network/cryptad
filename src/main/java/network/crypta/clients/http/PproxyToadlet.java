package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.pluginmanager.AccessDeniedPluginHTTPException;
import network.crypta.pluginmanager.DownloadPluginHTTPException;
import network.crypta.pluginmanager.NotFoundPluginHTTPException;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import network.crypta.pluginmanager.PluginHTTPException;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.pluginmanager.PluginManager.PluginProgress;
import network.crypta.pluginmanager.RedirectPluginHTTPException;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serves the plugins administration endpoint of the built-in HTTP interface and routes plugin
 * specific GET and POST requests to the appropriate plugin handlers.
 *
 * <p>This toadlet exposes a single hierarchical path under {@link #PLUGINS_PATH}. Requests with no
 * additional path render the management UI showing loaded plugins, loaders for official and
 * third-party plugins, and progress for plugins that are still starting. Requests with a plugin
 * identifier segment delegate directly to the plugin's HTTP adapter, allowing plugins to serve
 * their own resources without bypassing the node's access checks.
 *
 * <p>The instance relies on {@link Node} services such as the {@link PluginManager}, executor, and
 * update facilities supplied by the owning node. It trusts {@link ToadletContext} to enforce
 * authentication; POST submissions check form passwords while GET requests require full access. The
 * class itself is thread-safe at the toadlet level because all state is provided per request, but
 * it invokes plugin operations that may be long-running or asynchronous.
 *
 * <p>Typical usage is limited to the HTTP server wiring: construct once with the shared client and
 * node, register with the server under {@link #PLUGINS_PATH}, and let the inherited routing invoke
 * {@link #handleMethodGET(URI, HTTPRequest, ToadletContext)} or {@link #handleMethodPOST(URI,
 * HTTPRequest, ToadletContext)} for each request.
 */
public class PproxyToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(PproxyToadlet.class);
  private static final String KEY_PLUGINS = "plugins";
  private static final String PATH_SEPARATOR = "/";

  /**
   * Public path prefix for all plugin administration requests, always ending with a trailing slash
   * so relative links render correctly from within the management UI.
   *
   * <p>The path is registered with the HTTP server and used by plugin link generation elsewhere in
   * the codebase. External callers should treat it as a constant URL segment rather than a complete
   * URI and append plugin identifiers or relative targets as needed.
   */
  public static final String PLUGINS_PATH = PATH_SEPARATOR + KEY_PLUGINS + PATH_SEPARATOR;

  private static final String PLUGIN_PREFIX = "plugins/";
  private static final String STATUS_FOUND = "Found";
  private static final String HEADER_LOCATION = "Location";
  private static final String PARAM_FILE_ONLY = "fileonly";
  private static final String PARAM_UNLOAD_CONFIRM = "unloadconfirm";
  private static final String PARAM_UNLOAD = "unload";
  private static final String PARAM_RELOAD = "reload";
  private static final String PARAM_PURGE = "purge";
  private static final String PARAM_CANCEL = "cancel";
  private static final String ELEMENT_INPUT = "input";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_VALUE = "value";
  private static final String TYPE_HIDDEN = "hidden";
  private static final String TYPE_CHECKBOX = "checkbox";
  private static final String TYPE_SUBMIT = "submit";
  private static final String INFOBOX_HEADER = "infobox-header";
  private static final String INFOBOX_CONTENT = "infobox-content";
  private static final String INFOBOX_NORMAL = "infobox infobox-normal";
  private static final int MAX_PLUGIN_NAME_LENGTH = 1024;

  /** Maximum time to wait for a threaded plugin to exit */
  private static final long MAX_THREADED_UNLOAD_WAIT_TIME = SECONDS.toMillis(60);

  private final Node node;

  /**
   * Creates a toadlet that exposes plugin management over HTTP using the provided high-level client
   * facade and node services. The constructor performs no validation beyond null checks; the caller
   * remains responsible for registering the instance on the HTTP server under {@link #PLUGINS_PATH}
   * and for keeping the {@link Node} alive for the lifetime of the toadlet.
   *
   * <p>This constructor is typically invoked during node bootstrapping from a single-threaded setup
   * path, so it performs no heavy work. All expensive operations—such as plugin enumeration or
   * translation lookups—are deferred until request handling time.
   *
   * @param client the client used for upstream HTTP functionality; must not be {@code null}
   * @param node the owning node providing plugin, executor, and update services; must not be {@code
   *     null}
   */
  public PproxyToadlet(HighLevelSimpleClient client, Node node) {
    super(client);
    this.node = node;
  }

  /**
   * Indicates that POST requests to this toadlet may be processed without the global HTTP password
   * gate. Individual handlers still validate form passwords where appropriate. This aligns with the
   * broader UI model where the surrounding dashboard is already protected by access checks and
   * forms embed one-time tokens. Keeping the flag true prevents double prompts while still letting
   * downstream handlers reject malformed or unauthorized submissions.
   *
   * @return {@code true} to allow unauthenticated POST dispatch; form-level checks remain in place
   */
  @Override
  public boolean allowPOSTWithoutPassword() {
    return true;
  }

  /**
   * Handles plugin-related POST submissions, dispatching either to plugin-specific HTTP handlers or
   * to the built-in management forms depending on the requested path.
   *
   * <p>The method requires full toadlet access and rejects requests lacking sufficient rights. When
   * a plugin path segment is present, the call is delegated to {@link PluginManager#handleHTTPPost}
   * with the plugin identifier derived from the path. Otherwise, the method interprets form fields
   * for loading, unloading, reloading, and updating plugins, including purge and confirmation
   * flows. Unexpected exceptions result in an internal error response while known plugin HTTP
   * exceptions map to typed responses such as redirects or downloads.
   *
   * <p>Form parameters that refer to plugin identifiers are truncated to {@value
   * #MAX_PLUGIN_NAME_LENGTH} characters to guard against oversized submissions.
   *
   * @param uri the full request URI; must not be {@code null}
   * @param request parsed HTTP request wrapper providing form parameters and parts
   * @param ctx context for authentication, response writing, and localization lookups
   * @throws ToadletContextClosedException if the client connection closes while writing the reply
   * @throws IOException if an I/O error occurs while reading the request or sending the response
   */
  public void handleMethodPOST(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {

    Objects.requireNonNull(uri);

    if (!ctx.checkFullAccess(this)) return;

    String path = normalizePluginPath(request.getPath());

    if (LOG.isDebugEnabled()) LOG.debug("Pproxy received POST on {}", path);

    final PluginManager pm = node.getPluginManager();

    if (!path.isEmpty()) {
      handlePluginPost(path, pm, request, ctx);
      return;
    }

    handlePluginFormPost(request, ctx, pm);
  }

  private void handlePluginPost(
      String path, PluginManager pluginManager, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      String plugin;
      int to = path.indexOf('/');
      if (to == -1) {
        plugin = path;
      } else {
        plugin = path.substring(0, to);
      }

      writeHTMLReply(ctx, 200, "OK", pluginManager.handleHTTPPost(plugin, request));
    } catch (RedirectPluginHTTPException e) {
      writeTemporaryRedirect(ctx, e.message, e.newLocation);
    } catch (NotFoundPluginHTTPException e) {
      sendErrorPage(ctx, e.code(), e.message, e.location);
    } catch (AccessDeniedPluginHTTPException e) {
      sendErrorPage(ctx, e.code(), e.message, e.location);
    } catch (DownloadPluginHTTPException e) {
      MultiValueTable<String, String> head =
          MultiValueTable.from("Content-Disposition", "attachment; filename=\"" + e.filename + '"');
      ctx.sendReplyHeaders(e.code(), STATUS_FOUND, head, e.mimeType, e.data.length);
      ctx.writeData(e.data);
    } catch (PluginHTTPException e) {
      sendErrorPage(ctx, e.code(), e.message, e.location);
    } catch (Exception t) {
      writeInternalError(t, ctx);
    }
  }

  private void handlePluginFormPost(HTTPRequest request, ToadletContext ctx, PluginManager pm)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFormPassword(request)) return;

    MultiValueTable<String, String> headers = new MultiValueTable<>();
    PageMaker pageMaker = ctx.getPageMaker();

    if (request.isPartSet("submit-official")) {
      startOfficialPlugin(request, pm);
      sendFoundRedirect(ctx, headers, ".");
      return;
    }
    if (request.isPartSet("submit-other")) {
      startOtherPlugin(request, pm);
      sendFoundRedirect(ctx, headers, ".");
      return;
    }
    if (request.isPartSet("submit-freenet")) {
      startFreenetPlugin(request, pm);
      sendFoundRedirect(ctx, headers, ".");
      return;
    }
    if (request.isPartSet(PARAM_CANCEL)) {
      sendFoundRedirect(ctx, headers, PLUGINS_PATH);
      return;
    }

    String unloadConfirm =
        request.getPartAsStringFailsafe(PARAM_UNLOAD_CONFIRM, MAX_PLUGIN_NAME_LENGTH);
    if (!unloadConfirm.isEmpty()) {
      handleUnloadConfirmation(request, ctx, pm, pageMaker, unloadConfirm);
      return;
    }

    String unload = request.getPartAsStringFailsafe(PARAM_UNLOAD, MAX_PLUGIN_NAME_LENGTH);
    if (!unload.isEmpty()) {
      showUnloadConfirmation(ctx, pageMaker, unload);
      return;
    }

    String reload = request.getPartAsStringFailsafe(PARAM_RELOAD, MAX_PLUGIN_NAME_LENGTH);
    if (!reload.isEmpty()) {
      showReloadConfirmation(ctx, pm, pageMaker, reload);
      return;
    }

    String update = request.getPartAsStringFailsafe("update", MAX_PLUGIN_NAME_LENGTH);
    if (!update.isEmpty()) {
      handlePluginUpdate(ctx, pm, headers, update);
      return;
    }

    String reloadConfirm = request.getPartAsStringFailsafe("reloadconfirm", MAX_PLUGIN_NAME_LENGTH);
    if (!reloadConfirm.isEmpty()) {
      handlePluginReloadConfirmation(request, ctx, pm, headers, reloadConfirm);
      return;
    }

    sendFoundRedirect(ctx, headers, ".");
  }

  private boolean pluginWasLoadedFromLocalDisk(
      PluginManager pluginManager, String pluginIdentifier) {
    for (PluginInfoWrapper pluginInfoWrapper : pluginManager.getPlugins()) {
      if (pluginInfoWrapper.getThreadName().equals(pluginIdentifier)) {
        File pluginFile = new File(pluginInfoWrapper.getFilename());
        if (pluginFile.exists() && pluginFile.isFile()) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Searches all plugins for the plugin with the given thread name and returns the plugin
   * specification used to load the plugin.
   *
   * @param pluginManager The plugin manager
   * @param pluginThreadName The thread name of the plugin
   * @return The plugin specification of the plugin, or <code>null</code> if no plugin was found
   */
  private String getPluginSpecification(PluginManager pluginManager, String pluginThreadName) {
    for (PluginInfoWrapper pi : pluginManager.getPlugins()) {
      if (pi.getThreadName().equals(pluginThreadName)) {
        return pi.getFilename();
      }
    }
    return null;
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase()
        .getString("PproxyToadlet." + key, new String[] {pattern}, new String[] {value});
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("PproxyToadlet." + key);
  }

  private String normalizePluginPath(String path) {
    String normalizedPath = path;
    if (normalizedPath.startsWith("/")) {
      normalizedPath = normalizedPath.substring(1);
    }
    if (normalizedPath.startsWith(PLUGIN_PREFIX)) {
      normalizedPath = normalizedPath.substring(PLUGIN_PREFIX.length());
    }
    return normalizedPath;
  }

  private void sendFoundRedirect(
      ToadletContext ctx, MultiValueTable<String, String> headers, String location)
      throws ToadletContextClosedException, IOException {
    headers.put(HEADER_LOCATION, location);
    ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
  }

  private void startOfficialPlugin(HTTPRequest request, PluginManager pluginManager) {
    final String pluginName = request.getPartAsStringFailsafe("plugin-name", 40);
    node.getExecutor().execute(() -> pluginManager.startPluginOfficial(pluginName, true));
  }

  private void startOtherPlugin(HTTPRequest request, PluginManager pluginManager) {
    final String pluginName = request.getPartAsStringFailsafe("plugin-url", 200);
    final boolean fileOnly =
        "on".equalsIgnoreCase(request.getPartAsStringFailsafe(PARAM_FILE_ONLY, 20));

    node.getExecutor()
        .execute(
            () -> {
              if (fileOnly) {
                pluginManager.startPluginFile(pluginName, true);
              } else {
                pluginManager.startPluginURL(pluginName, true);
              }
            });
  }

  private void startFreenetPlugin(HTTPRequest request, PluginManager pluginManager) {
    final String pluginName = request.getPartAsStringFailsafe("plugin-uri", 300);
    node.getExecutor().execute(() -> pluginManager.startPluginFreenet(pluginName, true));
  }

  private void handleUnloadConfirmation(
      HTTPRequest request,
      ToadletContext ctx,
      PluginManager pluginManager,
      PageMaker pageMaker,
      String pluginThreadName)
      throws ToadletContextClosedException, IOException {
    String pluginSpecification = getPluginSpecification(pluginManager, pluginThreadName);
    pluginManager.killPlugin(pluginThreadName, MAX_THREADED_UNLOAD_WAIT_TIME, false);
    if (request.isPartSet(PARAM_PURGE)) {
      pluginManager.removeCachedCopy(pluginSpecification);
    }
    PageNode page = pageMaker.getPageNode(l10n(KEY_PLUGINS), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode infobox = contentNode.addChild("div", ATTR_CLASS, "infobox infobox-success");
    infobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER, l10n("pluginUnloaded"));
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    infoboxContent.addChild("#", l10n("pluginUnloadedWithName", "name", pluginThreadName));
    infoboxContent.addChild("br");
    infoboxContent.addChild("#", l10n("pluginFilesWarning"));
    infoboxContent.addChild("br");
    infoboxContent.addChild("br");
    infoboxContent.addChild("a", "href", PLUGINS_PATH, l10n("returnToPluginPage"));
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void showUnloadConfirmation(
      ToadletContext ctx, PageMaker pageMaker, String pluginThreadName)
      throws ToadletContextClosedException, IOException {
    PageNode page = pageMaker.getPageNode(l10n(KEY_PLUGINS), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode infobox = contentNode.addChild("div", ATTR_CLASS, "infobox infobox-query");
    infobox.addChild("div", ATTR_CLASS, INFOBOX_HEADER, l10n("unloadPluginTitle"));
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    infoboxContent.addChild("#", l10n("unloadPluginWithName", "name", pluginThreadName));
    HTMLNode unloadForm = ctx.addFormChild(infoboxContent, PLUGINS_PATH, "unloadPluginConfirmForm");
    unloadForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_HIDDEN, PARAM_UNLOAD_CONFIRM, pluginThreadName});
    HTMLNode tempNode = unloadForm.addChild("p");
    tempNode.addChild(
        ELEMENT_INPUT, new String[] {"type", "name"}, new String[] {TYPE_CHECKBOX, PARAM_PURGE});
    tempNode.addChild("#", l10n("unloadPurge"));
    tempNode = unloadForm.addChild("p");
    tempNode.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "confirm", l10n(PARAM_UNLOAD)});
    tempNode.addChild("#", " ");
    tempNode.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, PARAM_CANCEL, NodeL10n.getBase().getString("Toadlet.cancel")});
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void showReloadConfirmation(
      ToadletContext ctx, PluginManager pluginManager, PageMaker pageMaker, String pluginIdentifier)
      throws ToadletContextClosedException, IOException {
    PageNode page = pageMaker.getPageNode(l10n(KEY_PLUGINS), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode reloadContent =
        pageMaker.getInfobox(
            "infobox infobox-query", l10n("reloadPluginTitle"), contentNode, "plugin-reload", true);
    reloadContent.addChild("p", l10n("reloadExplanation"));
    reloadContent.addChild("p", l10n("reloadWarning"));
    HTMLNode reloadForm = ctx.addFormChild(reloadContent, PLUGINS_PATH, "reloadPluginConfirmForm");
    reloadForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_HIDDEN, "reloadconfirm", pluginIdentifier});
    if (!pluginWasLoadedFromLocalDisk(pluginManager, pluginIdentifier)) {
      HTMLNode tempNode = reloadForm.addChild("p");
      tempNode.addChild(
          ELEMENT_INPUT, new String[] {"type", "name"}, new String[] {TYPE_CHECKBOX, PARAM_PURGE});
      tempNode.addChild("#", l10n("reloadPurgeWarning"));
    }
    HTMLNode tempNode = reloadForm.addChild("p");
    tempNode.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "confirm", l10n(PARAM_RELOAD)});
    tempNode.addChild("#", " ");
    tempNode.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, PARAM_CANCEL, NodeL10n.getBase().getString("Toadlet.cancel")});
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void handlePluginUpdate(
      ToadletContext ctx,
      PluginManager pluginManager,
      MultiValueTable<String, String> headers,
      String pluginFilename)
      throws ToadletContextClosedException, IOException {
    if (!pluginManager.isPluginLoaded(pluginFilename)) {
      sendErrorPage(
          ctx,
          404,
          l10n("pluginNotFoundUpdatingTitle"),
          l10n("pluginNotFoundUpdating", "name", pluginFilename));
      return;
    }

    node.getNodeUpdater().deployPluginWhenReady(pluginFilename);
    sendFoundRedirect(ctx, headers, ".");
  }

  private void handlePluginReloadConfirmation(
      HTTPRequest request,
      ToadletContext ctx,
      PluginManager pluginManager,
      MultiValueTable<String, String> headers,
      String pluginThreadName)
      throws ToadletContextClosedException, IOException {
    boolean purge = request.isPartSet(PARAM_PURGE);
    final String filename = getPluginSpecification(pluginManager, pluginThreadName);

    if (filename == null) {
      sendErrorPage(ctx, 404, l10n("pluginNotFoundReloadTitle"), l10n("pluginNotFoundReload"));
      return;
    }

    pluginManager.killPlugin(pluginThreadName, MAX_THREADED_UNLOAD_WAIT_TIME, true);
    if (purge) {
      pluginManager.removeCachedCopy(filename);
    }
    node.getExecutor().execute(() -> pluginManager.startPluginAuto(filename, true));

    sendFoundRedirect(ctx, headers, ".");
  }

  /**
   * Handles GET requests for the plugin area, serving either the management dashboard or delegating
   * directly to a plugin's HTTP handler based on the remaining path.
   *
   * <p>The method checks debug logging for request paths, enforces access control for the root
   * dashboard, and forwards plugin-specific paths to {@link PluginManager#handleHTTPGet}. Known
   * plugin HTTP exceptions are translated into the appropriate HTTP responses, downloads are
   * streamed with correct headers, and socket-level failures force a disconnect to avoid partial
   * responses. All other unexpected errors generate an internal error page while logging the
   * incident.
   *
   * @param uri the resolved request URI used for context; not modified by the handler
   * @param request parsed HTTP request containing the path and headers
   * @param ctx execution context for permission checks and response writing
   * @throws ToadletContextClosedException if the client disconnects before the response completes
   * @throws IOException if the handler encounters an I/O problem while reading or writing data
   */
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String path = normalizePluginPath(request.getPath());

    PluginManager pm = node.getPluginManager();

    if (LOG.isDebugEnabled()) LOG.debug("Pproxy fetching {}", path);
    try {
      if (path.isEmpty()) {
        handleRootGet(pm, ctx);
      } else {
        handlePluginGet(path, pm, request, ctx);
      }
    } catch (RedirectPluginHTTPException e) {
      writeTemporaryRedirect(ctx, e.message, e.newLocation);
    } catch (NotFoundPluginHTTPException e) {
      sendErrorPage(ctx, e.code(), e.message, e.location);
    } catch (AccessDeniedPluginHTTPException e) {
      sendErrorPage(ctx, e.code(), e.message, e.location);
    } catch (DownloadPluginHTTPException e) {
      // Handles download responses inline rather than delegating to sendErrorPage.

      MultiValueTable<String, String> head =
          MultiValueTable.from("Content-Disposition", "attachment; filename=\"" + e.filename + '"');
      ctx.sendReplyHeaders(e.code(), STATUS_FOUND, head, e.mimeType, e.data.length);
      ctx.writeData(e.data);
    } catch (PluginHTTPException e) {
      sendErrorPage(ctx, e.code(), e.message, e.location);
    } catch (SocketException _) {
      ctx.forceDisconnect();
    } catch (Exception t) {
      ctx.forceDisconnect();
      LOG.error("Caught: {}", t, t);
      writeInternalError(t, ctx);
    }
  }

  private void handleRootGet(PluginManager pluginManager, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    Set<PluginProgress> startingPlugins = pluginManager.getStartingPlugins();
    PageNode page = ctx.getPageMaker().getPageNode(l10n(KEY_PLUGINS), ctx);
    boolean advancedModeEnabled = ctx.isAdvancedModeEnabled();
    addAutoRefreshMeta(page, startingPlugins);

    HTMLNode contentNode = page.getContentNode();
    contentNode.addChild(ctx.getAlertManager().createSummary());

    SortedMap<String, List<OfficialPluginDescription>> groupedAvailablePlugins =
        groupAvailablePlugins(pluginManager, startingPlugins, advancedModeEnabled);

    showStartingPlugins(pluginManager, contentNode);
    showPluginList(ctx, pluginManager, contentNode, advancedModeEnabled);
    showOfficialPluginLoader(
        ctx, contentNode, groupedAvailablePlugins, pluginManager, advancedModeEnabled);
    showUnofficialPluginLoader(ctx, contentNode);
    showFreenetPluginLoader(ctx, contentNode);

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void handlePluginGet(
      String path, PluginManager pluginManager, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, PluginHTTPException {
    int to = path.indexOf('/');
    String plugin;
    if (to == -1) {
      plugin = path;
    } else {
      plugin = path.substring(0, to);
    }

    writeHTMLReply(ctx, 200, "OK", pluginManager.handleHTTPGet(plugin, request));
  }

  private void addAutoRefreshMeta(PageNode page, Set<PluginProgress> startingPlugins) {
    if (startingPlugins.isEmpty()) {
      return;
    }
    page.getHeadNode()
        .addChild(
            "meta", new String[] {"http-equiv", "content"}, new String[] {"refresh", "10; url="});
  }

  private SortedMap<String, List<OfficialPluginDescription>> groupAvailablePlugins(
      PluginManager pluginManager,
      Set<PluginProgress> startingPlugins,
      boolean advancedModeEnabled) {
    List<OfficialPluginDescription> availablePlugins =
        new ArrayList<>(pluginManager.findAvailablePlugins());
    removeLoadedPlugins(pluginManager, availablePlugins);
    removeStartingPlugins(startingPlugins, pluginManager, availablePlugins);

    SortedMap<String, List<OfficialPluginDescription>> groupedAvailablePlugins = new TreeMap<>();
    for (OfficialPluginDescription pluginDescription : availablePlugins) {
      if (!advancedModeEnabled
          && (pluginDescription.advanced
              || pluginDescription.experimental
              || pluginDescription.deprecated)) {
        continue;
      }
      String translatedGroup = l10n("pluginGroup." + pluginDescription.group);
      groupedAvailablePlugins
          .computeIfAbsent(translatedGroup, key -> new ArrayList<>())
          .add(pluginDescription);
    }
    for (List<OfficialPluginDescription> pluginDescriptions : groupedAvailablePlugins.values()) {
      pluginDescriptions.sort(Comparator.comparing(description -> description.name));
    }
    return groupedAvailablePlugins;
  }

  private void removeLoadedPlugins(
      PluginManager pluginManager, List<OfficialPluginDescription> availablePlugins) {
    for (PluginInfoWrapper pluginInfoWrapper : pluginManager.getPlugins()) {
      String pluginName = pluginInfoWrapper.getPluginClassName();
      String shortPluginName = pluginName.substring(pluginName.lastIndexOf('.') + 1);

      if (shortPluginName.equals("FreemailPlugin")) {
        shortPluginName = "Freemail";
      }

      availablePlugins.remove(pluginManager.isOfficialPlugin(shortPluginName));
    }
  }

  private void removeStartingPlugins(
      Set<PluginProgress> startingPlugins,
      PluginManager pluginManager,
      List<OfficialPluginDescription> availablePlugins) {
    for (PluginProgress pluginProgress : startingPlugins) {
      String pluginName = pluginProgress.getName();
      availablePlugins.remove(pluginManager.isOfficialPlugin(pluginName));
    }
  }

  /**
   * Shows a list of all currently loading plugins.
   *
   * @param pluginManager The plugin manager
   * @param contentNode The node to add content to
   */
  private void showStartingPlugins(PluginManager pluginManager, HTMLNode contentNode) {
    Set<PluginProgress> startingPlugins = pluginManager.getStartingPlugins();
    if (!startingPlugins.isEmpty()) {
      HTMLNode startingPluginsBox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL);
      startingPluginsBox.addChild("div", ATTR_CLASS, INFOBOX_HEADER, l10n("startingPluginsTitle"));
      HTMLNode startingPluginsContent =
          startingPluginsBox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
      HTMLNode startingPluginsTable = startingPluginsContent.addChild("table");
      HTMLNode startingPluginsHeader = startingPluginsTable.addChild("tr");
      startingPluginsHeader.addChild("th", l10n("startingPluginName"));
      startingPluginsHeader.addChild("th", l10n("startingPluginStatus"));
      startingPluginsHeader.addChild("th", l10n("startingPluginTime"));
      for (PluginProgress pluginProgress : startingPlugins) {
        HTMLNode startingPluginsRow = startingPluginsTable.addChild("tr");
        startingPluginsRow.addChild("td", pluginProgress.getLocalisedPluginName());
        startingPluginsRow.addChild(pluginProgress.toLocalisedHTML());
        startingPluginsRow.addChild(
            "td", "aligh", "right", TimeUtil.formatTime(pluginProgress.getTime()));
      }
    }
  }

  private void showPluginList(
      ToadletContext ctx, PluginManager pm, HTMLNode contentNode, boolean advancedMode) {
    HTMLNode infobox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL);
    infobox.addChild(
        "div",
        ATTR_CLASS,
        INFOBOX_HEADER,
        NodeL10n.getBase().getString("PluginToadlet.pluginListTitle"));
    HTMLNode infoboxContent = infobox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    if (pm.getPlugins().isEmpty()) {
      infoboxContent.addChild("div", l10n("noPlugins"));
      return;
    }

    HTMLNode pluginTable = infoboxContent.addChild("table", ATTR_CLASS, KEY_PLUGINS);
    addPluginTableHeaders(pluginTable, advancedMode);
    for (PluginInfoWrapper pluginInfoWrapper : pm.getPlugins()) {
      addPluginRow(ctx, pluginTable, advancedMode, pluginInfoWrapper);
    }
  }

  private void addPluginTableHeaders(HTMLNode pluginTable, boolean advancedMode) {
    HTMLNode headerRow = pluginTable.addChild("tr");
    headerRow.addChild("th", l10n("pluginFilename"));
    if (advancedMode) {
      headerRow.addChild("th", l10n("classNameTitle"));
    }
    headerRow.addChild("th", l10n("versionTitle"));
    if (advancedMode) {
      headerRow.addChild("th", l10n("internalIDTitle"));
      headerRow.addChild("th", l10n("startedAtTitle"));
    }
    headerRow.addChild("th");
    headerRow.addChild("th");
    headerRow.addChild("th");
  }

  private void addPluginRow(
      ToadletContext ctx,
      HTMLNode pluginTable,
      boolean advancedMode,
      PluginInfoWrapper pluginInfo) {
    HTMLNode pluginRow = pluginTable.addChild("tr");
    pluginRow.addChild("td", pluginInfo.getLocalisedPluginName());
    if (advancedMode) {
      pluginRow.addChild("td", pluginInfo.getPluginClassName());
    }
    pluginRow.addChild("td", formatPluginVersion(pluginInfo));
    if (advancedMode) {
      pluginRow.addChild("td", pluginInfo.getThreadName());
      pluginRow.addChild("td", new Date(pluginInfo.getStarted()).toString());
    }
    if (pluginInfo.isStopping()) {
      addStoppingCells(pluginRow);
      return;
    }

    addVisitCell(ctx, pluginRow, pluginInfo);
    addUnloadCell(ctx, pluginRow, pluginInfo);
    addReloadCell(ctx, pluginRow, pluginInfo);
  }

  private String formatPluginVersion(PluginInfoWrapper pluginInfo) {
    long version = pluginInfo.getPluginLongVersion();
    if (version == -1) {
      return pluginInfo.getPluginVersion();
    }
    return pluginInfo.getPluginVersion() + " (" + version + ")";
  }

  private void addStoppingCells(HTMLNode pluginRow) {
    pluginRow.addChild("td", l10n("pluginStopping"));
    pluginRow.addChild("td");
    pluginRow.addChild("td");
  }

  private void addVisitCell(ToadletContext ctx, HTMLNode pluginRow, PluginInfoWrapper pluginInfo) {
    if (pluginInfo.isPproxyPlugin()) {
      HTMLNode visitForm =
          pluginRow
              .addChild("td")
              .addChild(
                  "form",
                  new String[] {"method", "action", "target", "rel"},
                  new String[] {
                    "get", pluginInfo.getPluginClassName(), "_blank", "noreferrer noopener"
                  });
      visitForm.addChild(
          ELEMENT_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {TYPE_HIDDEN, "formPassword", ctx.getFormPassword()});
      visitForm.addChild(
          ELEMENT_INPUT,
          new String[] {"type", ATTR_VALUE},
          new String[] {TYPE_SUBMIT, NodeL10n.getBase().getString("PluginToadlet.visit")});
      return;
    }
    pluginRow.addChild("td");
  }

  private void addUnloadCell(ToadletContext ctx, HTMLNode pluginRow, PluginInfoWrapper pluginInfo) {
    HTMLNode unloadForm = ctx.addFormChild(pluginRow.addChild("td"), ".", "unloadPluginForm");
    unloadForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_HIDDEN, PARAM_UNLOAD, pluginInfo.getThreadName()});
    unloadForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, l10n(PARAM_UNLOAD)});
  }

  private void addReloadCell(ToadletContext ctx, HTMLNode pluginRow, PluginInfoWrapper pluginInfo) {
    HTMLNode reloadForm = ctx.addFormChild(pluginRow.addChild("td"), ".", "reloadPluginForm");
    reloadForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_HIDDEN, PARAM_RELOAD, pluginInfo.getThreadName()});
    reloadForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, l10n(PARAM_RELOAD)});
  }

  private void showOfficialPluginLoader(
      ToadletContext toadletContext,
      HTMLNode contentNode,
      Map<String, List<OfficialPluginDescription>> availablePlugins,
      PluginManager pm,
      boolean advancedModeEnabled) {
    /* box for "official" plugins. */
    HTMLNode addOfficialPluginBox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL);
    addOfficialPluginBox.addChild("div", ATTR_CLASS, INFOBOX_HEADER, l10n("loadOfficialPlugin"));
    HTMLNode addOfficialPluginContent =
        addOfficialPluginBox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    HTMLNode addOfficialForm =
        toadletContext.addFormChild(addOfficialPluginContent, ".", "addOfficialPluginForm");

    HTMLNode p = addOfficialForm.addChild("p");
    p.addChild("#", l10n("loadOfficialPluginText"));

    for (Entry<String, List<OfficialPluginDescription>> groupPlugins :
        availablePlugins.entrySet()) {
      List<OfficialPluginDescription> notLoadedPlugins =
          groupPlugins.getValue().stream()
              .filter(plugin -> !pm.isPluginLoaded(plugin.name))
              .filter(plugin -> !plugin.unsupported)
              .toList();
      if (notLoadedPlugins.isEmpty()) {
        continue;
      }
      addPluginGroupForLoading(
          advancedModeEnabled, groupPlugins, addOfficialForm, notLoadedPlugins);
    }
    addOfficialForm
        .addChild("p")
        .addChild(
            ELEMENT_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {TYPE_SUBMIT, "submit-official", l10n("Load")});
  }

  private void addPluginGroupForLoading(
      boolean advancedModeEnabled,
      Entry<String, List<OfficialPluginDescription>> groupPlugins,
      HTMLNode addOfficialForm,
      List<OfficialPluginDescription> notLoadedPlugins) {
    HTMLNode pluginGroupNode = addOfficialForm.addChild("div", ATTR_CLASS, "plugin-group");
    pluginGroupNode.addChild(
        "div",
        ATTR_CLASS,
        "plugin-group-title",
        l10n("pluginGroupTitle", "pluginGroup", groupPlugins.getKey()));
    for (OfficialPluginDescription pluginDescription : notLoadedPlugins) {
      HTMLNode pluginNode = pluginGroupNode.addChild("div", ATTR_CLASS, "plugin");
      HTMLNode option =
          pluginNode.addChild(
              ELEMENT_INPUT,
              new String[] {"type", "name", ATTR_VALUE, "id"},
              new String[] {
                "radio",
                "plugin-name",
                pluginDescription.name,
                "radioPlugin" + pluginDescription.name
              });
      option
          .addChild(
              "label", new String[] {"for"}, new String[] {"radioPlugin" + pluginDescription.name})
          .addChild("i", pluginDescription.getLocalisedPluginName());
      if (pluginDescription.deprecated)
        option.addChild("b", " (" + l10n("loadLabelDeprecated") + ")");
      if (pluginDescription.experimental)
        option.addChild("b", " (" + l10n("loadLabelExperimental") + ")");
      if (advancedModeEnabled && pluginDescription.minimumVersion >= 0) {
        option.addChild(
            "#", " (" + l10n("pluginVersion") + " " + pluginDescription.recommendedVersion + ")");
      }
      option.addChild("#", " - " + pluginDescription.getLocalisedPluginDescription());
    }
  }

  private void showUnofficialPluginLoader(ToadletContext toadletContext, HTMLNode contentNode) {
    /* box for unofficial plugins. */
    HTMLNode addOtherPluginBox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL);
    addOtherPluginBox.addChild("div", ATTR_CLASS, INFOBOX_HEADER, l10n("loadOtherPlugin"));
    HTMLNode addOtherPluginContent = addOtherPluginBox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    HTMLNode addOtherForm =
        toadletContext.addFormChild(addOtherPluginContent, ".", "addOtherPluginForm");
    addOtherForm.addChild("div", l10n("loadOtherPluginText"));
    addOtherForm.addChild("#", (l10n("loadOtherURLLabel") + ": "));
    addOtherForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", "size"},
        new String[] {"text", "plugin-url", "80"});
    addOtherForm.addChild("#", " ");
    addOtherForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "submit-other", l10n("Load")});
    addOtherForm.addChild("br");
    addOtherForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", "checked", "id"},
        new String[] {TYPE_CHECKBOX, PARAM_FILE_ONLY, "checked", PARAM_FILE_ONLY});
    addOtherForm.addChild(
        "label", new String[] {"for"}, new String[] {PARAM_FILE_ONLY}, " " + l10n(PARAM_FILE_ONLY));
  }

  private void showFreenetPluginLoader(ToadletContext toadletContext, HTMLNode contentNode) {
    /* box for freenet plugins. */
    HTMLNode addFreenetPluginBox = contentNode.addChild("div", ATTR_CLASS, INFOBOX_NORMAL);
    addFreenetPluginBox.addChild("div", ATTR_CLASS, INFOBOX_HEADER, l10n("loadCryptaPlugin"));
    HTMLNode addFreenetPluginContent =
        addFreenetPluginBox.addChild("div", ATTR_CLASS, INFOBOX_CONTENT);
    HTMLNode addFreenetForm =
        toadletContext.addFormChild(addFreenetPluginContent, ".", "addFreenetPluginForm");
    addFreenetForm.addChild("div", l10n("loadCryptaPluginText"));
    addFreenetForm.addChild("#", (l10n("loadCryptaURLLabel") + ": "));
    addFreenetForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", "size"},
        new String[] {"text", "plugin-uri", "80"});
    addFreenetForm.addChild("#", " ");
    addFreenetForm.addChild(
        ELEMENT_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "submit-freenet", l10n("Load")});
  }

  /**
   * Returns the registered HTTP path for this toadlet, including a trailing slash to simplify
   * relative link construction inside generated pages.
   *
   * <p>The value is a stable, public constant and is used by both the dispatcher and the rendered
   * HTML forms when composing self-referential targets. Callers should append plugin identifiers or
   * child paths rather than stripping the trailing slash, because the UI expects relative links to
   * resolve from that directory-style prefix.
   *
   * @return the canonical path prefix under which plugin management requests are served
   */
  @Override
  public String path() {
    return PLUGINS_PATH;
  }
}
