package network.crypta.clients.http;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.filter.PushingTagReplacerCallback;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.SecurityLevels;
import network.crypta.pluginmanager.FredPluginL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds and renders the shared HTML skeleton used by Crypta's HTTP console pages.
 *
 * <p>It assembles the document head (favicons, stylesheets, scripts), navigation menus, status
 * indicators, and main content containers while honoring theme selection, localization, and the
 * caller's access level. Typical callers configure menus once per plugin or request handler and
 * then obtain a {@link PageNode} for each response via {@link #getPageNode(String,
 * ToadletContext)}, injecting their own content into the returned container.
 *
 * <p>State is limited to configured menus and the active {@linkplain #setTheme(THEME) theme};
 * rendering itself is stateless and produces fresh node trees on each invocation. The class is safe
 * to use from multiple threads provided callers synchronize mutations to shared navigation
 * configuration. Expensive assets are loaded lazily and reused through standard browser caching.
 *
 * <ul>
 *   <li>Composes page heads with optional web-push bootstrap and theme assets.
 *   <li>Renders navigation/status controls that adapt to advanced-mode and access rights.
 *   <li>Provides helpers for localization-aware CSS identifiers and infobox creation.
 * </ul>
 *
 * @see PageMaker.RenderParameters
 * @see PageNode
 */
public final class PageMaker {
  private static final Logger LOG = LoggerFactory.getLogger(PageMaker.class);

  private static final String ATTR_TITLE = "title";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_LANGUAGE = "language";
  private static final String ATTR_HREF = "href";
  private static final String ATTR_CLASS = "class";
  private static final String MIME_TEXT_CSS = "text/css";
  private static final String MIME_TEXT_JAVASCRIPT = "text/javascript";
  private static final String JAVASCRIPT = "javascript";
  private static final String THEME_BASE_PATH = "static/themes/";
  private static final String THEME_STYLESHEET = "/theme.css";
  private static final String THEME_SCRIPT = "/script.js";
  private static final String STYLESHEET = "stylesheet";
  private static final String TAG_SCRIPT = "script";
  private static final String TAG_LINK = "link";
  private static final String TAG_TITLE = "title";
  private static final String TAG_A = "a";
  private static final String TAG_DIV = "div";
  private static final String TAG_UL = "ul";
  private static final String TAG_LI = "li";

  /** Mode value that renders the UI without advanced controls, suited for first-time users. */
  public static final int MODE_SIMPLE = 1;

  /** Mode value that shows the full set of controls intended for experienced users. */
  public static final int MODE_ADVANCED = 2;

  /**
   * Enumeration of visual themes available to the HTTP console.
   *
   * <p>Each theme bundles a stylesheet, optional JavaScript, and hints that influence how the
   * welcome page is populated. The active theme is chosen through {@link #setTheme(THEME)} and is
   * baked into the generated head section. Themes are discoverable via {@link #possibleValues()} to
   * help configuration UIs.
   */
  public enum THEME {
    /**
     * Default theme pairing a dark-friendly palette with restrained contrasts and JavaScript hooks
     * for client-side enhancements.
     */
    CRYPTAFORGE(
        "cryptaforge",
        "Cryptaforge",
        "Modern theme with dark mode support and clean design",
        true,
        false);

    private static final String[] POSSIBLE_VALUES = {CRYPTAFORGE.code};

    /** Machine-readable code used for file names, CSS identifiers, and query parameters. */
    public final String code; // the internal name

    /** Human-facing label shown in settings menus and theme selectors. */
    public final String displayName; // the name in "human form"

    /** Short marketing description used in tooltips and configuration summaries. */
    public final String description; // description

    /**
     * Whether the welcome page should always display active links, regardless of the user's own
     * preference toggle.
     */
    public final boolean forceActivelinks;

    /**
     * Whether the “Fetch a key” infobox is elevated above the bookmarks panel on the welcome page
     * for quicker discovery.
     */
    public final boolean fetchKeyBoxAboveBookmarks;

    THEME(
        String code,
        String displayName,
        String description,
        boolean forceActivelinks,
        boolean fetchKeyBoxAboveBookmarks) {
      this.code = code;
      this.displayName = displayName;
      this.description = description;
      this.forceActivelinks = forceActivelinks;
      this.fetchKeyBoxAboveBookmarks = fetchKeyBoxAboveBookmarks;
    }

    /**
     * Resolves a theme from a user-provided identifier.
     *
     * <p>Matching is case-insensitive and accepts either the {@link #code} or {@link #displayName}
     * value. Unknown identifiers fall back to {@link #getDefault()} to avoid rendering failures.
     *
     * @param cssName theme identifier supplied by configuration or query parameters; {@code null}
     *     yields the default theme
     * @return matching theme or the default when no match is found
     */
    public static THEME themeFromName(String cssName) {
      for (THEME t : THEME.values()) {
        if (t.code.equalsIgnoreCase(cssName) || t.displayName.equalsIgnoreCase(cssName)) {
          return t;
        }
      }
      return getDefault();
    }

    /**
     * Returns the theme used when no explicit user preference is available.
     *
     * <p>The default is stable to reduce cache churn and keep bookmark screenshots consistent
     * across releases.
     *
     * @return the default theme instance
     */
    public static THEME getDefault() {
      return THEME.CRYPTAFORGE;
    }

    /**
     * Lists the set of theme identifiers that callers may present to users.
     *
     * @return a defensive copy of the available theme codes suitable for UI dropdowns
     */
    public static String[] possibleValues() {
      return POSSIBLE_VALUES.clone();
    }
  }

  PageMaker(THEME t, Node n) {
    setTheme(t);
    this.node = n;
  }

  /**
   * Builds a stable CSS identifier from a plugin class name and localization key.
   *
   * <p>The identifier is sanitized via {@link #filterCSSIdentifier(String)} so that it can be used
   * safely as an HTML {@code id} or class name regardless of plugin package naming conventions or
   * translation keys. Callers typically use the result to tag navigation items or infoboxes for
   * styling while keeping selectors resilient to localization changes.
   *
   * @param plugin plugin localization instance supplying the class name namespace; must not be
   *     {@code null}
   * @param key translation key or other logical identifiers to append after the plugin name
   * @return sanitized CSS identifier combining plugin and key components
   */
  public static String getPluginL10nCSSIdentifier(FredPluginL10n plugin, String key) {
    return filterCSSIdentifier(plugin.getClass().getName() + '-' + key);
  }

  /**
   * Filters a string into a syntactically valid CSS identifier.
   *
   * <p>The filter replaces any character outside {@code [-_a-zA-Z0-9]} with an underscore, and
   * guards against identifiers beginning with "-" followed by a non-letter by substituting an
   * underscore. Identifiers shorter than two characters are padded with underscores to meet CSS
   * grammar requirements. The filter is intentionally ASCII-only to avoid surprises in selectors
   * and tools that do not fully support Unicode identifiers.
   *
   * @param input raw identifier candidate, such as a localization key or plugin name
   * @return a sanitized identifier that may be used in HTML id/class attributes
   * @see <a href="http://www.w3.org/TR/CSS21/syndata.html#tokenization">CSS 2.1 tokenization</a>
   * @see <a href="http://www.w3.org/TR/CSS21/grammar.html#scanner">CSS 2.1 scanner</a>
   * @see <a href="http://stackoverflow.com/questions/448981/">StackOverflow discussion</a>
   */
  public static String filterCSSIdentifier(String input) {
    while (input.length() < 2) {
      input = input.concat("_");
    }

    return input.replaceFirst("^-[^_a-zA-Z]", "-_").replaceAll("[^-_a-zA-Z0-9]", "_");
  }

  /**
   * Registers a navigation category that appears in the main menu bar.
   *
   * <p>The category is keyed by {@code name} and points to {@code link} when clicked. The provided
   * {@code title} is shown as the tooltip. If a plugin localization object is supplied, generated
   * CSS identifiers and text fall back to plugin-local translations; otherwise node-local strings
   * are used. Existing entries with the same name are replaced.
   *
   * @param link default navigation target when the category itself is clicked
   * @param name menu label used for both CSS identifiers and the visible link text
   * @param title tooltip text describing the category’s purpose
   * @param plugin optional plugin localization provider that owns the link text; {@code null}
   *     yields node-local translations
   */
  public synchronized void addNavigationCategory(
      String link, String name, String title, FredPluginL10n plugin) {
    SubMenu menu = new SubMenu(link, name, title, plugin);
    subMenus.put(name, menu);
    menuList.add(menu);
  }

  /**
   * Adds a navigation category at a specific position in the menu bar.
   *
   * <p>This overload mirrors {@link #addNavigationCategory(String, String, String, FredPluginL10n)}
   * but inserts the category at {@code menuOffset} instead of appending. Positions are counted from
   * the left starting at zero; out-of-range offsets behave like {@link List#add(int, Object)} and
   * may throw if negative.
   *
   * @param link default navigation target when the category itself is clicked
   * @param name menu label used for both CSS identifiers and the visible link text
   * @param title tooltip text describing the category’s purpose
   * @param plugin optional plugin localization provider that owns the link text; {@code null}
   *     yields node-local translations
   * @param menuOffset The position of the link in FProxy's menu. 0 = left.
   */
  @SuppressWarnings("unused")
  public synchronized void addNavigationCategory(
      String link, String name, String title, FredPluginL10n plugin, int menuOffset) {
    SubMenu menu = new SubMenu(link, name, title, plugin);
    subMenus.put(name, menu);
    menuList.add(menuOffset, menu);
  }

  /**
   * Removes a navigation category and all of its links.
   *
   * <p>If the category does not exist, a log entry is emitted and the method returns without
   * throwing. Callers typically pair this with {@link #addNavigationCategory(String, String,
   * String, FredPluginL10n)} when plugins are unloaded.
   *
   * @param name category key previously registered via {@code addNavigationCategory}
   */
  @SuppressWarnings("unused")
  public synchronized void removeNavigationCategory(String name) {
    SubMenu menu = subMenus.remove(name);
    if (menu == null) {
      LOG.error("can't remove navigation category, name={}", name);
      return;
    }
    menuList.remove(menu);
  }

  /**
   * Adds a navigation link to an existing submenu.
   *
   * <p>Links can be marked {@code fullOnly} to hide them from limited-access sessions. When {@code
   * cb} is provided, the link is rendered only if the callback returns {@code true} for the current
   * {@link ToadletContext}. Titles and link text are localized using the supplied plugin
   * localization when present; otherwise node-local strings are used.
   *
   * @param menutext name of the parent menu as registered via {@code addNavigationCategory}
   * @param path relative path invoked when the link is clicked
   * @param name key identifying the link within the submenu; also used for CSS ids
   * @param title tooltip text describing the destination
   * @param fullOnly {@code true} to show only for full-access sessions; {@code false} to show to
   *     all users
   * @param cb optional callback evaluated to decide whether the link is enabled for the current
   *     request; may be {@code null}
   * @param l10n optional plugin localization used to translate link text and titles
   * @throws NullPointerException if no submenu exists for {@code menutext}
   */
  public synchronized void addNavigationLink(
      String menutext,
      String path,
      String name,
      String title,
      boolean fullOnly,
      LinkEnabledCallback cb,
      FredPluginL10n l10n) {
    SubMenu menu = subMenus.get(menutext);
    if (menu == null) {
      throw new NullPointerException("there is no menu named " + menutext);
    }
    menu.addNavigationLink(path, name, title, fullOnly, cb, l10n);
  }

  /**
   * Removes a navigation link from a submenu across all pages.
   *
   * <p>This updates the shared menu model; per-request customization should instead adjust the
   * {@link RenderParameters}. Missing links are ignored silently.
   *
   * @param menutext parent menu name
   * @param name the link key within that menu to remove
   */
  public synchronized void removeNavigationLink(String menutext, String name) {
    SubMenu menu = subMenus.get(menutext);
    // The menu may have already been removed.
    if (menu != null) {
      menu.removeNavigationLink(name);
    }
  }

  /**
   * Builds a backlink element targeting the HTTP referer when present.
   *
   * <p>The link falls back to a JavaScript {@code history.back()} call when no referer header is
   * available. The caller is responsible for inserting the returned node into the page content.
   *
   * @param toadletContext request context used to extract the {@code Referer} header; may be {@code
   *     null} but will then always emit the JavaScript fallback
   * @param name visible text for the link
   * @return hyperlink node pointing either to the referer or a client-side back action
   */
  public HTMLNode createBackLink(ToadletContext toadletContext, String name) {
    String referer = toadletContext.getHeaders().getFirst("referer");
    if (referer != null) {
      return new HTMLNode(
          "a", new String[] {"href", ATTR_TITLE}, new String[] {referer, name}, name);
    }
    return new HTMLNode(
        "a", new String[] {"href", ATTR_TITLE}, new String[] {"javascript:back()", name}, name);
  }

  /**
   * Generates a fully themed page scaffold with default navigation and status elements.
   *
   * <p>The returned {@link PageNode} contains a head populated with favicons, stylesheets, and
   * scripts, plus a body with navigation, status bar, and a content container. Callers typically
   * append their own nodes to {@link PageNode#getContentNode()} and then serialize the page through
   * the standard rendering pipeline.
   *
   * @param title page title shown in the browser and within the header
   * @param ctx request context; determines access level, theme delivery, and localization; may be
   *     {@code null} for non-request rendering paths
   * @return {@link PageNode} with head and body ready for caller-provided content
   */
  public PageNode getPageNode(String title, ToadletContext ctx) {
    return getPageNode(title, ctx, new RenderParameters());
  }

  /**
   * Generates a template page while controlling whether navigation is rendered.
   *
   * <p>This overload is useful for lightweight pages such as popups or embedded resources that do
   * not need the global navigation bar. Status information remains enabled to keep context visible
   * for the user unless suppressed via {@link RenderParameters}.
   *
   * @param title page title shown in the browser and within the header
   * @param renderNavigationLinks {@code true} to render the navigation bar; {@code false} to omit
   * @param ctx request context controlling permissions, localisation, and theme delivery
   * @return a template {@link PageNode}; prefer {@link #getPageNode(String, ToadletContext,
   *     RenderParameters)} for additional control
   */
  public PageNode getPageNode(String title, boolean renderNavigationLinks, ToadletContext ctx) {
    return getPageNode(
        title,
        ctx,
        new RenderParameters().renderNavigationLinks(renderNavigationLinks).renderStatus(true));
  }

  /**
   * Generates a template page while selecting both navigation and status visibility.
   *
   * <p>Use this overload when rendering narrow embedded views or diagnostic screens that should not
   * include top-level chrome. Other page aspects (theme, assets, content container) remain
   * unchanged from the default rendering path.
   *
   * @param title page title shown in the browser and within the header
   * @param renderNavigationLinks {@code true} to render the navigation bar; {@code false} to omit
   * @param renderStatus {@code true} to include the status bar; {@code false} to omit
   * @param ctx request context controlling permissions, localisation, and theme delivery
   * @return template {@link PageNode}; prefer {@link #getPageNode(String, ToadletContext,
   *     RenderParameters)} for finer-grained options
   */
  public PageNode getPageNode(
      String title, boolean renderNavigationLinks, boolean renderStatus, ToadletContext ctx) {
    return getPageNode(
        title,
        ctx,
        new RenderParameters()
            .renderNavigationLinks(renderNavigationLinks)
            .renderStatus(renderStatus)
            .renderModeSwitch(true));
  }

  /**
   * Generates a template page with explicit control over optional elements.
   *
   * <p>The {@link RenderParameters} determine whether navigation, status bar, and mode switch are
   * included. When {@code ctx} is {@code null}, the page still renders but omits features that rely
   * on request context (e.g., advanced-mode toggle). This method is the preferred entry point for
   * callers that need deterministic output across different embedding scenarios.
   *
   * @param title page title shown in the browser and within the header
   * @param ctx request context; may be {@code null} for out-of-band rendering such as plugin
   *     dashboards
   * @param renderParameters immutable set of flags controlling which UI chrome is rendered
   * @return {@link PageNode} containing a ready-to-populate content container
   */
  public PageNode getPageNode(String title, ToadletContext ctx, RenderParameters renderParameters) {
    boolean fullAccess = ctx != null && ctx.isAllowedFullAccess();
    HTMLNode pageNode = new HTMLNode.HTMLDoctype("html", "-//W3C//DTD XHTML 1.1//EN");
    HTMLNode htmlNode =
        pageNode.addChild("html", "xml:lang", NodeL10n.getBase().getSelectedLanguage().isoCode);
    HTMLNode headNode = createHeadNode(htmlNode, title, ctx);

    boolean webPushingEnabled = isWebPushingEnabled(ctx);
    String activePath = resolveActivePath(ctx);
    HTMLNode contentDiv =
        createBody(
            htmlNode, title, ctx, renderParameters, fullAccess, webPushingEnabled, activePath);
    return new PageNode(pageNode, headNode, contentDiv);
  }

  private HTMLNode createHeadNode(HTMLNode htmlNode, String title, ToadletContext ctx) {
    HTMLNode headNode = htmlNode.addChild("head");
    headNode.addChild(
        "meta",
        new String[] {"http-equiv", "content"},
        new String[] {"Content-Type", "text/html; charset=utf-8"});
    headNode.addChild(TAG_TITLE, title + " - Crypta");
    addFavicons(headNode);
    addThemeBootstrap(headNode);
    addThemeStylesheets(headNode, ctx);
    addThemeScripts(headNode, ctx);
    addPushingScript(headNode, ctx);
    return headNode;
  }

  private void addFavicons(HTMLNode headNode) {
    headNode.addChild(
        TAG_LINK,
        new String[] {"rel", ATTR_HREF, ATTR_TYPE},
        new String[] {"icon", "/static/favicon.svg", "image/svg+xml"});
    headNode.addChild(
        TAG_LINK,
        new String[] {"rel", ATTR_HREF, "sizes"},
        new String[] {"icon", "/favicon.ico", "any"});
  }

  private void addThemeBootstrap(HTMLNode headNode) {
    headNode.addChild("noscript").addChild("style", " .jsonly {display:none;}");
    headNode.addChild(
        new HTMLNode(
            "%",
            """
            <style>
              :root[data-theme="dark"] {
                --bg-primary: #1a1a1a;
                --text-primary: #e0e0e0;
              }
              :root[data-theme="light"] {
                --bg-primary: #fff;
                --text-primary: #333;
              }
            </style>

            <script>
              try {
                let current_theme = "light";
                const m = localStorage.getItem("theme-mode"); // 'light' | 'dark' | 'system' | null
                const d = document.documentElement;

                if (m === null) {
                  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                    current_theme = "dark";
                  }
                } else {
                  current_theme = m;
                }

                if (current_theme === "dark") {
                  d.setAttribute("data-theme", "dark");
                  d.style.colorScheme = "dark";
                } else if (current_theme === "light") {
                  d.setAttribute("data-theme", "light");
                  d.style.colorScheme = "light";
                }
                // If m === 'system', 'auto', or null, leave attribute unset → CSS follows OS prefers-color-scheme
              } catch {}
            </script>
            """));
  }

  private String themeWebPath(String themeName, String suffix) {
    return "/" + THEME_BASE_PATH + themeName + suffix;
  }

  private void addThemeStylesheets(HTMLNode headNode, ToadletContext ctx) {
    if (override != null) {
      headNode.addChild(getOverrideContent());
      return;
    }

    headNode.addChild(
        TAG_LINK,
        new String[] {"rel", ATTR_HREF, ATTR_TYPE, ATTR_TITLE},
        new String[] {
          STYLESHEET, themeWebPath(theme.code, THEME_STYLESHEET), MIME_TEXT_CSS, theme.code
        });

    if (sendAllThemes(ctx)) {
      for (THEME t : THEME.values()) {
        String themeName = t.code;
        headNode.addChild(
            TAG_LINK,
            new String[] {"rel", ATTR_HREF, ATTR_TYPE, "media", ATTR_TITLE},
            new String[] {
              "alternate stylesheet",
              themeWebPath(themeName, THEME_STYLESHEET),
              MIME_TEXT_CSS,
              "screen",
              themeName
            });
      }
    }
  }

  private void addThemeScripts(HTMLNode headNode, ToadletContext ctx) {
    if (!isJavascriptEnabled(ctx)) {
      return;
    }
    URL themeJsUrl = getClass().getResource("staticfiles/themes/" + theme.code + THEME_SCRIPT);
    if (themeJsUrl != null) {
      headNode.addChild(
          TAG_SCRIPT,
          new String[] {ATTR_TYPE, ATTR_LANGUAGE, "src"},
          new String[] {MIME_TEXT_JAVASCRIPT, JAVASCRIPT, themeWebPath(theme.code, THEME_SCRIPT)});
    }
  }

  private void addPushingScript(HTMLNode headNode, ToadletContext ctx) {
    if (!isWebPushingEnabled(ctx)) {
      return;
    }
    headNode.addChild(
        TAG_SCRIPT,
        new String[] {ATTR_TYPE, ATTR_LANGUAGE, "src"},
        new String[] {MIME_TEXT_JAVASCRIPT, JAVASCRIPT, "/static/freenetjs/freenetjs.nocache.js"});
  }

  private HTMLNode createBody(
      HTMLNode htmlNode,
      String title,
      ToadletContext ctx,
      RenderParameters renderParameters,
      boolean fullAccess,
      boolean webPushingEnabled,
      String activePath) {
    HTMLNode bodyNode =
        htmlNode.addChild(
            "body",
            new String[] {ATTR_CLASS, "id"},
            new String[] {"fproxy-page", filterCSSIdentifier("page-" + activePath)});
    addWebPushInputs(bodyNode, ctx, webPushingEnabled);
    HTMLNode pageDiv = bodyNode.addChild(TAG_DIV, "id", "page");
    HTMLNode topBarDiv = pageDiv.addChild(TAG_DIV, "id", "topbar");

    if (renderParameters.isRenderStatus() && fullAccess) {
      renderStatusBar(pageDiv, ctx, renderParameters);
    }

    topBarDiv.addChild("h1", title);
    renderNavigation(pageDiv, ctx, renderParameters, fullAccess, activePath);
    return pageDiv.addChild(TAG_DIV, "id", "content");
  }

  private void addWebPushInputs(HTMLNode bodyNode, ToadletContext ctx, boolean webPushingEnabled) {
    if (!webPushingEnabled) {
      return;
    }
    bodyNode.addChild(
        "input",
        new String[] {"type", "name", "value", "id"},
        new String[] {"hidden", "requestId", ctx.getUniqueId(), "requestId"});
    bodyNode
        .addChild(
            TAG_SCRIPT,
            new String[] {ATTR_TYPE, ATTR_LANGUAGE},
            new String[] {MIME_TEXT_JAVASCRIPT, JAVASCRIPT})
        .addChild("%", PushingTagReplacerCallback.getClientSideLocalizationScript());
  }

  private void renderStatusBar(
      HTMLNode pageDiv, ToadletContext ctx, RenderParameters renderParameters) {
    if (node == null || node.services().clientCore() == null) {
      return;
    }
    HTMLNode statusBarDiv =
        pageDiv.addChild(TAG_DIV, "id", "statusbar-container").addChild(TAG_DIV, "id", "statusbar");

    addAlerts(statusBarDiv, ctx);
    addLanguageSelector(statusBarDiv);
    addModeSwitch(statusBarDiv, ctx, renderParameters);
    addSecurityLevels(statusBarDiv);
    addPeerStatus(statusBarDiv);
  }

  private void addAlerts(HTMLNode statusBarDiv, ToadletContext ctx) {
    if (ctx == null) {
      return;
    }
    HTMLNode alerts = ctx.getAlertManager().createSummary(true);
    if (alerts != null) {
      statusBarDiv.addChild(alerts).addAttribute("id", "statusbar-alerts");
      addSeparator(statusBarDiv);
    }
  }

  private void addLanguageSelector(HTMLNode statusBarDiv) {
    statusBarDiv
        .addChild(TAG_DIV, "id", "statusbar-language")
        .addChild(
            TAG_A, "href", "/config/node#l10n", NodeL10n.getBase().getSelectedLanguage().fullName);
  }

  private void addModeSwitch(
      HTMLNode statusBarDiv, ToadletContext ctx, RenderParameters renderParameters) {
    if (node.services().clientCore() == null
        || ctx == null
        || !renderParameters.isRenderModeSwitch()) {
      return;
    }
    boolean isAdvancedMode = ctx.isAdvancedModeEnabled();
    String uri = ctx.getUri().getQuery();
    Map<String, List<String>> parameters = HTTPRequestImpl.parseUriParameters(uri, true);
    List<String> newModeSwitchValues = new ArrayList<>();
    newModeSwitchValues.add(String.valueOf(isAdvancedMode ? MODE_SIMPLE : MODE_ADVANCED));
    parameters.put(MODE_SWITCH_PARAMETER, newModeSwitchValues);

    addSeparator(statusBarDiv);
    HTMLNode switchMode = statusBarDiv.addChild(TAG_DIV, "id", "statusbar-switchmode");
    switchMode.addAttribute(ATTR_CLASS, isAdvancedMode ? "simple" : "advanced");
    switchMode.addChild(
        TAG_A,
        new String[] {"href"},
        new String[] {"?" + HTTPRequestImpl.createQueryString(parameters, false)},
        isAdvancedMode
            ? NodeL10n.getBase().getString("StatusBar.switchToSimpleMode")
            : NodeL10n.getBase().getString("StatusBar.switchToAdvancedMode"));
  }

  private void addSecurityLevels(HTMLNode statusBarDiv) {
    addSeparator(statusBarDiv);
    HTMLNode secLevels =
        statusBarDiv.addChild(
            TAG_DIV,
            "id",
            "statusbar-seclevels",
            NodeL10n.getBase().getString("SecurityLevels.statusBarPrefix"));

    HTMLNode network =
        secLevels.addChild(
            TAG_A,
            "href",
            "/seclevels/",
            SecurityLevels.localisedName(node.services().securityLevels().getNetworkThreatLevel())
                + "\u00a0");
    network.addAttribute(
        ATTR_TITLE, NodeL10n.getBase().getString("SecurityLevels.networkThreatLevelShort"));
    network.addAttribute(
        ATTR_CLASS,
        node.services().securityLevels().getNetworkThreatLevel().toString().toLowerCase());

    HTMLNode physical =
        secLevels.addChild(
            TAG_A,
            "href",
            "/seclevels/",
            SecurityLevels.localisedName(
                node.services().securityLevels().getPhysicalThreatLevel()));
    physical.addAttribute(
        ATTR_TITLE, NodeL10n.getBase().getString("SecurityLevels.physicalThreatLevelShort"));
    physical.addAttribute(
        ATTR_CLASS,
        node.services().securityLevels().getPhysicalThreatLevel().toString().toLowerCase());
  }

  private void addPeerStatus(HTMLNode statusBarDiv) {
    addSeparator(statusBarDiv);
    int connectedPeers = node.network().peers().countConnectedPeers();
    int darknetTotal = countEnabledDarknetPeers();
    int connectedDarknetPeers = node.network().peers().countConnectedDarknetPeers();
    int totalPeers =
        node.network().opennet() == null
            ? determineDarknetTotal(darknetTotal)
            : node.network().opennet().getNumberOfConnectedPeersToAimIncludingDarknet();
    double connectedRatio = ((double) connectedPeers) / (double) totalPeers;
    String additionalClass =
        classifyPeerStatus(connectedPeers, connectedDarknetPeers, connectedRatio);

    HTMLNode progressBar = statusBarDiv.addChild(TAG_DIV, ATTR_CLASS, "progressbar");
    progressBar.addChild(
        TAG_DIV,
        new String[] {ATTR_CLASS, "style"},
        new String[] {
          "progressbar-done progressbar-peers " + additionalClass,
          "width: " + Math.min(100, Math.floor(100 * connectedRatio)) + "%;"
        });

    progressBar.addChild(
        TAG_DIV,
        new String[] {ATTR_CLASS, ATTR_TITLE},
        new String[] {
          "progress_fraction_finalized",
          NodeL10n.getBase()
              .getString(
                  "StatusBar.connectedPeers",
                  new String[] {"X", "Y"},
                  new String[] {
                    Integer.toString(node.network().peers().countConnectedDarknetPeers()),
                    Integer.toString(node.network().peers().countConnectedOpennetPeers())
                  })
        },
        connectedPeers + ((totalPeers != Integer.MAX_VALUE) ? " / " + totalPeers : ""));
  }

  private String classifyPeerStatus(
      int connectedPeers, int connectedDarknetPeers, double connectedRatio) {
    if (connectedPeers > connectedDarknetPeers) {
      if (connectedRatio < 0.3D || connectedPeers < 3) {
        return "very-few-peers";
      }
      if (connectedRatio < 0.5D) {
        return "few-peers";
      }
      if (connectedRatio < 0.75D) {
        return "avg-peers";
      }
      return "full-peers";
    }

    if (connectedDarknetPeers < 3) {
      return "very-few-peers";
    }
    if (connectedDarknetPeers < 5) {
      return "few-peers";
    }
    if (connectedDarknetPeers < 10) {
      return "avg-peers";
    }
    return "full-peers";
  }

  private int determineDarknetTotal(int darknetTotal) {
    return darknetTotal > 0 ? darknetTotal : Integer.MAX_VALUE;
  }

  private int countEnabledDarknetPeers() {
    int darknetTotal = 0;
    for (DarknetPeerNode peer : node.network().peers().roster().getDarknetPeers()) {
      if (peer != null && !peer.isDisabled()) {
        darknetTotal++;
      }
    }
    return darknetTotal;
  }

  private void addSeparator(HTMLNode statusBarDiv) {
    statusBarDiv.addChild(TAG_DIV, ATTR_CLASS, "separator", "\u00a0");
  }

  private void renderNavigation(
      HTMLNode pageDiv,
      ToadletContext ctx,
      RenderParameters renderParameters,
      boolean fullAccess,
      String activePath) {
    if (!renderParameters.isRenderNavigationLinks() || ctx == null) {
      return;
    }
    HTMLNode navbarDiv = pageDiv.addChild(TAG_DIV, "id", "navbar");
    HTMLNode navbarUl = navbarDiv.addChild(TAG_UL, "id", "navlist");

    SubMenu selected = renderMenus(navbarUl, ctx, fullAccess, activePath);
    renderSelectedSubmenu(pageDiv, ctx, fullAccess, activePath, selected);
  }

  private SubMenu renderMenus(
      HTMLNode navbarUl, ToadletContext ctx, boolean fullAccess, String activePath) {
    SubMenu selected = null;
    synchronized (this) {
      for (SubMenu menu : menuList) {
        boolean isSelected = renderMenu(navbarUl, ctx, fullAccess, activePath, menu);
        if (isSelected) {
          selected = menu;
        }
      }
    }
    return selected;
  }

  private boolean renderMenu(
      HTMLNode navbarUl, ToadletContext ctx, boolean fullAccess, String activePath, SubMenu menu) {
    HTMLNode subnavlist = new HTMLNode(TAG_UL);
    boolean isSelected = false;
    boolean nonEmpty = false;
    for (String navigationLink :
        fullAccess ? menu.navigationLinkTexts : menu.navigationLinkTextsNonFull) {
      LinkEnabledCallback cb = menu.navigationLinkCallbacks.get(navigationLink);
      if (cb != null && !cb.isEnabled(ctx)) {
        continue;
      }
      nonEmpty = true;
      isSelected = renderNavigationItem(subnavlist, activePath, navigationLink, menu) || isSelected;
    }
    if (nonEmpty) {
      HTMLNode listItem = createMenuListItem(menu, subnavlist, isSelected);
      navbarUl.addChild(listItem);
    }
    return isSelected;
  }

  private boolean renderNavigationItem(
      HTMLNode subnavlist, String activePath, String navigationLink, SubMenu menu) {
    String navigationTitle = menu.navigationLinkTitles.get(navigationLink);
    String navigationPath = menu.navigationLinks.get(navigationLink);
    HTMLNode sublistItem;
    boolean isSelected;
    if (activePath.equals(navigationPath)) {
      sublistItem = subnavlist.addChild(TAG_LI, ATTR_CLASS, "submenuitem-selected");
      isSelected = true;
    } else {
      sublistItem = subnavlist.addChild(TAG_LI, ATTR_CLASS, "submenuitem-not-selected");
      isSelected = false;
    }

    FredPluginL10n l10n = menu.navigationLinkL10n.getOrDefault(navigationLink, menu.plugin);
    NavigationText navigationText =
        localiseNavigationEntries(navigationTitle, navigationLink, l10n);

    String cssIdKey =
        navigationText.titleLocalizationKey() != null
            ? navigationText.titleLocalizationKey()
            : navigationLink;
    if (cssIdKey != null) {
      if (l10n != null) {
        sublistItem.addAttribute("id", getPluginL10nCSSIdentifier(l10n, cssIdKey));
      } else {
        sublistItem.addAttribute("id", filterCSSIdentifier(cssIdKey));
      }
    }
    addNavigationLink(sublistItem, navigationPath, navigationText);
    return isSelected;
  }

  private NavigationText localiseNavigationEntries(
      String navigationTitle, String navigationLink, FredPluginL10n l10n) {
    String localizedTitle =
        l10n != null
            ? getOptionalString(l10n, navigationTitle)
            : getOptionalString(NodeL10n.getBase(), navigationTitle);
    String localizedLink =
        l10n != null
            ? getOptionalString(l10n, navigationLink)
            : getOptionalString(NodeL10n.getBase(), navigationLink);
    return new NavigationText(
        navigationTitle, localizedTitle, localizedLink == null ? navigationLink : localizedLink);
  }

  private String getOptionalString(FredPluginL10n l10n, String key) {
    if (key == null) {
      return null;
    }
    String result = l10n.getString(key);
    if (result == null) {
      LOG.error("Navigation l10n returned null for getString(key); plugin={}", l10n);
    }
    return result;
  }

  private String getOptionalString(BaseL10n l10n, String key) {
    if (key == null) {
      return null;
    }
    return l10n.getString(key);
  }

  private void addNavigationLink(HTMLNode sublistItem, String navigationPath, NavigationText text) {
    if (text.localizedTitle() != null) {
      sublistItem.addChild(
          TAG_A,
          new String[] {"href", ATTR_TITLE},
          new String[] {navigationPath, text.localizedTitle()},
          text.localizedLink());
    } else {
      sublistItem.addChild(TAG_A, "href", navigationPath, text.localizedLink());
    }
  }

  private HTMLNode createMenuListItem(SubMenu menu, HTMLNode subnavlist, boolean isSelected) {
    HTMLNode listItem;
    if (isSelected) {
      subnavlist.addAttribute(ATTR_CLASS, "subnavlist-selected");
      listItem = new HTMLNode(TAG_LI, ATTR_CLASS, "navlist-selected");
    } else {
      subnavlist.addAttribute(ATTR_CLASS, "subnavlist");
      listItem = new HTMLNode(TAG_LI, ATTR_CLASS, "navlist-not-selected");
    }
    String menuItemTitle = menu.defaultNavigationLinkTitle;
    String text = menu.navigationLinkText;
    if (menu.plugin == null) {
      listItem.addAttribute("id", filterCSSIdentifier(menuItemTitle));
      menuItemTitle = NodeL10n.getBase().getString(menuItemTitle);
      text = NodeL10n.getBase().getString(text);
    } else {
      listItem.addAttribute("id", getPluginL10nCSSIdentifier(menu.plugin, text));
      menuItemTitle = replaceNullWithLocalization(menu.plugin, menuItemTitle);
      text = replaceNullWithLocalization(menu.plugin, text);
    }

    listItem.addChild(
        TAG_A,
        new String[] {"href", ATTR_TITLE},
        new String[] {menu.defaultNavigationLink, menuItemTitle},
        text);
    listItem.addChild(subnavlist);
    return listItem;
  }

  private String replaceNullWithLocalization(FredPluginL10n plugin, String key) {
    String localized = plugin.getString(key);
    if (localized == null) {
      LOG.error("Menu label l10n returned null for getString(key); plugin={}", plugin);
      return key;
    }
    return localized;
  }

  private void renderSelectedSubmenu(
      HTMLNode pageDiv,
      ToadletContext ctx,
      boolean fullAccess,
      String activePath,
      SubMenu selected) {
    if (selected == null) {
      return;
    }
    HTMLNode div = new HTMLNode(TAG_DIV, "id", "selected-subnavbar");
    HTMLNode subnavlist = div.addChild(TAG_UL, "id", "selected-subnavbar-list");
    boolean nonEmpty = false;
    for (String navigationLink :
        fullAccess ? selected.navigationLinkTexts : selected.navigationLinkTextsNonFull) {
      boolean rendered =
          renderSelectedSubmenuItem(ctx, activePath, navigationLink, selected, subnavlist);
      nonEmpty = nonEmpty || rendered;
    }
    if (nonEmpty) {
      pageDiv.addChild(div);
    }
  }

  private boolean renderSelectedSubmenuItem(
      ToadletContext ctx,
      String activePath,
      String navigationLink,
      SubMenu selected,
      HTMLNode subnavlist) {
    LinkEnabledCallback cb = selected.navigationLinkCallbacks.get(navigationLink);
    if (cb != null && ctx != null && !cb.isEnabled(ctx)) {
      return false;
    }
    String navigationTitle = selected.navigationLinkTitles.get(navigationLink);
    String navigationPath = selected.navigationLinks.get(navigationLink);
    HTMLNode sublistItem =
        subnavlist.addChild(
            TAG_LI,
            ATTR_CLASS,
            activePath.equals(navigationPath)
                ? "submenuitem-selected"
                : "submenuitem-not-selected");

    FredPluginL10n l10n = selected.navigationLinkL10n.getOrDefault(navigationLink, selected.plugin);
    String localizedTitle =
        l10n != null
            ? getOptionalString(l10n, navigationTitle)
            : getOptionalString(NodeL10n.getBase(), navigationTitle);
    String localizedLink =
        l10n != null
            ? getOptionalString(l10n, navigationLink)
            : getOptionalString(NodeL10n.getBase(), navigationLink);

    addNavigationLink(
        sublistItem,
        navigationPath,
        new NavigationText(
            navigationTitle,
            localizedTitle,
            localizedLink == null ? navigationLink : localizedLink));
    return true;
  }

  private boolean isJavascriptEnabled(ToadletContext ctx) {
    return ctx != null && ctx.getContainer().isFProxyJavascriptEnabled();
  }

  private boolean isWebPushingEnabled(ToadletContext ctx) {
    return ctx != null
        && ctx.getContainer().isFProxyJavascriptEnabled()
        && ctx.getContainer().isFProxyWebPushingEnabled();
  }

  private boolean sendAllThemes(ToadletContext ctx) {
    return ctx != null && ctx.getContainer().sendAllThemes();
  }

  private String resolveActivePath(ToadletContext ctx) {
    if (ctx == null) {
      return "";
    }
    Toadlet t = ctx.activeToadlet();
    if (t != null) {
      t = t.showAsToadlet(ctx);
    }
    return t != null ? t.path() : "";
  }

  /**
   * Returns the theme currently applied when rendering page heads.
   *
   * @return active theme, never {@code null}
   */
  public THEME getTheme() {
    return this.theme;
  }

  /**
   * Selects the theme used for further render operations.
   *
   * <p>Unknown or {@code null} themes fall back to {@link THEME#getDefault()}. The method validates
   * that corresponding assets exist before accepting a theme to avoid broken references in
   * generated pages.
   *
   * @param theme2 desired theme; {@code null} or missing assets lead to the default theme
   */
  public void setTheme(THEME theme2) {
    if (theme2 == null) {
      this.theme = THEME.getDefault();
    } else {
      URL themeurl = getClass().getResource("staticfiles/themes/" + theme2.code + THEME_STYLESHEET);
      if (themeurl == null) {
        this.theme = THEME.getDefault();
      } else {
        this.theme = theme2;
      }
    }
  }

  /**
   * Creates a standard infobox using a plain-text header.
   *
   * <p>This is a convenience overload for callers that do not need custom header markup. The box
   * uses the default styling and is not marked unique. Content can be appended through the returned
   * {@link InfoboxNode}.
   *
   * @param header text displayed in the infobox header; must not be {@code null}
   * @return wrapper exposing both outer and content nodes for further composition
   */
  public InfoboxNode getInfobox(String header) {
    return getInfobox(header, null, false);
  }

  /**
   * Creates a standard infobox using a pre-built header node.
   *
   * <p>Use this overload when the header needs inline formatting or localization markup. The box is
   * styled with default classes and is not marked as unique.
   *
   * @param header HTML fragment to place in the header area; must not be {@code null}
   * @return wrapper exposing both outer and content nodes for further composition
   */
  public InfoboxNode getInfobox(HTMLNode header) {
    return getInfobox(header, null, false);
  }

  /**
   * Creates an infobox with an additional category class and plain-text header.
   *
   * <p>The {@code category} value is appended to the {@code infobox} CSS class, enabling targeted
   * styling. The box is not marked unique and uses the provided text header.
   *
   * @param category optional CSS category appended to the infobox class list; may be {@code null}
   * @param header text shown in the header area; must not be {@code null}
   * @return infobox wrapper ready to receive content
   */
  public InfoboxNode getInfobox(String category, String header) {
    return getInfobox(category, header, null, false);
  }

  /**
   * Creates and appends an infobox to a parent node, returning the content container.
   *
   * <p>This overload is useful when callers only need to fill the content area directly. The box is
   * styled with an optional category class and uses a plain-text header.
   *
   * @param category optional CSS category appended to the infobox class list; may be {@code null}
   * @param header text displayed in the infobox header; must not be {@code null}
   * @param parent parent node the infobox is appended to; must not be {@code null}
   * @return the inner content node to which callers can add body elements
   */
  public HTMLNode getInfobox(String category, String header, HTMLNode parent) {
    return getInfobox(category, header, parent, null, false);
  }

  /**
   * Creates an infobox with an optional category and rich header node.
   *
   * <p>Choose this overload when the header requires markup while still attaching a category class
   * for styling purposes. The box is not marked as unique.
   *
   * @param category optional CSS category appended to the infobox class list; may be {@code null}
   * @param header header node to render inside the infobox; must not be {@code null}
   * @return infobox wrapper ready to receive content
   */
  public InfoboxNode getInfobox(String category, HTMLNode header) {
    return getInfobox(category, header, null, false);
  }

  /**
   * Builds an infobox with a text header, optional CSS title, and uniqueness flag.
   *
   * <p>When {@code isUnique} is {@code true}, the {@code title} is used as the element id to aid
   * client-side manipulation. Otherwise, it is added as a CSS class. The box uses the default
   * infobox styling and no category-specific classes.
   *
   * @param header text displayed in the header area; must not be {@code null}
   * @param title optional identifier used as a CSS class or id depending on {@code isUnique}
   * @param isUnique {@code true} to use {@code title} as an element id; {@code false} to add it as
   *     a class name
   * @return infobox wrapper exposing both outer and content nodes
   */
  public InfoboxNode getInfobox(String header, String title, boolean isUnique) {
    if (header == null) {
      throw new NullPointerException();
    }
    return getInfobox(new HTMLNode("#", header), title, isUnique);
  }

  /**
   * Builds an infobox with a rich header node, optional title marker, and uniqueness flag.
   *
   * <p>Titles become CSS classes by default, or element ids when {@code isUnique} is {@code true}.
   * Categories can be added by using the broader overload.
   *
   * @param header header node to render inside the infobox; must not be {@code null}
   * @param title optional identifier used as a CSS class or id depending on {@code isUnique}
   * @param isUnique {@code true} to use {@code title} as an element id; {@code false} to add it as
   *     a class name
   * @return infobox wrapper exposing both outer and content nodes
   */
  public InfoboxNode getInfobox(HTMLNode header, String title, boolean isUnique) {
    if (header == null) {
      throw new NullPointerException();
    }
    return getInfobox(null, header, title, isUnique);
  }

  /**
   * Builds an infobox with optional category styling, text header, and identifier semantics.
   *
   * <p>The header is wrapped as text, the category augments CSS classes, and the title is either an
   * id (when {@code isUnique}) or an additional class. The constructed box is returned as an {@link
   * InfoboxNode} for easy content population.
   *
   * @param category optional CSS category appended to the infobox class list; may be {@code null}
   * @param header text displayed in the header area; must not be {@code null}
   * @param title optional identifier used as a CSS class or id depending on {@code isUnique}
   * @param isUnique {@code true} to use {@code title} as an element id; {@code false} to add it as
   *     a class name
   * @return infobox wrapper exposing both outer and content nodes
   */
  public InfoboxNode getInfobox(String category, String header, String title, boolean isUnique) {
    if (header == null) {
      throw new NullPointerException();
    }
    return getInfobox(category, new HTMLNode("#", header), title, isUnique);
  }

  /**
   * Creates an infobox, attaches it to a parent, and returns the content container.
   *
   * <p>This helper is ideal when the caller wants to stream content directly into the created box
   * without keeping the wrapper object. Category and title are applied as described in the other
   * overloads, and uniqueness controls whether the title becomes an id.
   *
   * @param category optional CSS category appended to the infobox class list; may be {@code null}
   * @param header text displayed in the header area; must not be {@code null}
   * @param parent parent node receiving the new infobox; must not be {@code null}
   * @param title optional identifier used as a CSS class or id depending on {@code isUnique}
   * @param isUnique {@code true} to use {@code title} as an element id; {@code false} to add it as
   *     a class name
   * @return the inner content node suitable for appending arbitrary HTML nodes
   */
  public HTMLNode getInfobox(
      String category, String header, HTMLNode parent, String title, boolean isUnique) {
    InfoboxNode infoboxNode = getInfobox(category, header, title, isUnique);
    parent.addChild(infoboxNode.getOuterNode());
    return infoboxNode.getContentNode();
  }

  /**
   * Returns an infobox with optional category styling, rich header node, and identifier semantics.
   *
   * <p>The category augments the CSS class list, while {@code title} is applied as either a class
   * name or id depending on {@code isUnique}. The method never mutates the supplied header node and
   * throws early if the header is missing to avoid silent rendering failures.
   *
   * @param category optional CSS category appended to the infobox class list; may be {@code null}
   * @param header header node to render inside the infobox; must not be {@code null}
   * @param title optional identifier used as a CSS class or id depending on {@code isUnique}
   * @param isUnique {@code true} to use {@code title} as an element id; {@code false} to add it as
   *     a class name
   * @return infobox wrapper exposing both outer and content nodes
   */
  public InfoboxNode getInfobox(String category, HTMLNode header, String title, boolean isUnique) {
    if (header == null) {
      throw new NullPointerException();
    }

    StringBuilder classes = new StringBuilder("infobox");
    if (category != null) {
      classes.append(" ");
      classes.append(category);
    }
    if (title != null && !isUnique) {
      classes.append(" ");
      classes.append(title);
    }

    HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, classes.toString());

    if (title != null && isUnique) {
      infobox.addAttribute("id", title);
    }

    infobox.addChild("div", ATTR_CLASS, "infobox-header").addChild(header);
    return new InfoboxNode(infobox, infobox.addChild("div", ATTR_CLASS, "infobox-content"));
  }

  /**
   * Determines whether the current request should render in advanced mode.
   *
   * <p>The method inspects the {@code fproxyAdvancedMode} parameter when present, updates the
   * container’s advanced-mode flag accordingly, and returns the resulting state. It gracefully
   * defaults to the container’s existing preference when the parameter is absent or unparsable.
   *
   * @param req HTTP request whose parameters may toggle advanced mode
   * @param container the owning container that stores the persistent advanced-mode preference
   * @return {@code true} when advanced mode is enabled after processing the request
   */
  public boolean advancedMode(HTTPRequest req, ToadletContainer container) {
    return parseMode(req, container) >= MODE_ADVANCED;
  }

  /**
   * Parses and persists the mode switch parameter from the current request.
   *
   * <p>The method reads the {@value #MODE_SWITCH_PARAMETER} integer parameter, falls back to the
   * container’s current preference when absent, and updates the container accordingly. Returning
   * the resolved mode allows callers to gate additional logic without re-querying the container.
   * Invocations should precede navigation rendering so menu visibility reflects the latest user
   * selection.
   *
   * @param req HTTP request whose parameters may specify the desired mode
   * @param container holder of the persisted advanced-mode state; never {@code null}
   * @return {@link #MODE_ADVANCED} or {@link #MODE_SIMPLE} depending on the resolved request state
   */
  public int parseMode(HTTPRequest req, ToadletContainer container) {
    int mode = container.isAdvancedModeEnabled() ? MODE_ADVANCED : MODE_SIMPLE;

    if (req.isParameterSet(MODE_SWITCH_PARAMETER)) {
      mode = req.getIntParam(MODE_SWITCH_PARAMETER, mode);
      container.setAdvancedMode(mode == MODE_ADVANCED);
    }

    return mode;
  }

  void setOverride(String pointTo) {
    this.override = pointTo;
  }

  private HTMLNode getOverrideContent() {
    return new HTMLNode(
        "link",
        new String[] {"rel", ATTR_HREF, ATTR_TYPE, "media", ATTR_TITLE},
        new String[] {STYLESHEET, override, MIME_TEXT_CSS, "screen", "custom"});
  }

  /**
   * Immutable bundle of flags controlling which chrome elements are rendered into a page.
   *
   * <p>Instances are inexpensive value objects; mutator-style methods return new instances rather
   * than altering state. Defaults enable all optional elements, so callers start from the fully
   * featured view before selectively disabling navigation, status, or the mode switch.
   *
   * @param renderNavigationLinks {@code true} to include the navigation bar
   * @param renderStatus {@code true} to include the status bar with alerts, language selector, and
   *     peer info
   * @param renderModeSwitch {@code true} to include the advanced/simple toggle when eligible
   * @see PageMaker#getPageNode(String, ToadletContext, RenderParameters)
   */
  public record RenderParameters(
      boolean renderNavigationLinks, boolean renderStatus, boolean renderModeSwitch) {

    /**
     * Creates default render parameters that include all optional elements.
     *
     * <p>Use this constructor when you want the standard FProxy chrome and intend to tweak only a
     * subset of features on a per-request basis.
     */
    public RenderParameters() {
      this(true, true, true);
    }

    /**
     * Indicates whether the navigation links should be rendered into the page.
     *
     * @return {@code true} when navigation links are to be shown alongside page content
     */
    public boolean isRenderNavigationLinks() {
      return renderNavigationLinks;
    }

    /**
     * Returns a new instance with the navigation rendering flag updated.
     *
     * <p>Other flags are preserved, enabling fluent configuration chains.
     *
     * @param renderNavigationLinks {@code true} to render the navigation links, {@code false}
     *     otherwise
     * @return new {@link RenderParameters} reflecting the requested navigation visibility
     */
    public RenderParameters renderNavigationLinks(boolean renderNavigationLinks) {
      return new RenderParameters(renderNavigationLinks, renderStatus, renderModeSwitch);
    }

    /**
     * Indicates whether the status bar should be rendered into the page.
     *
     * @return {@code true} when the status bar should appear below the top bar
     */
    public boolean isRenderStatus() {
      return renderStatus;
    }

    /**
     * Returns a new instance with the status bar flag updated.
     *
     * <p>Other flags remain unchanged, allowing targeted adjustments.
     *
     * @param renderStatus {@code true} to render the status bar, {@code false} otherwise
     * @return new {@link RenderParameters} reflecting the requested status visibility
     */
    public RenderParameters renderStatus(boolean renderStatus) {
      return new RenderParameters(renderNavigationLinks, renderStatus, renderModeSwitch);
    }

    /**
     * Indicates whether the advanced/simple mode switch should be rendered.
     *
     * @return {@code true} when the toggle should be shown, typically in the status bar
     */
    public boolean isRenderModeSwitch() {
      return renderModeSwitch;
    }

    /**
     * Returns a new instance with the mode-switch flag updated.
     *
     * <p>Use this to suppress the toggle for embedded pages that inherit mode from the surrounding
     * UI.
     *
     * @param renderModeSwitch {@code true} to render the mode switch, {@code false} otherwise
     * @return new {@link RenderParameters} reflecting the requested toggle visibility
     */
    public RenderParameters renderModeSwitch(boolean renderModeSwitch) {
      return new RenderParameters(renderNavigationLinks, renderStatus, renderModeSwitch);
    }
  }

  private record NavigationText(
      String titleLocalizationKey, String localizedTitle, String localizedLink) {}

  private static class SubMenu {

    public SubMenu(String link, String name, String title, FredPluginL10n plugin) {
      this.navigationLinkText = name;
      this.defaultNavigationLink = link;
      this.defaultNavigationLinkTitle = title;
      this.plugin = plugin;
    }

    public void addNavigationLink(
        String path,
        String name,
        String title,
        boolean fullOnly,
        LinkEnabledCallback cb,
        FredPluginL10n l10n) {
      navigationLinkTexts.add(name);
      if (!fullOnly) {
        navigationLinkTextsNonFull.add(name);
      }
      navigationLinkTitles.put(name, title);
      navigationLinks.put(name, path);
      if (cb != null) {
        navigationLinkCallbacks.put(name, cb);
      }
      if (l10n != null) {
        navigationLinkL10n.put(name, l10n);
      }
    }

    /** Remove a link from this submenu. */
    public void removeNavigationLink(String name) {
      navigationLinkTexts.remove(name);
      navigationLinkTextsNonFull.remove(name);
      navigationLinkTitles.remove(name);
      navigationLinks.remove(name);
      navigationLinkL10n.remove(
          name); // Should this be here? If so, why not remove from navigationLinkCallbacks either
    }

    /** Name of the submenu */
    private final String navigationLinkText;

    /** Link if the user clicks on the submenu itself */
    private final String defaultNavigationLink;

    /** Tooltip */
    private final String defaultNavigationLinkTitle;

    private final FredPluginL10n plugin;
    private final List<String> navigationLinkTexts = new ArrayList<>();
    private final List<String> navigationLinkTextsNonFull = new ArrayList<>();
    private final Map<String, String> navigationLinkTitles = new HashMap<>();
    private final Map<String, String> navigationLinks = new HashMap<>();
    private final Map<String, LinkEnabledCallback> navigationLinkCallbacks = new HashMap<>();
    private final Map<String, FredPluginL10n> navigationLinkL10n = new HashMap<>();
  }

  /** Parameter for simple/advanced mode switch. */
  private static final String MODE_SWITCH_PARAMETER = "fproxyAdvancedMode";

  private final Node node;
  private final List<SubMenu> menuList = new ArrayList<>();
  private final Map<String, SubMenu> subMenus = new HashMap<>();
  private THEME theme;
  private String override;
}
