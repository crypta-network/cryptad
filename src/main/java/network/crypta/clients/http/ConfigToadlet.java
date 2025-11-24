package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.Config;
import network.crypta.config.ConfigCallback;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.config.WrapperConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.FredPluginConfigurable;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Node Configuration Toadlet. Accessible from http://...<code>/config/</code>.
 *
 * <p>This toadlet renders and processes the node and plugin configuration UI that lives under the
 * {@code /config/<subconfig>} path. It translates {@link Option} metadata into HTML controls,
 * handles form submissions, persists updates to {@link Config}, and surfaces restart requirements
 * through both inline notices and {@link UserAlert} instances. The handler also wires the optional
 * directory chooser loop so users can browse for filesystem paths without manually editing text
 * fields.
 *
 * <p>Typical call flow is a GET request to display grouped options followed by a POST that either
 * applies changes, redirects to the directory selector, or confirms a reset to defaults. The class
 * is stateful only for per-request restart tracking, and instances are tied to a single {@link
 * SubConfig} (or plugin-provided equivalent). It is not thread-safe; callers rely on the
 * surrounding HTTP server to serialize handling per session. Inputs are trusted only after {@link
 * ToadletContext#checkFullAccess(Toadlet)} succeeds, so external callers must provide a properly
 * authorized context.
 *
 * <ul>
 *   <li>Renders localized labels and descriptions from {@link NodeL10n} and plugin resources.
 *   <li>Normalizes directory selection callbacks to maintain form state across redirects.
 *   <li>Surfaces wrapper JVM memory overrides when the node configuration prefix is {@code node}.
 * </ul>
 *
 * @see LocalFileBrowserToadlet
 * @see WrapperConfig
 */
public class ConfigToadlet extends Toadlet implements LinkEnabledCallback {
  private static final Logger LOG = LoggerFactory.getLogger(ConfigToadlet.class);
  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_TITLE = "title";
  private static final String ATTR_DISABLED = "disabled";
  private static final String VALUE_HIDDEN = "hidden";
  private static final String VALUE_SUBMIT = "submit";
  private static final String TAG_SELECT = "select";
  private static final String TAG_OPTION = "option";
  private static final String VALUE_SELECTED = "selected";
  private static final String VALUE_TRUE = "true";
  private static final String VALUE_FALSE = "false";
  private static final String CSS_CONFIG = "config";
  private static final String PARAM_SUBCONFIG = "subconfig";
  private static final String PARAM_CONFIRM_RESET = "confirm-reset-to-defaults";
  private static final String PARAM_DECLINE_DEFAULT_RESET = "decline-default-reset";
  private static final String PARAM_RESET_TO_DEFAULTS = "reset-to-defaults";
  private static final String PARAM_SELECT_FOR = "select-for";
  private static final String SELECT_DIRECTORY_PREFIX = "select-directory.";
  private static final String BROWSER_PATH_DEFAULT_SEGMENT = "unset-browser-path";
  private static final String WRAPPER_MAX_MEMORY = "wrapper.java.maxmemory";

  // If a setting has to be more than a meg, something is seriously wrong!
  private static final int MAX_PARAM_VALUE_SIZE = 1024 * 1024;
  private String directoryBrowserPath;
  private final SubConfig subConfig;
  private final Config config;
  private final NodeClientCore core;
  private final Node node;

  /** plugin is always null except when this ConfigToadlet serves a plugin */
  private final FredPluginConfigurable plugin;

  private boolean needRestart = false;
  private NeedRestartUserAlert needRestartUserAlert;

  /** Prompt for node restart */
  private class NeedRestartUserAlert extends AbstractUserAlert {
    private final String formPassword;

    public NeedRestartUserAlert(String formPassword) {
      this.formPassword = formPassword;
    }

    @Override
    public String getTitle() {
      return l10n("needRestartTitle");
    }

    @Override
    public String getText() {
      return getHTMLText().toString();
    }

    @Override
    public String getShortText() {
      return l10n("needRestartShort");
    }

    @Override
    public HTMLNode getHTMLText() {
      HTMLNode alertNode = new HTMLNode("div");
      alertNode.addChild("#", l10n("needRestart"));

      if (node.isUsingWrapper()) {
        alertNode.addChild("br");
        HTMLNode restartForm =
            alertNode
                .addChild(
                    "form",
                    new String[] {"action", "method", "enctype", "id", "accept-charset"},
                    new String[] {"/", "post", "multipart/form-data", "restartForm", "utf-8"})
                .addChild("div");
        restartForm.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {VALUE_HIDDEN, "formPassword", formPassword});
        restartForm.addChild("div");
        restartForm.addChild(
            TAG_INPUT, //
            new String[] {ATTR_TYPE, ATTR_NAME}, //
            new String[] {VALUE_HIDDEN, "restart"});
        restartForm.addChild(
            TAG_INPUT, //
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE}, //
            new String[] {VALUE_SUBMIT, "restart2", l10n("restartNode")});
      }

      return alertNode;
    }

    @Override
    public short getPriorityClass() {
      return UserAlert.WARNING;
    }

    @Override
    public boolean isValid() {
      return needRestart;
    }

    @Override
    public boolean userCanDismiss() {
      return false;
    }
  }

  /** Describes which UI element should be used to present an option. */
  private enum OptionType {
    /** A writable option with an enumerable list of possible values. */
    DROP_DOWN("dropdown"),
    /** A writable option which can be either true or false. */
    BOOLEAN("boolean"),
    /** A writable option which is a path to a directory. */
    DIRECTORY("directory"),
    /** A writable option set with a string of text. */
    TEXT("text"),
    /** A read-only option presented in a text field. */
    TEXT_READ_ONLY("text readonly");

    /** A CSS class descriptor for this option type. */
    public final String cssClass;

    OptionType(String cssClass) {
      this.cssClass = cssClass;
    }
  }

  /**
   * Creates a configuration toadlet bound to a specific subconfig and explicit directory browser
   * path.
   *
   * <p>The provided {@code directoryBrowserPath} is normalized to include leading and trailing
   * slashes so directory selection redirects remain stable. This constructor is typically used when
   * the caller controls where directory browsing should occur (for example, a plugin exposing its
   * own chooser endpoint) while still relying on the standard rendering and persistence logic.
   *
   * @param directoryBrowserPath path segment for directory browsing, with or without slashes; never
   *     {@code null} after normalization.
   * @param client HTTP client used for outbound helper requests initiated by the parent toadlet.
   * @param conf configuration root that persists option values once form submission succeeds.
   * @param subConfig logical configuration group that provides the options to render and update.
   * @param node running node instance required for restart checks and wrapper awareness.
   * @param core node client core used to locate directories such as the default downloads path.
   */
  public ConfigToadlet(
      String directoryBrowserPath,
      HighLevelSimpleClient client,
      Config conf,
      SubConfig subConfig,
      Node node,
      NodeClientCore core) {
    this(directoryBrowserPath, client, conf, subConfig, node, core, null);
  }

  /**
   * Creates a configuration toadlet with a default directory browser path when no plugin is
   * involved.
   *
   * <p>This overload is suited for core node configuration pages that do not need to override the
   * directory browsing endpoint. The path defaults to {@code /unset-browser-path/} until the caller
   * supplies a real location via the alternate constructor.
   *
   * @param client HTTP client used for outbound helper requests initiated by the parent toadlet.
   * @param conf configuration root that persists option values once form submission succeeds.
   * @param subConfig logical configuration group that provides the options to render and update.
   * @param node running node instance required for restart checks and wrapper awareness.
   * @param core node client core used to locate directories such as the default downloads path.
   */
  public ConfigToadlet(
      HighLevelSimpleClient client,
      Config conf,
      SubConfig subConfig,
      Node node,
      NodeClientCore core) {
    this(client, conf, subConfig, node, core, null);
  }

  /**
   * Creates a configuration toadlet bound to a plugin with a custom directory browser path.
   *
   * <p>Use this overload when a plugin contributes configurable options and wants directory
   * browsing to defer to a plugin-owned endpoint. The plugin is stored for later localization
   * lookups on option descriptions.
   *
   * @param directoryBrowserPath path segment for directory browsing, with or without slashes.
   * @param client HTTP client used for outbound helper requests initiated by the parent toadlet.
   * @param conf configuration root that persists option values once form submission succeeds.
   * @param subConfig logical configuration group that provides the options to render and update.
   * @param node running node instance required for restart checks and wrapper awareness.
   * @param core node client core used to locate directories such as the default downloads path.
   * @param plugin plugin contributing the configuration group; may be {@code null} when unused.
   */
  public ConfigToadlet(
      String directoryBrowserPath,
      HighLevelSimpleClient client,
      Config conf,
      SubConfig subConfig,
      Node node,
      NodeClientCore core,
      FredPluginConfigurable plugin) {
    this(client, conf, subConfig, node, core, plugin);
    this.directoryBrowserPath = normalizeDirectoryBrowserPath(directoryBrowserPath);
  }

  /**
   * Creates a configuration toadlet bound to the given configuration group, optionally for a
   * plugin.
   *
   * <p>This is the central constructor used by the other overloads. It normalizes the directory
   * browser path, remembers the owning plugin for localization lookups, and delegates rendering and
   * persistence to the shared helpers. Instances created here are ready to handle GET/POST cycles
   * immediately after construction.
   *
   * @param client HTTP client used for outbound helper requests initiated by the parent toadlet.
   * @param conf configuration root that persists option values once form submission succeeds.
   * @param subConfig logical configuration group that provides the options to render and update.
   * @param node running node instance required for restart checks and wrapper awareness.
   * @param core node client core used to locate directories such as the default downloads path.
   * @param plugin plugin contributing the configuration group; may be {@code null} when unused.
   */
  public ConfigToadlet(
      HighLevelSimpleClient client,
      Config conf,
      SubConfig subConfig,
      Node node,
      NodeClientCore core,
      FredPluginConfigurable plugin) {
    super(client);
    config = conf;
    this.core = core;
    this.node = node;
    this.subConfig = subConfig;
    this.plugin = plugin;
    this.directoryBrowserPath = normalizeDirectoryBrowserPath(null);
  }

  private static String normalizeDirectoryBrowserPath(String path) {
    String normalized = (path == null) ? BROWSER_PATH_DEFAULT_SEGMENT : path;
    if (!normalized.startsWith("/")) {
      normalized = '/' + normalized;
    }
    if (!normalized.endsWith("/")) {
      normalized = normalized + '/';
    }
    return normalized;
  }

  @SuppressWarnings("UnusedReturnValue")
  private static HTMLNode addInput(HTMLNode parent, String type, String name, String value) {
    return parent.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {type, name, value});
  }

  /**
   * Processes configuration submissions made via HTTP POST.
   *
   * <p>The handler validates access through {@link ToadletContext#checkFullAccess(Toadlet)}, routes
   * special cases such as reset confirmations or directory selection callbacks, and otherwise
   * applies option updates. When invoked after a directory chooser redirect, it forwards to the GET
   * handler to re-render the form with the chosen path. Errors encountered while setting option
   * values are aggregated and displayed to the user; restart requirements are tracked per-request.
   *
   * @param uri absolute request URI, used only for parity with the toadlet interface.
   * @param request HTTP request containing posted form parts for options or control actions; never
   *     {@code null}.
   * @param ctx toadlet context providing authorization, page rendering, and reply helpers; must
   *     already represent an authenticated session.
   * @throws ToadletContextClosedException if the client connection closes while writing the
   *     response.
   * @throws IOException if generating or sending the reply fails.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {

    if (!ctx.checkFullAccess(this)) return;

    if (request.isPartSet(PARAM_CONFIRM_RESET)) {
      renderConfirmResetPage(request, ctx);
      return;
    }

    if (isReturningFromDirectorySelector(request)) {
      handleMethodGET(uri, request, ctx);
      return;
    }

    if (redirectToDirectorySelector(request, ctx)) {
      return;
    }

    processConfigSubmission(request, ctx);
  }

  private boolean isReturningFromDirectorySelector(HTTPRequest request) {
    return request.isPartSet(LocalFileBrowserToadlet.SELECT_DIR)
        || request.isPartSet(PARAM_DECLINE_DEFAULT_RESET);
  }

  private void renderConfirmResetPage(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmResetTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                "infobox-warning", l10n("confirmResetTitle"), contentNode, "reset-confirm", true);
    content.addChild("#", l10n("confirmReset"));

    HTMLNode formNode = ctx.addFormChild(content, path(), "yes-button");
    String subconfig = request.getPartAsStringFailsafe(PARAM_SUBCONFIG, MAX_PARAM_VALUE_SIZE);
    addInput(formNode, VALUE_HIDDEN, PARAM_SUBCONFIG, subconfig);

    for (String part : request.getParts()) {
      if (part.startsWith(subconfig)) {
        addInput(
            formNode,
            VALUE_HIDDEN,
            part,
            request.getPartAsStringFailsafe(part, MAX_PARAM_VALUE_SIZE));
      }
    }

    addInput(
        formNode,
        VALUE_SUBMIT,
        PARAM_RESET_TO_DEFAULTS,
        NodeL10n.getBase().getString("Toadlet.yes"));
    addInput(
        formNode,
        VALUE_SUBMIT,
        PARAM_DECLINE_DEFAULT_RESET,
        NodeL10n.getBase().getString("Toadlet.no"));
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean redirectToDirectorySelector(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    boolean directorySelector = false;
    StringBuilder paramsBuilder = new StringBuilder("?");

    for (String key : request.getParts()) {
      String value = request.getPartAsStringFailsafe(key, MAX_PARAM_VALUE_SIZE);
      if (key.startsWith(SELECT_DIRECTORY_PREFIX)) {
        paramsBuilder
            .append(PARAM_SELECT_FOR)
            .append('=')
            .append(URLEncoder.encode(key.substring(SELECT_DIRECTORY_PREFIX.length()), true))
            .append('&');
        directorySelector = true;
      } else {
        paramsBuilder
            .append(URLEncoder.encode(key, true))
            .append('=')
            .append(URLEncoder.encode(value, true))
            .append('&');
      }
    }

    if (!directorySelector) {
      return false;
    }

    MultiValueTable<String, String> headers =
        MultiValueTable.from(
            "Location",
            directoryBrowserPath
                + paramsBuilder
                + "path="
                + core.getDownloadsDir().getAbsolutePath());
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
    return true;
  }

  private void processConfigSubmission(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    StringBuilder errbuf = new StringBuilder();

    String prefix = request.getPartAsStringFailsafe(PARAM_SUBCONFIG, MAX_PARAM_VALUE_SIZE);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Current config prefix is {}", prefix);
    }
    boolean resetToDefault = request.isPartSet(PARAM_RESET_TO_DEFAULTS);
    if (resetToDefault && LOG.isDebugEnabled()) {
      LOG.debug("Resetting to defaults");
    }

    applyOptionChanges(request, errbuf, prefix, resetToDefault);
    applyWrapperConfig(request);

    config.store();
    writeApplyResult(ctx, errbuf);
  }

  private void applyOptionChanges(
      HTTPRequest request, StringBuilder errbuf, String prefix, boolean resetToDefault) {
    for (Option<?> option : config.get(prefix).getOptions()) {
      String configName = option.getName();
      logCheckingOption(prefix, configName);

      if (!request.isPartSet(prefix + '.' + configName)) {
        continue;
      }

      String value =
          resetToDefault
              ? getDefaultValue(prefix, configName, option)
              : request.getPartAsStringFailsafe(prefix + '.' + configName, MAX_PARAM_VALUE_SIZE);

      if (option.getValueDisplayString().equals(value)) {
        logOptionNotChanged(prefix, configName);
      } else {
        setOptionValue(option, prefix, configName, value, errbuf);
      }
    }
  }

  private void setOptionValue(
      Option<?> option, String prefix, String configName, String value, StringBuilder errbuf) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Changing {}.{} to {}", prefix, configName, value);
    }

    try {
      option.setValue(value);
    } catch (InvalidConfigValueException e) {
      errbuf.append(option.getName()).append(' ').append(e.getMessage()).append('\n');
    } catch (NodeNeedRestartException e) {
      needRestart = true;
    } catch (Exception e) {
      errbuf.append(option.getName()).append(' ').append(e).append('\n');
      LOG.error("Caught {}", e, e);
    }
  }

  private void logOptionNotChanged(String prefix, String configName) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("{}.{} not changed", prefix, configName);
    }
  }

  private void logCheckingOption(String prefix, String configName) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Checking option {}.{}", prefix, configName);
    }
  }

  private String getDefaultValue(String prefix, String configName, Option<?> option) {
    if (prefix.equals("fproxy") && configName.equals("port")) {
      return option.getValueDisplayString();
    }
    return option.getDefault();
  }

  private void applyWrapperConfig(HTTPRequest request) {
    if (!request.isPartSet(WRAPPER_MAX_MEMORY)) {
      return;
    }

    String value = request.getPartAsStringFailsafe(WRAPPER_MAX_MEMORY, MAX_PARAM_VALUE_SIZE);
    if (!value.equals(WrapperConfig.getWrapperProperty(WRAPPER_MAX_MEMORY))) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Setting {} to {}", WRAPPER_MAX_MEMORY, value);
      }
      WrapperConfig.setWrapperProperty(WRAPPER_MAX_MEMORY, value);
    }
  }

  private void writeApplyResult(ToadletContext ctx, StringBuilder errbuf)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("appliedTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    if (errbuf.isEmpty()) {
      renderSuccessContent(ctx, contentNode);
    } else {
      HTMLNode content =
          ctx.getPageMaker()
              .getInfobox(
                  "infobox-error",
                  l10n("appliedFailureTitle"),
                  contentNode,
                  "configuration-error",
                  true)
              .addChild("div", ATTR_CLASS, "infobox-content");
      content.addChild("#", l10n("appliedFailureExceptions"));
      content.addChild("br");
      content.addChild("#", errbuf.toString());
    }

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                "infobox-normal",
                l10n("possibilitiesTitle"),
                contentNode,
                "configuration-possibilities",
                false);
    content.addChild(
        "a",
        new String[] {"href", ATTR_TITLE},
        new String[] {path(), l10n("shortTitle")},
        l10n("returnToNodeConfig"));
    content.addChild("br");
    addHomepageLink(content);

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void renderSuccessContent(ToadletContext ctx, HTMLNode contentNode) {
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                "infobox-success",
                l10n("appliedTitle"),
                contentNode,
                "configuration-applied",
                true);
    content.addChild("#", l10n("appliedSuccess"));

    if (!needRestart) {
      return;
    }

    content.addChild("br");
    content.addChild("#", l10n("needRestart"));

    if (node.isUsingWrapper()) {
      content.addChild("br");
      HTMLNode restartForm = ctx.addFormChild(content, "/", "restartForm");
      restartForm.addChild(
          TAG_INPUT, new String[] {ATTR_TYPE, ATTR_NAME}, new String[] {VALUE_HIDDEN, "restart"});
      restartForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {VALUE_SUBMIT, "restart2", l10n("restartNode")});
    }

    if (needRestartUserAlert == null) {
      needRestartUserAlert = new NeedRestartUserAlert(ctx.getFormPassword());
      ctx.getAlertManager().register(needRestartUserAlert);
    }
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("ConfigToadlet." + string);
  }

  /**
   * Renders the configuration UI for the current subconfig.
   *
   * <p>The response includes any active alerts, all eligible options (filtered by advanced mode and
   * plugin context), and helper controls such as wrapper memory tuning. If the request carries
   * directory selection results, the relevant option value is overridden before rendering so the
   * chosen path is visible immediately. The form posts back to the same path and preserves the
   * subconfig prefix as a hidden field.
   *
   * @param uri absolute request URI, passed for interface completeness.
   * @param req HTTP request used to detect advanced mode, pre-filled values, and directory chooser
   *     callbacks; never {@code null}.
   * @param ctx toadlet context responsible for authorization, localization, and HTML generation.
   * @throws ToadletContextClosedException if the client disconnects while the page is being sent.
   * @throws IOException if output generation or transmission fails.
   */
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {

    if (!ctx.checkFullAccess(this)) return;

    boolean advancedModeEnabled = ctx.isAdvancedModeEnabled();

    PageNode page =
        ctx.getPageMaker()
            .getPageNode(NodeL10n.getBase().getString("ConfigToadlet.fullTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    contentNode.addChild(ctx.getAlertManager().createSummary());

    HTMLNode formNode = buildConfigForm(ctx, contentNode);
    addWrapperMaxMemoryOption(req, formNode);

    SelectionOverride selectionOverride = determineSelectionOverride(req);
    HTMLNode configGroupUlNode = new HTMLNode("ul", ATTR_CLASS, CSS_CONFIG);

    short displayedConfigElements =
        addOptionGroups(req, configGroupUlNode, advancedModeEnabled, selectionOverride);

    if (displayedConfigElements > 0) {
      formNode.addChild(
          "div",
          ATTR_CLASS,
          "configprefix",
          (plugin == null) ? l10n(subConfig.getPrefix()) : plugin.getString(subConfig.getPrefix()));
      formNode.addChild("a", "id", subConfig.getPrefix());
      formNode.addChild(configGroupUlNode);
    }

    addFormButtons(formNode);

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private HTMLNode buildConfigForm(ToadletContext ctx, HTMLNode contentNode) {
    HTMLNode infobox = contentNode.addChild("div", ATTR_CLASS, "infobox infobox-normal");
    infobox.addChild("div", ATTR_CLASS, "infobox-header", l10n(ATTR_TITLE));
    HTMLNode configNode = infobox.addChild("div", ATTR_CLASS, "infobox-content");
    HTMLNode formNode = ctx.addFormChild(configNode, path(), "configForm");
    formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE, ATTR_CLASS},
        new String[] {VALUE_SUBMIT, l10n("apply"), "invisible"});
    return formNode;
  }

  private void addWrapperMaxMemoryOption(HTTPRequest req, HTMLNode formNode) {
    if (!subConfig.getPrefix().equals("node") || !WrapperConfig.canChangeProperties()) {
      return;
    }

    String curValue = WrapperConfig.getWrapperProperty(WRAPPER_MAX_MEMORY);
    if (req.isPartSet(WRAPPER_MAX_MEMORY)) {
      curValue = req.getPartAsStringFailsafe(WRAPPER_MAX_MEMORY, MAX_PARAM_VALUE_SIZE);
    }
    if (curValue == null) {
      return;
    }

    formNode.addChild("div", ATTR_CLASS, "configprefix", l10n("wrapper"));
    HTMLNode list = formNode.addChild("ul", ATTR_CLASS, CSS_CONFIG);
    HTMLNode item = list.addChild("li", ATTR_CLASS, OptionType.TEXT.cssClass);
    String defaultValue = curValue;
    item.addChild(
            "span",
            new String[] {ATTR_CLASS, ATTR_TITLE, "style"},
            new String[] {
              "configshortdesc",
              NodeL10n.getBase()
                  .getString(
                      "ConfigToadlet.defaultIs",
                      new String[] {"default"},
                      new String[] {defaultValue}),
              "cursor: help;"
            })
        .addChild(NodeL10n.getBase().getHTMLNode("WrapperConfig." + WRAPPER_MAX_MEMORY + ".short"));
    item.addChild("span", ATTR_CLASS, CSS_CONFIG)
        .addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_CLASS, ATTR_NAME, ATTR_VALUE},
            new String[] {"text", CSS_CONFIG, WRAPPER_MAX_MEMORY, curValue});
    item.addChild("span", ATTR_CLASS, "configlongdesc")
        .addChild(NodeL10n.getBase().getHTMLNode("WrapperConfig." + WRAPPER_MAX_MEMORY + ".long"));
  }

  private SelectionOverride determineSelectionOverride(HTTPRequest req) {
    if (req.isPartSet(PARAM_SELECT_FOR) && req.isPartSet(LocalFileBrowserToadlet.SELECT_DIR)) {
      return new SelectionOverride(
          req.getPartAsStringFailsafe(PARAM_SELECT_FOR, MAX_PARAM_VALUE_SIZE),
          req.getPartAsStringFailsafe("filename", MAX_PARAM_VALUE_SIZE));
    }
    return null;
  }

  private short addOptionGroups(
      HTTPRequest req,
      HTMLNode configGroupUlNode,
      boolean advancedModeEnabled,
      SelectionOverride selectionOverride) {
    short displayedConfigElements = 0;
    for (Option<?> option : subConfig.getOptions()) {
      if ((!advancedModeEnabled) && option.isExpert()) {
        continue;
      }
      displayedConfigElements++;
      appendOptionItem(req, advancedModeEnabled, selectionOverride, configGroupUlNode, option);
    }
    return displayedConfigElements;
  }

  private void appendOptionItem(
      HTTPRequest req,
      boolean advancedModeEnabled,
      SelectionOverride selectionOverride,
      HTMLNode configGroupUlNode,
      Option<?> option) {
    String configName = option.getName();
    String fullName = subConfig.getPrefix() + '.' + configName;
    String value = option.getValueDisplayString();

    if (value == null) {
      LOG.error("{}has returned null from config!);", fullName);
      return;
    }

    ConfigCallback<?> callback = option.getCallback();
    OptionType optionType = resolveOptionType(callback);

    HTMLNode shortDesc = option.getShortDescNode(plugin);
    HTMLNode longDesc = option.getLongDescNode(plugin);

    HTMLNode configItemNode = configGroupUlNode.addChild("li");
    String defaultValue =
        (callback instanceof BooleanCallback) ? l10n(option.getDefault()) : option.getDefault();

    configItemNode.addAttribute(ATTR_CLASS, optionType.cssClass);
    configItemNode
        .addChild("a", new String[] {"name", "id"}, new String[] {configName, configName})
        .addChild(
            "span",
            new String[] {ATTR_CLASS, ATTR_TITLE, "style"},
            new String[] {
              "configshortdesc",
              NodeL10n.getBase()
                      .getString(
                          "ConfigToadlet.defaultIs",
                          new String[] {"default"},
                          new String[] {defaultValue})
                  + (advancedModeEnabled ? " [" + fullName + ']' : ""),
              "cursor: help;"
            })
        .addChild(shortDesc);
    HTMLNode configItemValueNode = configItemNode.addChild("span", ATTR_CLASS, CSS_CONFIG);

    if (req.isPartSet(fullName)) {
      value = req.getPartAsStringFailsafe(fullName, MAX_PARAM_VALUE_SIZE);
    }
    if (selectionOverride != null && selectionOverride.option().equals(fullName)) {
      value = selectionOverride.value();
    }

    switch (optionType) {
      case DROP_DOWN ->
          configItemValueNode.addChild(
              addComboBox(
                  value, (EnumerableOptionCallback) callback, fullName, callback.isReadOnly()));
      case BOOLEAN ->
          configItemValueNode.addChild(
              addBooleanComboBox(Boolean.parseBoolean(value), fullName, callback.isReadOnly()));
      case DIRECTORY -> {
        configItemValueNode.addChild(addTextBox(value, fullName, option, false));
        configItemValueNode.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {
              VALUE_SUBMIT,
              SELECT_DIRECTORY_PREFIX + fullName,
              NodeL10n.getBase().getString("QueueToadlet.browseToChange")
            });
      }
      case TEXT_READ_ONLY ->
          configItemValueNode.addChild(addTextBox(value, fullName, option, true));
      case TEXT -> configItemValueNode.addChild(addTextBox(value, fullName, option, false));
    }

    configItemNode.addChild("span", ATTR_CLASS, "configlongdesc").addChild(longDesc);
  }

  private OptionType resolveOptionType(ConfigCallback<?> callback) {
    if (callback instanceof EnumerableOptionCallback) {
      return OptionType.DROP_DOWN;
    }
    if (callback instanceof BooleanCallback) {
      return OptionType.BOOLEAN;
    }
    if (callback instanceof ProgramDirectory.DirectoryCallback && !callback.isReadOnly()) {
      return OptionType.DIRECTORY;
    }
    if (!callback.isReadOnly()) {
      return OptionType.TEXT;
    }
    return OptionType.TEXT_READ_ONLY;
  }

  private void addFormButtons(HTMLNode formNode) {
    formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE},
        new String[] {VALUE_SUBMIT, l10n("apply")});
    formNode.addChild(
        TAG_INPUT, new String[] {ATTR_TYPE, ATTR_VALUE}, new String[] {"reset", l10n("undo")});
    addInput(formNode, VALUE_HIDDEN, PARAM_SUBCONFIG, subConfig.getPrefix());

    if (!subConfig.getPrefix().equals("node")) {
      addInput(formNode, VALUE_SUBMIT, PARAM_CONFIRM_RESET, l10n("resetToDefaults"));
    }
  }

  private record SelectionOverride(String option, String value) {}

  /**
   * Builds a single-line text input for a configuration option.
   *
   * <p>The caller supplies the current value and the fully qualified option name so the generated
   * field integrates with the existing POST handling. When {@code disabled} is true the input is
   * rendered read-only and styled accordingly, preserving the displayed value for clarity. The
   * option's short description is attached as the {@code alt} attribute to support screen readers
   * and contextual help popups.
   *
   * @param value current option value to render inside the text box; empty strings are allowed.
   * @param fullName full option name (including prefix) used as the form field name.
   * @param o option metadata providing the short description for accessibility and tooltips.
   * @param disabled whether the input should be rendered with the {@code disabled} attribute.
   * @return input element with class {@code config} containing the supplied value and name mapping.
   */
  public static HTMLNode addTextBox(String value, String fullName, Option<?> o, boolean disabled) {
    HTMLNode result;

    if (disabled) {
      result =
          new HTMLNode(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_CLASS, ATTR_DISABLED, "alt", ATTR_NAME, ATTR_VALUE}, //
              new String[] {"text", CSS_CONFIG, ATTR_DISABLED, o.getShortDesc(), fullName, value});
    } else {
      result =
          new HTMLNode(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_CLASS, "alt", ATTR_NAME, ATTR_VALUE}, //
              new String[] {"text", CSS_CONFIG, o.getShortDesc(), fullName, value});
    }

    return result;
  }

  /**
   * Builds a drop-down element for an enumerable configuration option.
   *
   * <p>The selectable values are sourced from the provided {@link EnumerableOptionCallback} and the
   * current value is preselected when present. The method avoids mutating the callback and
   * therefore remains safe to call during both GET rendering and POST re-rendering after validation
   * errors. When {@code disabled} is true, the resulting control carries the {@code disabled}
   * attribute but still lists all choices for reference.
   *
   * @param value currently applied or staged value to mark as selected when present.
   * @param o enumerable callback supplying the finite list of allowed values and read-only flag.
   * @param fullName full option name (including prefix) used as the form field name for POST data.
   * @param disabled whether the select element should be disabled while still showing options.
   * @return select node containing option children for every allowed value with selection applied.
   */
  public static HTMLNode addComboBox(
      String value, EnumerableOptionCallback o, String fullName, boolean disabled) {
    HTMLNode result;

    if (disabled) {
      result =
          new HTMLNode(
              TAG_SELECT, //
              new String[] {ATTR_NAME, ATTR_DISABLED}, //
              new String[] {fullName, ATTR_DISABLED});
    } else {
      result = new HTMLNode(TAG_SELECT, ATTR_NAME, fullName);
    }

    for (String possibleValue : o.getPossibleValues()) {
      if (possibleValue.equals(value)) {
        result.addChild(
            TAG_OPTION,
            new String[] {ATTR_VALUE, VALUE_SELECTED},
            new String[] {possibleValue, VALUE_SELECTED},
            possibleValue);
      } else {
        result.addChild(TAG_OPTION, ATTR_VALUE, possibleValue, possibleValue);
      }
    }

    return result;
  }

  /**
   * Builds a localized drop-down for boolean options.
   *
   * <p>The resulting element contains two options labeled with localized {@code true}/{@code false}
   * strings and selects the entry that matches {@code value}. It is used for both editable and
   * read-only boolean settings so the current state is always displayed consistently. Callers may
   * attach additional attributes to the returned select element before serialization.
   *
   * @param value boolean value to preselect within the rendered options.
   * @param fullName full option name (including prefix) used as the form field name for POST data.
   * @param disabled whether the select element should be disabled while still showing choices.
   * @return select node with two option children reflecting the localized boolean values.
   */
  public static HTMLNode addBooleanComboBox(boolean value, String fullName, boolean disabled) {
    HTMLNode result;

    if (disabled) {
      result =
          new HTMLNode(
              TAG_SELECT, //
              new String[] {ATTR_NAME, ATTR_DISABLED}, //
              new String[] {fullName, ATTR_DISABLED});
    } else {
      result = new HTMLNode(TAG_SELECT, ATTR_NAME, fullName);
    }

    if (value) {
      result.addChild(
          TAG_OPTION,
          new String[] {ATTR_VALUE, VALUE_SELECTED},
          new String[] {VALUE_TRUE, VALUE_SELECTED},
          l10n(VALUE_TRUE));
      result.addChild(TAG_OPTION, ATTR_VALUE, VALUE_FALSE, l10n(VALUE_FALSE));
    } else {
      result.addChild(TAG_OPTION, ATTR_VALUE, VALUE_TRUE, l10n(VALUE_TRUE));
      result.addChild(
          TAG_OPTION,
          new String[] {ATTR_VALUE, VALUE_SELECTED},
          new String[] {VALUE_FALSE, VALUE_SELECTED},
          l10n(VALUE_FALSE));
    }

    return result;
  }

  /**
   * Returns the request path served by this toadlet.
   *
   * <p>The path is the configuration root for the associated {@link SubConfig} and matches the form
   * action used in both GET and POST flows. It is deterministic for the lifetime of the instance
   * and does not change when advanced mode is toggled.
   *
   * @return absolute path segment used to access this configuration toadlet.
   */
  @Override
  public String path() {
    return "/config/" + subConfig.getPrefix();
  }

  /**
   * Indicates whether at least one option in the current subconfig should be shown.
   *
   * <p>In basic mode only non-expert options enable the toadlet; in advanced mode all options
   * qualify. The method has no side effects and simply inspects the declared metadata, making it
   * safe to call frequently during menu construction.
   *
   * @param ctx request context providing the advanced-mode flag that influences visibility.
   * @return {@code true} when the toadlet should be exposed to the caller, otherwise {@code false}.
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    Option<?>[] o = subConfig.getOptions();
    if (ctx.isAdvancedModeEnabled()) return true;
    for (Option<?> option : o) if (!option.isExpert()) return true;
    return false;
  }
}
