package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.filter.FilterOperation;
import network.crypta.clients.http.ContentFilterToadlet.ResultHandling;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Renders the web-based wizard for inserting a single file into the node and wires the page to the
 * queue submission endpoints. The toadlet exposes a simple form for casual users and reveals
 * advanced tuning controls when the caller has enabled expert mode.
 *
 * <p>Instances are short-lived per request but maintain minimal state to remember whether the user
 * last chose a canonical (CHK) or random (SSK) insert key. That hint influences the default
 * selection on the next page render, improving usability without altering any server-side
 * guarantees. The class is not thread-safe; callers should create a fresh instance per request
 * cycle rather than sharing across threads.
 *
 * <p>Typical flow:
 *
 * <ul>
 *   <li>{@link #handleMethodGET(URI, HTTPRequest, ToadletContext)} builds the HTML page and
 *       enforces access rules.
 *   <li>{@link #reportCanonicalInsert()} or {@link #reportRandomInsert()} record the user’s last
 *       selection to bias subsequent renders.
 * </ul>
 *
 * <p>The toadlet relies on {@link NodeClientCore} to derive security defaults, {@link PageMaker} to
 * assemble infoboxes, and the surrounding {@link ToadletContext} for permissions and localization.
 * It performs no I/O beyond HTML generation and delegates upload handling to queue endpoints.
 */
public class FileInsertWizardToadlet extends Toadlet implements LinkEnabledCallback {

  /**
   * Creates the toadlet that renders the file-insert wizard for the given client and node core. The
   * instance keeps only lightweight preferences and is intended to be short-lived; callers
   * typically construct one per incoming HTTP request or per handler registration. The constructor
   * does not perform I/O, and all dependencies are assumed to remain valid for the lifetime of the
   * toadlet. State stored in the instance is not synchronized and should not be shared across
   * threads without external coordination.
   *
   * @param client high-level client used to bind uploads to the current session; never {@code
   *     null}.
   * @param clientCore backing node core providing security defaults and queue endpoints; never
   *     {@code null}.
   */
  protected FileInsertWizardToadlet(HighLevelSimpleClient client, NodeClientCore clientCore) {
    super(client);
    this.core = clientCore;
  }

  final NodeClientCore core;

  // IMHO there isn't much point synchronizing these.
  private boolean rememberedLastTime;
  private boolean wasCanonicalLastTime;

  private static final String PATH_SEGMENT = "insertfile";
  static final String PATH = '/' + PATH_SEGMENT + '/';

  private static final String TAG_INPUT = "input";
  private static final String TAG_LABEL = "label";
  private static final String ATTR_VALUE = "value";
  private static final String INPUT_RADIO = "radio";
  private static final String INPUT_SUBMIT = "submit";
  private static final String INPUT_CHECKED = "checked";
  private static final String INPUT_KEYTYPE = "keytype";
  private static final String NBSP = " \u00a0 ";

  /**
   * Returns the HTTP path served by this toadlet.
   *
   * @return trailing-slash path segment used to register the wizard endpoint.
   */
  @Override
  public String path() {
    return PATH;
  }

  /**
   * Records that the most recent insert used a canonical CHK key so the next rendered form defaults
   * to the same choice. The hint influences only UI defaults; it does not persist beyond this
   * instance and does not bypass explicit user selections on later requests. This method only
   * updates in-memory hints and is safe to call after a successful queue submission.
   */
  public void reportCanonicalInsert() {
    rememberedLastTime = true;
    wasCanonicalLastTime = true;
  }

  /**
   * Records that the most recent insert used a random SSK key so subsequent renders bias toward the
   * same option. The flag affects only default radio-button selection and never forces a key type
   * when the caller provides explicit form data. State is retained only for the lifetime of this
   * toadlet instance.
   */
  public void reportRandomInsert() {
    rememberedLastTime = true;
    wasCanonicalLastTime = false;
  }

  /**
   * Builds and writes the HTML page for the insert wizard, enforcing gateway and permission rules
   * before rendering. The page includes basic controls plus optional advanced settings for key
   * selection, compression, compatibility modes, and splitfile key overrides. When the caller lacks
   * sufficient privileges, the method returns an unauthorized response instead of rendering the
   * wizard. It generates only HTML; file uploads are delegated to other toadlets via generated
   * forms, keeping this handler free of I/O-heavy work.
   *
   * @param uri request target used only for consistency checks; expected to match {@link #path()}.
   * @param request parsed HTTP request carrying headers and query parameters; must not be {@code
   *     null}.
   * @param ctx toadlet context supplying localization, permission flags, and form helpers; must not
   *     be {@code null}.
   * @throws ToadletContextClosedException if the context is closed while writing the response
   *     stream.
   * @throws IOException if output cannot be written to the client or template resources fail to
   *     load.
   * @throws RedirectException if access control redirects the caller to an authorization page.
   */
  public void handleMethodGET(URI uri, final HTTPRequest request, final ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
      sendUnauthorizedPage(ctx);
      return;
    }

    final PageMaker pageMaker = ctx.getPageMaker();

    PageNode page = pageMaker.getPageNode(l10n("pageTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    /* add alert summary box */
    if (ctx.isAllowedFullAccess()) contentNode.addChild(ctx.getAlertManager().createSummary());

    contentNode.addChild(createInsertBox(pageMaker, ctx, ctx.isAdvancedModeEnabled()));
    if (ctx.isAdvancedModeEnabled()) contentNode.addChild(createFilterBox(pageMaker, ctx));

    writeHTMLReply(ctx, 200, "OK", null, page.generate());
  }

  private HTMLNode createInsertBox(
      PageMaker pageMaker, ToadletContext ctx, boolean isAdvancedModeEnabled) {
    /* the insert file box */
    InfoboxNode infobox =
        pageMaker.getInfobox(
            NodeL10n.getBase().getString("QueueToadlet.insertFile"), "insert-queue", true);
    HTMLNode insertBox = infobox.getOuterNode();
    HTMLNode insertContent = infobox.getContentNode();
    insertContent.addChild("p", l10n("insertIntro"));
    NETWORK_THREAT_LEVEL seclevel =
        core.getNode().services().securityLevels().getNetworkThreatLevel();
    HTMLNode insertForm =
        ctx.addFormChild(insertContent, QueueToadlet.PATH_UPLOADS, "queueInsertForm");
    boolean preselectSsk =
        (!rememberedLastTime && seclevel != NETWORK_THREAT_LEVEL.LOW)
            || (rememberedLastTime && !wasCanonicalLastTime)
            || seclevel == NETWORK_THREAT_LEVEL.MAXIMUM;

    addKeyTypeOptions(insertForm, preselectSsk, isAdvancedModeEnabled);
    addCompressionOption(insertForm, isAdvancedModeEnabled);
    addCompatibilityOptions(insertForm, isAdvancedModeEnabled);
    addFileInputs(insertForm, ctx);

    return insertBox;
  }

  private void addFileInputs(HTMLNode insertForm, ToadletContext ctx) {
    insertForm.addChild("br");
    insertForm.addChild("br");
    if (ctx.isAllowedFullAccess()) {
      insertForm.addChild(
          "#", NodeL10n.getBase().getString("QueueToadlet.insertFileBrowseLabel") + ": ");
      insertForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {
            INPUT_SUBMIT,
            "insert-local",
            NodeL10n.getBase().getString("QueueToadlet.insertFileBrowseButton") + "..."
          });
      insertForm.addChild("br");
    }
    insertForm.addChild("#", NodeL10n.getBase().getString("QueueToadlet.insertFileLabel") + ": ");
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"file", "filename", ""});
    insertForm.addChild("#", NBSP);
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT,
          "insert",
          NodeL10n.getBase().getString("QueueToadlet.insertFileInsertFileLabel")
        });
    insertForm.addChild("#", NBSP);
  }

  private void addCompatibilityOptions(HTMLNode insertForm, boolean isAdvancedModeEnabled) {
    if (!isAdvancedModeEnabled) {
      return;
    }
    insertForm.addChild("br");
    insertForm.addChild("#", NodeL10n.getBase().getString("QueueToadlet.compatModeLabel") + ": ");
    HTMLNode select = insertForm.addChild("select", "name", "compatibilityMode");
    for (CompatibilityMode mode : InsertContext.CompatibilityMode.values()) {
      if (mode == CompatibilityMode.COMPAT_UNKNOWN) {
        continue;
      }
      HTMLNode option =
          select.addChild(
              "option",
              ATTR_VALUE,
              mode.name(),
              NodeL10n.getBase().getString("InsertContext.CompatibilityMode." + mode.name()));
      if (mode == CompatibilityMode.COMPAT_DEFAULT) {
        option.addAttribute("selected", "");
      }
    }
    insertForm.addChild("br");
    insertForm.addChild("#", l10n("splitfileCryptoKeyLabel") + ": ");
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", "maxlength"},
        new String[] {"text", "overrideSplitfileKey", "64"});
  }

  private void addCompressionOption(HTMLNode insertForm, boolean isAdvancedModeEnabled) {
    if (isAdvancedModeEnabled) {
      insertForm.addChild("br");
      insertForm.addChild("br");
      insertForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", INPUT_CHECKED, "id"},
          new String[] {"checkbox", "compress", INPUT_CHECKED, "checkboxCompress"});
      insertForm.addChild(
          TAG_LABEL,
          new String[] {"for"},
          new String[] {"checkboxCompress"},
          ' ' + NodeL10n.getBase().getString("QueueToadlet.insertFileCompressLabel"));
      return;
    }
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "compress", "true"});
  }

  private void addKeyTypeOptions(
      HTMLNode insertForm, boolean preselectSsk, boolean isAdvancedModeEnabled) {
    addKeyChoice(
        insertForm,
        "keytypeChk",
        "CHK",
        !preselectSsk,
        l10n("insertCanonicalTitle"),
        l10n("insertCanonical"),
        isAdvancedModeEnabled ? l10n("insertCanonicalAdvanced") : null);
    insertForm.addChild("br");
    addKeyChoice(
        insertForm,
        "keytypeSsk",
        "SSK",
        preselectSsk,
        l10n("insertRandomTitle"),
        l10n("insertRandom"),
        isAdvancedModeEnabled ? l10n("insertRandomAdvanced") : null);
    if (isAdvancedModeEnabled) {
      insertForm.addChild("br");
      addKeyChoice(
          insertForm,
          "keytypeSpecify",
          "specify",
          false,
          l10n("insertSpecificKeyTitle"),
          l10n("insertSpecificKey"),
          null);
      insertForm.addChild("#", " ");
      insertForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"text", "key", "KSK@"});
    }
  }

  private void addKeyChoice(
      HTMLNode insertForm,
      String id,
      String value,
      boolean checked,
      String title,
      String description,
      String advancedDescription) {
    HTMLNode input =
        insertForm.addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE, "id"},
            new String[] {INPUT_RADIO, INPUT_KEYTYPE, value, id});
    if (checked) {
      input.addAttribute(INPUT_CHECKED, INPUT_CHECKED);
    }
    insertForm.addChild(TAG_LABEL, new String[] {"for"}, new String[] {id}).addChild("b", title);
    insertForm.addChild("#", ": " + description);
    if (advancedDescription != null) {
      insertForm.addChild("#", " " + advancedDescription);
    }
  }

  private HTMLNode createFilterBox(PageMaker pageMaker, ToadletContext ctx) {
    /* the insert file box */
    InfoboxNode infobox = pageMaker.getInfobox(l10n("previewFilterFile"), "insert-queue", true);
    HTMLNode insertBox = infobox.getOuterNode();
    HTMLNode insertContent = infobox.getContentNode();
    HTMLNode insertForm =
        ctx.addFormChild(
            insertContent, ContentFilterToadlet.CONTENT_FILTER_PATH, "filterPreviewForm");
    insertForm.addChild("#", l10n("filterFileLabel"));
    insertForm.addChild("br");
    insertForm.addChild("br");

    // apply read filter, write filter, or both (write filtering selection will be added once
    // ContentFilter supports it)
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "filter-operation", FilterOperation.BOTH.toString()});

    // display in browser or save to disk
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE, "id"},
        new String[] {
          INPUT_RADIO, "result-handling", ResultHandling.DISPLAY.toString(), "resHandlingDisplay"
        });
    insertForm.addChild(
        TAG_LABEL,
        new String[] {"for"},
        new String[] {"resHandlingDisplay"},
        ContentFilterToadlet.l10n("displayResultLabel"));
    insertForm.addChild("br");
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE, "id"},
        new String[] {
          INPUT_RADIO, "result-handling", ResultHandling.SAVE.toString(), "resHandlingSave"
        });
    insertForm.addChild(
        TAG_LABEL,
        new String[] {"for"},
        new String[] {"resHandlingSave"},
        ContentFilterToadlet.l10n("saveResultLabel"));
    insertForm.addChild("br");
    insertForm.addChild("br");

    // mime type
    insertForm.addChild("#", ContentFilterToadlet.l10n("mimeTypeLabel") + ": ");
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"text", "mime-type", ""});
    insertForm.addChild("br");
    insertForm.addChild("#", ContentFilterToadlet.l10n("mimeTypeText"));
    insertForm.addChild("br");
    insertForm.addChild("br");

    // Local file browser
    if (ctx.isAllowedFullAccess()) {
      insertForm.addChild(
          "#", NodeL10n.getBase().getString("QueueToadlet.insertFileBrowseLabel") + ": ");
      insertForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {
            INPUT_SUBMIT,
            "filter-local",
            NodeL10n.getBase().getString("QueueToadlet.insertFileBrowseButton") + "..."
          });
      insertForm.addChild("br");
    }
    insertForm.addChild("#", NodeL10n.getBase().getString("QueueToadlet.insertFileLabel") + ": ");
    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"file", "filename", ""});
    insertForm.addChild("#", NBSP);

    insertForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {
          INPUT_SUBMIT, "filter-upload", ContentFilterToadlet.l10n("filterFileFilterLabel")
        });
    return insertBox;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("FileInsertWizardToadlet." + key);
  }

  /**
   * Indicates whether this toadlet should be exposed for the given context. Public gateway mode
   * requires full access privileges; private deployments always allow access. The method performs
   * no side effects, tolerates a {@code null} context during startup probing, and may be called
   * repeatedly by routing logic without incurring additional checks beyond boolean evaluation.
   *
   * @param ctx current toadlet context carrying permission flags; may be {@code null} when called
   *     during early routing.
   * @return {@code true} when the endpoint is available for the caller, {@code false} otherwise.
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    return (!container.publicGatewayMode()) || ((ctx != null) && ctx.isAllowedFullAccess());
  }
}
