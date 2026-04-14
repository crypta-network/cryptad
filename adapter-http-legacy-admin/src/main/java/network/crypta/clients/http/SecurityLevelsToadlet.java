package network.crypta.clients.http;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.util.Objects;
import network.crypta.clients.http.wizardsteps.PageHelper;
import network.crypta.clients.http.wizardsteps.WizardL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.MasterPasswordMutationStatus;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.http.ExternalLinkSupport;
import network.crypta.support.io.LegacyFileSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renders and processes the security levels configuration page exposed over the HTTP client UI.
 *
 * <p>This toadlet orchestrates the full workflow for selecting network and physical threat levels,
 * prompting for master passwords when high-security modes require them, and rendering
 * confirmation/rollback screens before persisting changes. It keeps the HTTP request branching,
 * HTML construction, and localization logic in the toadlet, while delegating live runtime state and
 * mutations to the detached security-levels and config ports. The class assumes callers' gate
 * access through {@link ToadletContext#checkFullAccess(Toadlet)} so it can operate on
 * administrative data.
 *
 * <p>Lifecycle highlights:
 *
 * <ul>
 *   <li>Reads form submissions and routes between threat-level updates and password management.
 *   <li>Generates confirmation pages when sensitive changes occur, preserving user-provided form
 *       values so the follow-up submission remains deterministic.
 *   <li>Persists configuration changes via the detached config runtime port only after successful
 *       validation.
 *   <li>Surfaces localized guidance and warnings to steer users away from insecure downgrades.
 * </ul>
 *
 * <p>Thread safety: instances are created per toadlet and rely on the servlet-style dispatching of
 * the surrounding framework; no internal synchronization is performed. Mutability is limited to
 * request-scoped helpers and stored runtime-port references. Use a distinct instance per request
 * handler or ensure external serialization if reused.
 *
 * @author Matthew Toseland {@literal <}toad@amphibian.dyndns.org{@literal >} (0xE43DA450)
 * @see SecurityLevelsPort
 */
public class SecurityLevelsToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(SecurityLevelsToadlet.class);

  /**
   * Maximum number of characters accepted for password inputs across all security pages. Inputs
   * longer than this limit are truncated by {@link HTTPRequest#getPartAsStringFailsafe(String,
   * int)}, preventing excessively large payloads while still accommodating passphrases. The value
   * is expressed in UTF-16 code units as delivered by the servlet request, not bytes.
   */
  public static final int MAX_PASSWORD_LENGTH = 1024;

  private static final String PARAM_SECLEVELS = "seclevels";
  private static final String PARAM_NETWORK_THREAT_LEVEL = "security-levels.networkThreatLevel";
  private static final String PARAM_NETWORK_THREAT_LEVEL_CONFIRM =
      "security-levels.networkThreatLevel.confirm";
  private static final String PARAM_NETWORK_THREAT_LEVEL_TRY_CONFIRM =
      "security-levels.networkThreatLevel.tryConfirm";
  private static final String PARAM_PHYSICAL_THREAT_LEVEL = "security-levels.physicalThreatLevel";
  private static final String PARAM_MASTER_PASSWORD = "masterPassword";
  private static final String PARAM_CONFIRM_MASTER_PASSWORD = "confirmMasterPassword";
  private static final String PARAM_OLD_PASSWORD = "oldPassword";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_ID = "id";
  private static final String ATTR_CHECKED = "checked";
  private static final String TAG_INPUT = "input";
  private static final String TAG_DIV = "div";
  private static final String TAG_LABEL = "label";
  private static final String CLASS_CONFIG = "config";
  private static final String CLASS_INFOBOX_CONTENT = "infobox-content";
  private static final String INPUT_HIDDEN = "hidden";
  private static final String INPUT_RADIO = "radio";
  private static final String INPUT_PASSWORD = "password";
  private static final String INPUT_SUBMIT = "submit";
  private static final String INFOBOX_ERROR = "infobox-error";
  private static final String PASSWORD_PAGE_TITLE_KEY = "passwordPageTitle";
  private static final String PASSWORD_WRONG_TITLE_KEY = "passwordWrongTitle";
  private static final String PASSWORD_FOR_DECRYPT_TITLE_KEY = "passwordForDecryptTitle";
  private static final String PASSWORD_NOT_ZERO_LENGTH_KEY = "passwordNotZeroLength";
  private static final String PARAM_REDIRECT = "redirect";
  private static final String HEADER_LOCATION = "Location";
  private static final String STATUS_FOUND = "Found";
  private static final String PASSWORD_BOX_NAME = "passwordBox";
  private static final String PASSWORD_ERROR_CLASS = "password-error";
  private static final String MASTER_PASSWORD_FORM = "masterPasswordForm";
  private static final String CANT_DELETE_PASSWORD_FILE_TITLE_KEY = "cantDeletePasswordFileTitle";
  private static final String SET_PASSWORD_TITLE_KEY = "setPasswordTitle";
  private static final String CONFIRM_PASSWORD_BOX_ID = "confirmPasswordBox";
  private static final String PASSWORD_FILE_CORRUPTED_TITLE_KEY = "passwordFileCorruptedTitle";
  private final SecurityLevelsToadletRuntimePorts runtimePorts;

  // Legacy Logger threshold callbacks removed; use LOG.isDebugEnabled() directly.

  SecurityLevelsToadlet(SecurityLevelsToadletRuntimePorts runtimePorts) {
    super();
    this.runtimePorts = Objects.requireNonNull(runtimePorts, "runtimePorts");
  }

  private static final class SecurityChangeState {
    HTMLNode pageNode;
    HTMLNode formNode;
    boolean changedAnything;

    boolean hasConfirmPage() {
      return pageNode != null;
    }
  }

  private SecurityLevelsPort securityLevelsPort() {
    return runtimePorts.securityLevelsPort();
  }

  private SecurityLevelsSnapshot securitySnapshot() {
    return securityLevelsPort().snapshot();
  }

  /**
   * Handles POST submissions for the security levels page and dispatches them to specialized
   * handlers. The method enforces full-access checks, routes master password updates separately
   * from threat-level changes, and persists configuration only after successful validation. When a
   * request does not match any known handler, it redirects the client back to the main security
   * levels view to maintain a predictable user path.
   *
   * @param uri request URI, retained for consistency with the toadlet contract and null-checked.
   * @param request HTTP request carrying form parts such as security level selections and
   *     password-related fields.
   * @param ctx toadlet context responsible for authorization, page building, and response output.
   * @throws ToadletContextClosedException if the client disconnects before the response completes.
   * @throws IOException if an I/O error occurs while writing HTML content or redirects headers.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    Objects.requireNonNull(uri);
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    if (request.isPartSet(PARAM_SECLEVELS)) {
      handleSecurityLevelsPost(request, ctx);
    } else if (request.isPartSet(PARAM_MASTER_PASSWORD)) {
      handleMasterPasswordPost(request, ctx);
    } else {
      redirectToSeclevels(ctx);
    }
  }

  private void handleSecurityLevelsPost(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    SecurityChangeState state = new SecurityChangeState();

    processNetworkThreatLevel(request, ctx, state);

    if (processPhysicalThreatLevel(request, ctx, state)) {
      return;
    }

    if (state.changedAnything) {
      runtimePorts.configPort().persist();
    }

    if (state.hasConfirmPage()) {
      finalizeConfirmationPage(ctx, state);
    } else {
      redirectToSeclevels(ctx);
    }
  }

  private void processNetworkThreatLevel(
      HTTPRequest request, ToadletContext ctx, SecurityChangeState state) {
    String networkThreatLevel = request.getPartAsStringFailsafe(PARAM_NETWORK_THREAT_LEVEL, 128);
    SecurityNetworkThreatLevel newThreatLevel =
        SecurityNetworkThreatLevel.parse(networkThreatLevel);
    SecurityNetworkThreatLevel currentLevel = securitySnapshot().networkThreatLevel();

    if (newThreatLevel == null || newThreatLevel == currentLevel) {
      return;
    }

    if (request.isPartSet(PARAM_NETWORK_THREAT_LEVEL_CONFIRM)) {
      securityLevelsPort().setNetworkThreatLevel(newThreatLevel);
      state.changedAnything = true;
      return;
    }

    String warningHtml =
        securityLevelsPort()
            .networkThreatLevelConfirmWarningHtml(
                newThreatLevel, PARAM_NETWORK_THREAT_LEVEL_CONFIRM);
    if (warningHtml == null) {
      securityLevelsPort().setNetworkThreatLevel(newThreatLevel);
      state.changedAnything = true;
      return;
    }

    buildNetworkConfirmPage(networkThreatLevel, newThreatLevel, ctx, state, warningHtml);
  }

  private void buildNetworkConfirmPage(
      String networkThreatLevel,
      SecurityNetworkThreatLevel newThreatLevel,
      ToadletContext ctx,
      SecurityChangeState state,
      String warningHtml) {
    PageNode page =
        ctx.getPageMaker()
            .getPageNode(NodeL10n.getBase().getString("ConfigToadlet.fullTitle"), ctx);
    state.pageNode = page.getOuterNode();
    HTMLNode content = page.getContentNode();
    state.formNode = ctx.addFormChild(content, ".", "configFormSecLevels");
    HTMLNode ul = state.formNode.addChild("ul", ATTR_CLASS, CLASS_CONFIG);
    HTMLNode seclevelGroup = ul.addChild("li");

    seclevelGroup.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_NETWORK_THREAT_LEVEL, networkThreatLevel});
    HTMLNode infobox = seclevelGroup.addChild(TAG_DIV, ATTR_CLASS, "infobox infobox-information");
    infobox.addChild(
        TAG_DIV,
        ATTR_CLASS,
        "infobox-header",
        l10nSec(
            "networkThreatLevelConfirmTitle",
            "mode",
            l10nSec("networkThreatLevel.name." + newThreatLevel.name())));
    HTMLNode infoboxContent = infobox.addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    infoboxContent.addChild("%", warningHtml);
    infoboxContent.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_NETWORK_THREAT_LEVEL_TRY_CONFIRM, "on"});
  }

  private boolean processPhysicalThreatLevel(
      HTTPRequest request, ToadletContext ctx, SecurityChangeState state)
      throws ToadletContextClosedException, IOException {
    String physicalThreatLevel = request.getPartAsStringFailsafe(PARAM_PHYSICAL_THREAT_LEVEL, 128);
    SecurityPhysicalThreatLevel newPhysicalLevel =
        SecurityPhysicalThreatLevel.parse(physicalThreatLevel);
    SecurityPhysicalThreatLevel oldPhysicalLevel = securitySnapshot().physicalThreatLevel();
    if (LOG.isDebugEnabled()) {
      LOG.debug("New physical threat level: {} old = {}", newPhysicalLevel, oldPhysicalLevel);
    }

    if (newPhysicalLevel == null) {
      return false;
    }

    if (isSameHighThreatLevel(newPhysicalLevel, oldPhysicalLevel)) {
      return handlePasswordChangeWhileHigh(request, ctx, state, newPhysicalLevel);
    }

    if (newPhysicalLevel == oldPhysicalLevel) {
      return false;
    }

    if (newPhysicalLevel == SecurityPhysicalThreatLevel.HIGH
        && handleUpgradeToHigh(request, ctx, state, oldPhysicalLevel, newPhysicalLevel)) {
      return true;
    }

    if (isDowngradeFromHigh(newPhysicalLevel, oldPhysicalLevel)
        && handleDowngradeFromHigh(request, ctx, state, newPhysicalLevel)) {
      return true;
    }

    if (newPhysicalLevel == SecurityPhysicalThreatLevel.MAXIMUM
        && handleMaximumLevel(ctx, newPhysicalLevel)) {
      return true;
    }

    securityLevelsPort().setPhysicalThreatLevel(newPhysicalLevel);
    state.changedAnything = true;
    return false;
  }

  private boolean handlePasswordChangeWhileHigh(
      HTTPRequest request,
      ToadletContext ctx,
      SecurityChangeState state,
      SecurityPhysicalThreatLevel newPhysicalLevel)
      throws ToadletContextClosedException, IOException {

    String password = request.getPartAsStringFailsafe(PARAM_MASTER_PASSWORD, MAX_PASSWORD_LENGTH);
    String oldPassword = request.getPartAsStringFailsafe(PARAM_OLD_PASSWORD, MAX_PASSWORD_LENGTH);
    String confirmPassword =
        request.getPartAsStringFailsafe(PARAM_CONFIRM_MASTER_PASSWORD, MAX_PASSWORD_LENGTH);
    if (!oldPassword.isEmpty()
        && !confirmPassword.isEmpty()
        && !password.isEmpty()
        && password.equals(confirmPassword)) {
      MasterPasswordMutationStatus status =
          securityLevelsPort().changeMasterPassword(oldPassword, password);
      switch (status) {
        case SUCCESS -> {
          return false;
        }
        case WRONG_PASSWORD -> {
          sendChangePasswordForm(ctx, true, false, newPhysicalLevel.name());
          storeConfigIfChanged(state);
          return true;
        }
        case CORRUPTED_FILE -> {
          sendPasswordFileCorruptedPage(ctx);
          storeConfigIfChanged(state);
          return true;
        }
        case ALREADY_SET -> {
          sendChangePasswordForm(ctx, false, true, newPhysicalLevel.name());
          storeConfigIfChanged(state);
          return true;
        }
      }
    } else if (!password.isEmpty() || !oldPassword.isEmpty() || !confirmPassword.isEmpty()) {
      sendChangePasswordForm(ctx, false, true, newPhysicalLevel.name());
      storeConfigIfChanged(state);
      return true;
    }
    return false;
  }

  private boolean applyDowngradePasswordChange(
      String password,
      ToadletContext ctx,
      SecurityChangeState state,
      SecurityPhysicalThreatLevel newPhysicalLevel)
      throws ToadletContextClosedException, IOException {
    try {
      MasterPasswordMutationStatus status = securityLevelsPort().changeMasterPassword(password, "");
      switch (status) {
        case SUCCESS -> {
          return false;
        }
        case WRONG_PASSWORD -> {
          LOG.warn("Wrong password supplied when downgrading from HIGH");
          sendWrongPasswordResponse(
              ctx, PASSWORD_FOR_DECRYPT_TITLE_KEY, true, false, newPhysicalLevel.name());
          storeConfigIfChanged(state);
          return true;
        }
        case CORRUPTED_FILE -> {
          sendPasswordFileCorruptedPage(ctx);
          storeConfigIfChanged(state);
          return true;
        }
        case ALREADY_SET -> {
          sendChangePasswordForm(ctx, false, true, newPhysicalLevel.name());
          storeConfigIfChanged(state);
          return true;
        }
      }
    } catch (IOException e) {
      if (!securitySnapshot().masterPasswordFileExists()) {
        LOG.info("Master password file no longer exists, assuming this is deliberate");
      } else {
        LOG.error("Cannot change password as cannot write new passwords file", e);
        String msg =
            "<html><head><title>"
                + l10nSec("cantWriteNewMasterKeysFileTitle")
                + "</title></head><body><h1>"
                + l10nSec("cantWriteNewMasterKeysFileTitle")
                + "</h1><p>"
                + l10nSec("cantWriteNewMasterKeysFile")
                + "<pre>";
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        pw.flush();
        msg = msg + sw + "</pre></body></html>";
        writeHTMLReply(ctx, 500, "Internal Error", msg);
        storeConfigIfChanged(state);
        return true;
      }
    }
    return false;
  }

  private boolean handleUpgradeToHigh(
      HTTPRequest request,
      ToadletContext ctx,
      SecurityChangeState state,
      SecurityPhysicalThreatLevel oldPhysicalLevel,
      SecurityPhysicalThreatLevel newPhysicalLevel)
      throws ToadletContextClosedException, IOException {
    String password = request.getPartAsStringFailsafe(PARAM_MASTER_PASSWORD, MAX_PASSWORD_LENGTH);
    String confirmPassword =
        request.getPartAsStringFailsafe(PARAM_CONFIRM_MASTER_PASSWORD, MAX_PASSWORD_LENGTH);
    if (!passwordsMatch(password, confirmPassword)) {
      return handleUpgradePasswordMismatch(ctx, state, newPhysicalLevel, password, confirmPassword);
    }
    return applyUpgradePassword(oldPhysicalLevel, newPhysicalLevel, password, ctx, state);
  }

  private boolean passwordsMatch(String password, String confirmPassword) {
    return !password.isEmpty() && !confirmPassword.isEmpty() && password.equals(confirmPassword);
  }

  private boolean handleUpgradePasswordMismatch(
      ToadletContext ctx,
      SecurityChangeState state,
      SecurityPhysicalThreatLevel newPhysicalLevel,
      String password,
      String confirmPassword)
      throws ToadletContextClosedException, IOException {
    if (password.isEmpty() || confirmPassword.isEmpty()) {
      sendPasswordPage(ctx, newPhysicalLevel.name());
    } else {
      sendPasswordPageMismatch(ctx, newPhysicalLevel.name());
    }
    storeConfigIfChanged(state);
    return true;
  }

  private boolean applyUpgradePassword(
      SecurityPhysicalThreatLevel oldPhysicalLevel,
      SecurityPhysicalThreatLevel newPhysicalLevel,
      String password,
      ToadletContext ctx,
      SecurityChangeState state)
      throws ToadletContextClosedException, IOException {
    MasterPasswordMutationStatus status;
    if (oldPhysicalLevel == SecurityPhysicalThreatLevel.NORMAL
        || oldPhysicalLevel == SecurityPhysicalThreatLevel.LOW) {
      status = securityLevelsPort().changeMasterPassword("", password);
    } else {
      status = securityLevelsPort().setMasterPassword(password);
    }
    switch (status) {
      case SUCCESS -> {
        return false;
      }
      case ALREADY_SET -> {
        sendChangePasswordForm(ctx, false, false, newPhysicalLevel.name());
        storeConfigIfChanged(state);
        return true;
      }
      case WRONG_PASSWORD -> {
        LOG.warn("Wrong password supplied when upgrading to HIGH");
        sendWrongPasswordResponse(
            ctx, PASSWORD_PAGE_TITLE_KEY, false, true, newPhysicalLevel.name());
        storeConfigIfChanged(state);
        return true;
      }
      case CORRUPTED_FILE -> {
        sendPasswordFileCorruptedPage(ctx);
        storeConfigIfChanged(state);
        return true;
      }
    }
    throw new IllegalStateException("Unhandled master password mutation status: " + status);
  }

  private boolean handleDowngradeFromHigh(
      HTTPRequest request,
      ToadletContext ctx,
      SecurityChangeState state,
      SecurityPhysicalThreatLevel newPhysicalLevel)
      throws ToadletContextClosedException, IOException {
    String password = request.getPartAsStringFailsafe(PARAM_MASTER_PASSWORD, MAX_PASSWORD_LENGTH);
    if (!password.isEmpty()) {
      return applyDowngradePasswordChange(password, ctx, state, newPhysicalLevel);
    } else if (securitySnapshot().masterPasswordFileExists()) {
      PageNode page = ctx.getPageMaker().getPageNode(l10nSec(PASSWORD_FOR_DECRYPT_TITLE_KEY), ctx);
      HTMLNode contentNode = page.getContentNode();

      HTMLNode content =
          ctx.getPageMaker()
              .getInfobox(
                  INFOBOX_ERROR,
                  l10nSec(PASSWORD_FOR_DECRYPT_TITLE_KEY),
                  contentNode,
                  "password-prompt",
                  false)
              .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
      content.addChild("p", l10nSec(PASSWORD_NOT_ZERO_LENGTH_KEY));

      SecurityLevelsToadlet.generatePasswordFormPage(
          new PasswordFormOptions(false, false, true, false, newPhysicalLevel.name(), null),
          ctx.getContainer(),
          content);

      addBackToSeclevelsLink(content);

      writeHTMLReply(ctx, 200, "OK", page.generate());
      storeConfigIfChanged(state);
      return true;
    }
    return false;
  }

  private void sendWrongPasswordResponse(
      ToadletContext ctx,
      String pageTitleKey,
      boolean forDowngrade,
      boolean forUpgrade,
      String physicalLevel)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10nSec(pageTitleKey), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(PASSWORD_WRONG_TITLE_KEY),
                contentNode,
                "wrong-password",
                true)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(true, false, forDowngrade, forUpgrade, physicalLevel, null),
        ctx.getContainer(),
        content);
    addBackToSeclevelsLink(content);
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private boolean handleMaximumLevel(
      ToadletContext ctx, SecurityPhysicalThreatLevel newPhysicalLevel)
      throws ToadletContextClosedException, IOException {
    try {
      securityLevelsPort().deleteMasterPasswordFile();
    } catch (IOException _) {
      sendCantDeleteMasterKeysFile(ctx, newPhysicalLevel.name());
      return true;
    }
    return false;
  }

  private void handleMasterPasswordPost(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String masterPassword =
        request.getPartAsStringFailsafe(PARAM_MASTER_PASSWORD, MAX_PASSWORD_LENGTH);
    if (masterPassword.isEmpty()) {
      sendPasswordPage(ctx, null);
      return;
    }
    LOG.info("Setting master password");
    MasterPasswordMutationStatus status = securityLevelsPort().setMasterPassword(masterPassword);
    switch (status) {
      case SUCCESS -> {
        // Continue with the redirect handling below.
      }
      case ALREADY_SET -> {
        LOG.error("Already set master password");
        redirectToRoot(ctx);
        return;
      }
      case WRONG_PASSWORD -> {
        sendPasswordFormPage(ctx);
        return;
      }
      case CORRUPTED_FILE -> {
        sendPasswordFileCorruptedPage(ctx);
        return;
      }
    }
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    if (request.isPartSet(PARAM_REDIRECT)) {
      String to = request.getPartAsStringFailsafe(PARAM_REDIRECT, 100);
      if (to.startsWith("/")) {
        headers.put(HEADER_LOCATION, to);
        ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
        return;
      }
    }
    redirectToRoot(ctx);
  }

  private void finalizeConfirmationPage(ToadletContext ctx, SecurityChangeState state)
      throws ToadletContextClosedException, IOException {
    state.formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_SECLEVELS, "on"});
    state.formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, l10n("apply")});
    state.formNode.addChild(
        TAG_INPUT, new String[] {ATTR_TYPE, ATTR_VALUE}, new String[] {"reset", l10n("undo")});
    writeHTMLReply(ctx, 200, "OK", state.pageNode.generate());
  }

  private void redirectToSeclevels(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_LOCATION, PATH);
    ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
  }

  private void redirectToRoot(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_LOCATION, "/");
    ctx.sendReplyHeaders(302, STATUS_FOUND, headers, null, 0);
  }

  private void storeConfigIfChanged(SecurityChangeState state) {
    if (state.changedAnything) {
      runtimePorts.configPort().persist();
    }
  }

  private boolean isDowngradeFromHigh(
      SecurityPhysicalThreatLevel newPhysicalLevel, SecurityPhysicalThreatLevel oldPhysicalLevel) {
    return (newPhysicalLevel == SecurityPhysicalThreatLevel.LOW
            || newPhysicalLevel == SecurityPhysicalThreatLevel.NORMAL)
        && oldPhysicalLevel == SecurityPhysicalThreatLevel.HIGH;
  }

  private boolean isSameHighThreatLevel(
      SecurityPhysicalThreatLevel newPhysicalLevel, SecurityPhysicalThreatLevel oldPhysicalLevel) {
    return newPhysicalLevel == oldPhysicalLevel
        && newPhysicalLevel == SecurityPhysicalThreatLevel.HIGH;
  }

  private void sendCantDeleteMasterKeysFile(ToadletContext ctx, String physicalSecurityLevel)
      throws ToadletContextClosedException, IOException {
    HTMLNode pageNode =
        sendCantDeleteMasterKeysFileInner(
            ctx, securitySnapshot().masterPasswordFilePath(), false, physicalSecurityLevel);
    writeHTMLReply(ctx, 200, "OK", pageNode.generate());
  }

  /**
   * Adds an inline infobox to the first-time wizard when the node cannot delete the master password
   * file. The helper wires the error message into the wizard page, preserves the selected physical
   * threat level, and emits a retry form so users can resolve filesystem permissions without
   * abandoning the setup flow.
   *
   * @param helper wizard helper that supplies localization and form creation utilities.
   * @param filename absolute path to the password file that failed to delete; displayed verbatim to
   *     aid troubleshooting.
   * @param physicalSecurityLevel textual representation of the chosen physical threat level that
   *     should persist across retries.
   */
  public static void sendCantDeleteMasterKeysFileInner(
      PageHelper helper, String filename, String physicalSecurityLevel) {
    HTMLNode contentNode = helper.getPageContent(l10nSec(CANT_DELETE_PASSWORD_FILE_TITLE_KEY));
    HTMLNode content =
        helper
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(CANT_DELETE_PASSWORD_FILE_TITLE_KEY),
                contentNode,
                PASSWORD_ERROR_CLASS,
                true)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    HTMLNode form = helper.addFormChild(content, "/wizard/", MASTER_PASSWORD_FORM);
    sendCantDeleteMasterKeysFileInner(content, form, filename, physicalSecurityLevel);
  }

  /**
   * Constructs a full error page explaining that the master password file could not be deleted and
   * provides a retry action. It uses the supplied context to build a localized page shell, embeds
   * an infobox describing the failure, and returns the outer HTML node so callers can serialize the
   * page themselves. When invoked from the wizard flow, the generated form posts to the wizard; in
   * other contexts it posts back to this toadlet while keeping the chosen physical threat level.
   *
   * @param ctx toadlet context used for page construction and localization; must be non-null.
   * @param filename absolute path to the password file that failed deletion; shown to the user.
   * @param forFirstTimeWizard whether the retry form should target the first-time wizard handler.
   * @param physicalSecurityLevel the current physical threat level label persisted across
   *     submissions.
   * @return the outer HTML node containing the fully prepared page for immediate rendering.
   */
  public static HTMLNode sendCantDeleteMasterKeysFileInner(
      ToadletContext ctx,
      String filename,
      boolean forFirstTimeWizard,
      String physicalSecurityLevel) {
    PageNode page =
        ctx.getPageMaker().getPageNode(l10nSec(CANT_DELETE_PASSWORD_FILE_TITLE_KEY), ctx);
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode contentNode = page.getContentNode();

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(CANT_DELETE_PASSWORD_FILE_TITLE_KEY),
                contentNode,
                PASSWORD_ERROR_CLASS,
                true)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    HTMLNode form =
        forFirstTimeWizard
            ? ctx.addFormChild(content, "/wizard/", MASTER_PASSWORD_FORM)
            : ctx.addFormChild(content, PATH, MASTER_PASSWORD_FORM);

    sendCantDeleteMasterKeysFileInner(content, form, filename, physicalSecurityLevel);
    return pageNode;
  }

  private static void sendCantDeleteMasterKeysFileInner(
      HTMLNode content, HTMLNode form, String filename, String physicalSecurityLevel) {
    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_PHYSICAL_THREAT_LEVEL, physicalSecurityLevel});
    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_SECLEVELS, "true"});

    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, "tryAgain", l10nSec("cantDeletePasswordFileButton")});

    content.addChild("p", l10nSec("cantDeletePasswordFile", "filename", filename));
  }

  /**
   * Sends a form requesting a master password change when the node already operates at a high
   * physical threat level. The form highlights empty or incorrect passwords when indicated,
   * preserves the current physical threat level through hidden fields, and links back to the
   * security levels page. Configuration is not persisted here; callers remain responsible for
   * saving after successful submission.
   *
   * @param ctx toadlet context used to construct the page and write the response.
   * @param wrongPassword whether the previous attempt failed validation and should show an error.
   * @param emptyPassword whether the previous submission omitted a password and required a prompt.
   * @param physicalSecurityLevel selected physical threat level to retain across form posts.
   * @throws IOException if an error occurs while generating or sending the HTML response body.
   * @throws ToadletContextClosedException if the client connection closes before the reply finishes
   *     sending.
   */
  private void sendChangePasswordForm(
      ToadletContext ctx,
      boolean wrongPassword,
      boolean emptyPassword,
      String physicalSecurityLevel)
      throws ToadletContextClosedException, IOException {

    // Must set a password!
    PageNode page = ctx.getPageMaker().getPageNode(l10nSec("changePasswordTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR, l10nSec("changePasswordTitle"), contentNode, "password-change", true)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    if (emptyPassword) {
      content.addChild("p", l10nSec(PASSWORD_NOT_ZERO_LENGTH_KEY));
    }

    if (wrongPassword) {
      content.addChild("p", l10nSec("wrongOldPassword"));
    }

    HTMLNode form = ctx.addFormChild(content, path(), "changePasswordForm");

    addPasswordChangeForm(form);

    if (physicalSecurityLevel != null) {
      form.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_HIDDEN, PARAM_PHYSICAL_THREAT_LEVEL, physicalSecurityLevel});
      form.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_HIDDEN, PARAM_SECLEVELS, "true"});
    }
    addBackToSeclevelsLink(content);

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void sendPasswordPage(ToadletContext ctx, String threatlevel)
      throws ToadletContextClosedException, IOException {

    // Must set a password!
    PageNode page = ctx.getPageMaker().getPageNode(l10nSec(SET_PASSWORD_TITLE_KEY), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(SET_PASSWORD_TITLE_KEY),
                contentNode,
                "password-prompt",
                false)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    content.addChild("p", l10nSec(PASSWORD_NOT_ZERO_LENGTH_KEY));

    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, false, false, true, threatlevel, null),
        ctx.getContainer(),
        content);

    addBackToSeclevelsLink(content);

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private static void addBackToSeclevelsLink(HTMLNode content) {
    content.addChild("p").addChild("a", "href", PATH, l10nSec("backToSecurityLevels"));
  }

  /**
   * Renders the current security levels page for HTTP GET requests. It injects any accumulated
   * alerts, displays network and physical threat options with localized guidance, and ensures the
   * appropriate password prompts are visible based on the node state. The page is generated through
   * the shared page maker to preserve a consistent layout and theming across the UI.
   *
   * @param uri incoming request URI; retained for compatibility with the toadlet interface.
   * @param req HTTP request object supplying parameters used to pre-fill form fields when needed.
   * @param ctx toadlet context that validates full access and writes the completed page to the
   *     client.
   * @throws ToadletContextClosedException if the response output stream is closed prematurely.
   * @throws IOException if output generation fails during HTML serialization or transmission.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) return;

    PageNode page =
        ctx.getPageMaker()
            .getPageNode(NodeL10n.getBase().getString("SecurityLevelsToadlet.fullTitle"), ctx);
    HTMLNode contentNode = page.getContentNode();

    contentNode.addChild(ctx.getAlertManager().createSummary());

    drawSecurityLevelsPage(contentNode, ctx);

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void drawSecurityLevelsPage(HTMLNode contentNode, ToadletContext ctx) {
    HTMLNode formNode = createSeclevelsForm(contentNode, ctx);
    SecurityLevelsSnapshot snapshot = securitySnapshot();
    addNetworkThreatSection(formNode, snapshot.networkThreatLevel());
    addPhysicalThreatSection(formNode, snapshot.physicalThreatLevel(), snapshot.hasDatabase());

    addFormButtons(formNode);
  }

  private HTMLNode createSeclevelsForm(HTMLNode contentNode, ToadletContext ctx) {
    HTMLNode infobox = contentNode.addChild(TAG_DIV, ATTR_CLASS, "infobox infobox-normal");
    infobox.addChild(TAG_DIV, ATTR_CLASS, "infobox-header", l10nSec("title"));
    HTMLNode configNode = infobox.addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    return ctx.addFormChild(configNode, ".", "configFormSecLevels");
  }

  private void addNetworkThreatSection(
      HTMLNode formNode, SecurityNetworkThreatLevel currentNetworkLevel) {
    formNode.addChild(TAG_DIV, ATTR_CLASS, "configprefix", l10nSec("networkThreatLevelShort"));
    HTMLNode ul = formNode.addChild("ul", ATTR_CLASS, CLASS_CONFIG);
    HTMLNode seclevelGroup = ul.addChild("li");
    seclevelGroup.addChild("#", l10nSec("networkThreatLevel.opennetIntro"));

    addNetworkGroup(
        seclevelGroup,
        "networkThreatLevel.opennetLabel",
        "networkThreatLevel.opennetExplain",
        SecurityNetworkThreatLevel.opennetValues(),
        currentNetworkLevel,
        "opennetDiv",
        false);

    addNetworkGroup(
        seclevelGroup,
        "networkThreatLevel.darknetLabel",
        "networkThreatLevel.darknetExplain",
        SecurityNetworkThreatLevel.darknetValues(),
        currentNetworkLevel,
        "darknetDiv",
        true);

    seclevelGroup.addChild("p").addChild("b", l10nSec("networkThreatLevel.opennetFriendsWarning"));
  }

  private void addNetworkGroup(
      HTMLNode seclevelGroup,
      String labelKey,
      String explainKey,
      SecurityNetworkThreatLevel[] levels,
      SecurityNetworkThreatLevel currentNetworkLevel,
      String cssClass,
      boolean includeLink) {
    HTMLNode paragraph = seclevelGroup.addChild("p");
    paragraph.addChild("b", l10nSec(labelKey));
    paragraph.addChild("#", ": " + l10nSec(explainKey));
    HTMLNode container = seclevelGroup.addChild(TAG_DIV, ATTR_CLASS, cssClass);

    for (SecurityNetworkThreatLevel level : levels) {
      addNetworkLevelOption(container, currentNetworkLevel, level, includeLink);
    }
  }

  private void addNetworkLevelOption(
      HTMLNode container,
      SecurityNetworkThreatLevel currentNetworkLevel,
      SecurityNetworkThreatLevel level,
      boolean includeLink) {
    String inputId = PARAM_NETWORK_THREAT_LEVEL + level.name();
    HTMLNode input =
        addRadioInput(
            container.addChild("p"),
            PARAM_NETWORK_THREAT_LEVEL,
            level.name(),
            level == currentNetworkLevel,
            inputId);
    input
        .addChild(TAG_LABEL, new String[] {"for"}, new String[] {inputId})
        .addChild("b", l10nSec("networkThreatLevel.name." + level));
    input.addChild("#", ": ");
    addNetworkDescriptions(input, level, includeLink);
  }

  private void addNetworkDescriptions(
      HTMLNode input, SecurityNetworkThreatLevel level, boolean includeLink) {
    NodeL10n.getBase()
        .addL10nSubstitution(
            input,
            "SecurityLevels.networkThreatLevel.choice." + level,
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    HTMLNode inner = input.addChild("p").addChild("i");
    if (includeLink) {
      NodeL10n.getBase()
          .addL10nSubstitution(
              inner,
              "SecurityLevels.networkThreatLevel.desc." + level,
              new String[] {"bold", "link"},
              new HTMLNode[] {HTMLNode.STRONG, HTMLNode.link("/wizard/?step=OPENNET")});
    } else {
      NodeL10n.getBase()
          .addL10nSubstitution(
              inner,
              "SecurityLevels.networkThreatLevel.desc." + level,
              new String[] {"bold"},
              new HTMLNode[] {HTMLNode.STRONG});
    }
  }

  private void addPhysicalThreatSection(
      HTMLNode formNode, SecurityPhysicalThreatLevel currentPhysicalLevel, boolean hasDatabase) {
    formNode.addChild(TAG_DIV, ATTR_CLASS, "configprefix", l10nSec("physicalThreatLevelShort"));
    HTMLNode ul = formNode.addChild("ul", ATTR_CLASS, CLASS_CONFIG);
    HTMLNode seclevelGroup = ul.addChild("li");
    seclevelGroup.addChild("#", l10nSec("physicalThreatLevel"));

    NodeL10n.getBase()
        .addL10nSubstitution(
            seclevelGroup.addChild("p").addChild("i"),
            "SecurityLevels.physicalThreatLevelFDE",
            new String[] {"bold", "link"},
            new HTMLNode[] {
              HTMLNode.STRONG,
              HTMLNode.linkInNewWindow(
                  ExternalLinkSupport.escape(l10nSec("physicalThreatLevelFDELink")))
            });
    HTMLNode swapWarning = seclevelGroup.addChild("p").addChild("i");
    String operatingSystemNameKey = LegacyFileSupport.operatingSystemNameKey();
    swapWarning.addChild(
        "#",
        NodeL10n.getBase()
            .getString(
                "SecurityLevels.physicalThreatLevelSwapfile",
                "operatingSystem",
                NodeL10n.getBase().getString("OperatingSystemName." + operatingSystemNameKey)));
    if (LegacyFileSupport.isWindows()) {
      swapWarning.addChild("#", " " + WizardL10n.l10nSec("physicalThreatLevelSwapfileWindows"));
    }

    for (SecurityPhysicalThreatLevel level : SecurityPhysicalThreatLevel.values()) {
      addPhysicalLevelOption(seclevelGroup, currentPhysicalLevel, level, hasDatabase);
    }
  }

  private void addPhysicalLevelOption(
      HTMLNode seclevelGroup,
      SecurityPhysicalThreatLevel currentPhysicalLevel,
      SecurityPhysicalThreatLevel level,
      boolean hasDatabase) {
    String inputId = PARAM_PHYSICAL_THREAT_LEVEL + level.name();
    HTMLNode input =
        addRadioInput(
            seclevelGroup.addChild("p"),
            PARAM_PHYSICAL_THREAT_LEVEL,
            level.name(),
            level == currentPhysicalLevel,
            inputId);
    input
        .addChild(TAG_LABEL, new String[] {"for"}, new String[] {inputId})
        .addChild("b", l10nSec("physicalThreatLevel.name." + level));
    input.addChild("#", ": ");
    NodeL10n.getBase()
        .addL10nSubstitution(
            input,
            "SecurityLevels.physicalThreatLevel.choice." + level,
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    HTMLNode inner = input.addChild("p").addChild("i");
    NodeL10n.getBase()
        .addL10nSubstitution(
            inner,
            "SecurityLevels.physicalThreatLevel.desc." + level,
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    if (level == SecurityPhysicalThreatLevel.MAXIMUM && hasDatabase) {
      inner.addChild("b", " " + l10nSec("warningMaximumWillDeleteQueue"));
    }
    if (level == SecurityPhysicalThreatLevel.HIGH) {
      if (currentPhysicalLevel == level) {
        addPasswordChangeForm(inner);
      } else {
        inner.addChild("p", l10nSec("setPassword"));
        generatePasswordConfirmationForm(inner);
      }
    }
  }

  private HTMLNode addRadioInput(
      HTMLNode parent, String controlName, String value, boolean checked, String inputId) {
    String[] attributes =
        checked
            ? new String[] {ATTR_TYPE, ATTR_CHECKED, ATTR_NAME, ATTR_VALUE, ATTR_ID}
            : new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, ATTR_ID};
    String[] values =
        checked
            ? new String[] {INPUT_RADIO, "on", controlName, value, inputId}
            : new String[] {INPUT_RADIO, controlName, value, inputId};
    return parent.addChild(TAG_INPUT, attributes, values);
  }

  private void addFormButtons(HTMLNode formNode) {
    formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_HIDDEN, PARAM_SECLEVELS, "on"});
    formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, l10n("apply")});
    formNode.addChild(
        TAG_INPUT, new String[] {ATTR_TYPE, ATTR_VALUE}, new String[] {"reset", l10n("undo")});
  }

  private void addPasswordChangeForm(HTMLNode inner) {
    HTMLNode table = inner.addChild("table", "border", "0");
    HTMLNode row = table.addChild("tr");
    HTMLNode cell = row.addChild("td");
    cell.addChild(TAG_LABEL, "for", "oldPasswordBox", l10nSec("oldPasswordLabel"));
    cell = row.addChild("td");
    cell.addChild(
        TAG_INPUT,
        new String[] {"id", ATTR_TYPE, ATTR_NAME, "size"},
        new String[] {"oldPasswordBox", INPUT_PASSWORD, PARAM_OLD_PASSWORD, "100"});
    table.addChild("tr");
    row = table.addChild("tr");
    cell = row.addChild("td");
    cell.addChild(TAG_LABEL, "for", "newPasswordBox", l10nSec("newPasswordLabel"));
    cell = row.addChild("td");
    cell.addChild(
        TAG_INPUT,
        new String[] {"id", ATTR_TYPE, ATTR_NAME, "size"},
        new String[] {"newPasswordBox", INPUT_PASSWORD, PARAM_MASTER_PASSWORD, "100"});
    row = table.addChild("tr");
    cell = row.addChild("td");
    cell.addChild(TAG_LABEL, "for", CONFIRM_PASSWORD_BOX_ID, l10nSec("confirmNewPasswordLabel"));
    cell = row.addChild("td");
    cell.addChild(
        TAG_INPUT,
        new String[] {"id", ATTR_TYPE, ATTR_NAME, "size"},
        new String[] {
          CONFIRM_PASSWORD_BOX_ID, INPUT_PASSWORD, PARAM_CONFIRM_MASTER_PASSWORD, "100"
        });
    HTMLNode p = inner.addChild("p");
    p.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, "changePassword", l10nSec("changePasswordButton")});
  }

  private static final String PATH_PROPERTY = "network.crypta.seclevels.path";
  static final String PATH = System.getProperty(PATH_PROPERTY, "/seclevels/");

  /**
   * Returns the already-resolved routing path used by this toadlet class.
   *
   * <p>This accessor exposes the same cached value that backs {@link #path()}, allowing callers to
   * build links and form targets that stay aligned with the registered handler even if the backing
   * system property changes later in process lifetime.
   *
   * @return canonical cached toadlet path, resolved during class initialization.
   */
  public static String resolvedPath() {
    return PATH;
  }

  /**
   * Returns the routing path for this toadlet. The value comes from the {@code
   * network.crypta.seclevels.path} system property when set, otherwise falls back to {@code
   * /seclevels/}. Callers should treat the path as a stable identifier for hyperlink generation and
   * redirect targets; it is not recalculated per request.
   *
   * @return canonical toadlet path, guaranteed non-null and suitable for HTTP routing.
   */
  @Override
  public String path() {
    return PATH;
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("ConfigToadlet." + string);
  }

  private static String l10nSec(String key) {
    return NodeL10n.getBase().getString("SecurityLevels." + key);
  }

  private static String l10nSec(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("SecurityLevels." + key, pattern, value);
  }

  void sendPasswordFileCorruptedPage(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    HTMLNode page =
        sendPasswordFileCorruptedPageInner(ctx, securitySnapshot().masterPasswordFilePath());
    writeHTMLReply(ctx, 500, "Internal Server Error", page.generate());
  }

  /**
   * Embeds a corruption notice into the first-time wizard when the master password file cannot be
   * parsed. The helper supplies localized strings and existing page scaffolding; this method
   * appends an infobox that identifies the affected file and offers navigation links back to safer
   * entry points so the user can decide whether to retry, reset, or exit the wizard.
   *
   * @param helper wizard helper responsible for adding content to the current wizard step.
   * @param masterPasswordFile an absolute path to the corrupted master password file displayed to
   *     the user for clarity.
   */
  public static void sendPasswordFileCorruptedPageInner(
      PageHelper helper, String masterPasswordFile) {
    HTMLNode contentNode = helper.getPageContent(l10nSec(PASSWORD_FILE_CORRUPTED_TITLE_KEY));
    HTMLNode infoBox =
        helper
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(PASSWORD_FILE_CORRUPTED_TITLE_KEY),
                contentNode,
                PASSWORD_ERROR_CLASS,
                false)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    sendPasswordFileCorruptedPageInner(infoBox, masterPasswordFile);
  }

  /**
   * Creates a standalone page warning that the master password file appears corrupted. The page is
   * built through the provided context, includes localized text explaining the failure, and adds
   * navigation back to the security levels view so administrators can choose an appropriate
   * recovery path. This helper leaves HTTP status selection to the caller by returning the page
   * node instead of writing the response directly.
   *
   * @param ctx toadlet context that provides localization and HTML helper utilities.
   * @param masterPasswordFile absolute path to the corrupted file to display for diagnostic use.
   * @return HTML node representing the fully composed page, ready for serialization.
   */
  public static HTMLNode sendPasswordFileCorruptedPageInner(
      ToadletContext ctx, String masterPasswordFile) {
    PageNode page = ctx.getPageMaker().getPageNode(l10nSec(PASSWORD_FILE_CORRUPTED_TITLE_KEY), ctx);
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode contentNode = page.getContentNode();
    HTMLNode infoBox =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(PASSWORD_FILE_CORRUPTED_TITLE_KEY),
                contentNode,
                PASSWORD_ERROR_CLASS,
                false)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    sendPasswordFileCorruptedPageInner(infoBox, masterPasswordFile);
    return pageNode;
  }

  /**
   * Send a page asking what to do when the master password file has been corrupted.
   *
   * @param infoBox containing more information. Will be added to.
   * @param masterPasswordFile path to a master password file
   */
  private static void sendPasswordFileCorruptedPageInner(
      HTMLNode infoBox, String masterPasswordFile) {
    infoBox.addChild("p", l10nSec("passwordFileCorrupted", "file", masterPasswordFile));

    addHomepageLink(infoBox);

    addBackToSeclevelsLink(infoBox);
  }

  /**
   * Sends a retry page after the user entered a wrong master password. The page contains an error
   * infobox, re-displays the password prompt, and links back to the home page to avoid dead ends.
   * No configuration is changed here; it simply gives the user another chance to authenticate.
   *
   * @param ctx toadlet context used to localize strings, build the form, and emit the response.
   * @throws IOException if HTML serialization or response writing fails.
   * @throws ToadletContextClosedException if the connection closes before the response completes.
   */
  private void sendPasswordFormPage(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10nSec(PASSWORD_PAGE_TITLE_KEY), ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(PASSWORD_WRONG_TITLE_KEY),
                contentNode,
                PASSWORD_ERROR_CLASS,
                false)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    generatePasswordFormPage(
        new PasswordFormOptions(true, false, false, false, null, null),
        ctx.getContainer(),
        content);

    addHomepageLink(content);

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Sends a page prompting the user to provide or confirm the master password when upgrading
   * security or when a mismatch occurred. It highlights mismatched entries, preserves the chosen
   * threat level through hidden fields, and guides the user back to the security levels screen on
   * completion.
   *
   * @param ctx toadlet context used to construct localized content and deliver the HTML response.
   * @param threatLevel name of the physical threat level currently being configured; may be null
   *     when no specific level needs to be preserved.
   * @throws IOException if an error occurs while generating or sending the HTML page.
   * @throws ToadletContextClosedException if the client disconnects before the reply is sent.
   */
  private void sendPasswordPageMismatch(ToadletContext ctx, String threatLevel)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10nSec(PASSWORD_PAGE_TITLE_KEY), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode content =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_ERROR,
                l10nSec(SET_PASSWORD_TITLE_KEY),
                contentNode,
                PASSWORD_ERROR_CLASS,
                false)
            .addChild(TAG_DIV, ATTR_CLASS, CLASS_INFOBOX_CONTENT);
    content.addChild("p", l10nSec("passwordsDoNotMatch"));
    generatePasswordFormPage(
        new PasswordFormOptions(false, false, false, true, threatLevel, null),
        ctx.getContainer(),
        content);
    addBackToSeclevelsLink(content);
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Renders the shared password form used throughout the wizard and security levels flows. This
   * overload attaches the form to the supplied {@code content} node and directs submissions either
   * to the first-time wizard or this toadlet, depending on the {@code forFirstTimeWizard} flag. It
   * adds contextual messages for wrong passwords, downgrade decryption, or upgrade confirmation,
   * and preserves physical threat level choices and optional redirect targets via hidden inputs.
   *
   * @param options configuration for rendering the shared password form.
   * @param ctx container used to create the form element with the correct submission endpoint.
   * @param content HTML node that receives explanatory text and the generated form structure.
   */
  public static void generatePasswordFormPage(
      PasswordFormOptions options, ToadletContainer ctx, HTMLNode content) {

    String postTo =
        options.forFirstTimeWizard()
            ? FirstTimeWizardToadlet.TOADLET_URL
            : SecurityLevelsToadlet.PATH;
    HTMLNode form = ctx.addFormChild(content, postTo, MASTER_PASSWORD_FORM);
    generatePasswordFormPage(options, form, content);
  }

  private static void generatePasswordConfirmationForm(HTMLNode formNode) {
    HTMLNode table = formNode.addChild("table", "border", "0");
    HTMLNode row = table.addChild("tr");
    HTMLNode cell = row.addChild("td");
    cell.addChild(TAG_LABEL, "for", PASSWORD_BOX_NAME, l10nSec("passwordLabel"));
    cell = row.addChild("td");
    cell.addChild(
        TAG_INPUT,
        new String[] {"id", ATTR_TYPE, ATTR_NAME, "size"},
        new String[] {PASSWORD_BOX_NAME, INPUT_PASSWORD, PARAM_MASTER_PASSWORD, "100"});
    table.addChild("tr");
    row = table.addChild("tr");
    cell = row.addChild("td");
    cell.addChild(TAG_LABEL, "for", CONFIRM_PASSWORD_BOX_ID, l10nSec("confirmPasswordLabel"));
    cell = row.addChild("td");
    cell.addChild(
        TAG_INPUT,
        new String[] {"id", ATTR_TYPE, ATTR_NAME, "size"},
        new String[] {
          CONFIRM_PASSWORD_BOX_ID, INPUT_PASSWORD, PARAM_CONFIRM_MASTER_PASSWORD, "100"
        });
  }

  /**
   * Populates an existing form node with password controls and contextual messaging. The helper
   * tailors the surrounding {@code content} node to reflect whether the caller is prompting for a
   * downgrade decryption password, an upgrade confirmation, or a retry after failure. Hidden fields
   * can retain the selected physical threat level and redirect the target so follow-up requests
   * remain consistent. Response writing remains the caller's responsibility.
   *
   * @param options configuration for rendering the shared password form.
   * @param formNode form an element that receives inputs, hidden fields, and the submitting
   *     control.
   * @param content container node used to display descriptive text adjacent to the form.
   */
  public static void generatePasswordFormPage(
      PasswordFormOptions options, HTMLNode formNode, HTMLNode content) {
    if (options.forDowngrade() && !options.wasWrong()) {
      content.addChild("#", l10nSec("passwordForDecrypt"));
    } else if (options.wasWrong()) {
      content.addChild("#", l10nSec("passwordWrong"));
    } else if (options.forUpgrade()) {
      content.addChild("#", l10nSec("setPassword"));
    } else {
      content.addChild("#", l10nSec("enterPassword"));
    }

    // Creates a table for the password prompt and the confirmation box.
    if (options.forUpgrade()) {
      generatePasswordConfirmationForm(formNode);
    } else {
      formNode.addChild(TAG_LABEL, "for", PASSWORD_BOX_NAME, l10nSec("passwordLabel"));
      formNode.addChild(
          TAG_INPUT,
          new String[] {"id", ATTR_TYPE, ATTR_NAME, "size"},
          new String[] {PASSWORD_BOX_NAME, INPUT_PASSWORD, PARAM_MASTER_PASSWORD, "100"});
    }

    if (options.physicalSecurityLevel() != null) {
      formNode.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_HIDDEN, PARAM_PHYSICAL_THREAT_LEVEL, options.physicalSecurityLevel()
          });
      formNode.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_HIDDEN, PARAM_SECLEVELS, "true"});
    }
    if (options.redirect() != null) {
      formNode.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_HIDDEN, PARAM_REDIRECT, options.redirect()});
    }
    formNode.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_VALUE},
        new String[] {INPUT_SUBMIT, l10nSec("passwordSubmit")});
  }
}
