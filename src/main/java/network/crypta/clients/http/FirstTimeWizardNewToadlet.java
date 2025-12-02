package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.clients.http.wizardsteps.BandwidthManipulator;
import network.crypta.clients.http.wizardsteps.DATASTORE_SIZE;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.config.Option;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.support.Fields;
import network.crypta.support.IllegalValueException;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.DatastoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JavaScript-based First-Time-Wizard toadlet that guides new nodes through the minimum secure setup
 * steps. The regular wizard redirects here when both FProxy and the user's browser have JavaScript
 * enabled so that the richer, single-page flow can be used.
 *
 * <p>This toadlet orchestrates the entire first-run experience: it detects recommended bandwidth
 * limits, proposes datastore sizes, optionally enforces a master password based on the configured
 * physical threat level, and persists the resulting configuration. All rendering is delegated to
 * the shared web template system, with localized strings loaded via {@link NodeL10n} and per-page
 * state stored in a simple model map.
 *
 * <p>Instances are tied to a {@link NodeClientCore} and {@link Config}. They are not thread-safe on
 * their own but are typically created once and invoked by the toadlet container on request threads.
 * Error handling is intentionally defensive: invalid input re-renders the form with contextual
 * messages, while unexpected failures are surfaced through structured logging.
 *
 * <ul>
 *   <li>Collects threat-level choices and optionally enforces a master password.
 *   <li>Suggests datastore and bandwidth limits based on detected capabilities.
 *   <li>Redirects to {@link WelcomeToadlet#PATH} after successful completion.
 * </ul>
 *
 * @see WebTemplateToadlet
 * @see WelcomeToadlet
 */
public class FirstTimeWizardNewToadlet extends WebTemplateToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(FirstTimeWizardNewToadlet.class);

  /**
   * Public URL prefix under which the wizard is mounted; used by {@link #path()} and redirects from
   * the legacy flow. The value is stable so bookmarks and deep links continue to work across
   * releases.
   */
  public static final String TOADLET_URL = "/wiz/";

  private static final long MIN_STORAGE_LIMIT =
      Node.MIN_STORE_SIZE * 5 / 4; // min store size + 10% for client cache + 10% for slashdot cache

  private final NodeClientCore core;

  private final Config config;

  private static final String L10N_PREFIX = "FirstTimeWizardToadlet.";

  private static final int KIB = 1024;

  private static final String DOWNLOAD_LIMIT_ERROR_KEY = "downloadLimitError";

  private static final String UPLOAD_LIMIT_ERROR_KEY = "uploadLimitError";

  private static final String STORAGE_LIMIT_ERROR_KEY = "storageLimitError";

  private static final String PASSWORD_ERROR_KEY = "passwordError";

  private static final String CHECKED_VALUE = "checked";

  private static final String UNEXPECTED_ERROR_MESSAGE = "Should not happen, please report! {}";

  private boolean isPasswordAlreadySet;

  FirstTimeWizardNewToadlet(HighLevelSimpleClient client, NodeClientCore core, Config config) {
    super(client);
    this.core = core;
    this.config = config;
  }

  /**
   * Renders the first-time wizard landing page in response to a GET request.
   *
   * <p>The method first emits a debug log when a URI is supplied, then enforces the container's
   * full-access check to prevent partially initialized users from progressing. It marks whether a
   * master password is already required based on the current physical threat level and finally
   * delegates to {@link #showForm(ToadletContext, Map)} with a freshly detected model. The handler
   * is idempotent and safe to repeat if the browser reloads the page.
   *
   * @param uri the absolute request target as received by the toadlet dispatcher; may be {@code
   *     null} when upstream routing omits it
   * @param request the parsed HTTP request object; used for side effects only during context
   *     validation
   * @param ctx the active toadlet context that provides access checks and rendering helpers
   * @throws ToadletContextClosedException if the client disconnects before the response is written
   * @throws IOException if building or streaming the HTML page fails
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (LOG.isDebugEnabled() && uri != null) {
      LOG.debug("Handling GET for {}", uri);
    }
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    // if threat level is high, the password must already be set: user is running the wizard again?
    isPasswordAlreadySet =
        core.getNode().getSecurityLevels().getPhysicalThreatLevel()
            == SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH;
    showForm(ctx, new FormModel().toModel());
  }

  /**
   * Processes a submitted wizard form and either persists the settings or re-renders the page with
   * validation feedback.
   *
   * <p>The handler applies the same access gate as {@link #handleMethodGET(URI, HTTPRequest,
   * ToadletContext)} and logs the incoming URI when debug logging is enabled. Inputs are captured
   * in a {@code FormModel}, validated for bandwidth, datastore size, and optional password rules,
   * then saved when no errors are present. A successful submission triggers a temporary redirect to
   * the welcome page; otherwise the form is displayed again with localized error messages. The
   * method performs no partial saves on invalid input, keeping configuration atomic.
   *
   * @param uri the original request URI supplied by the toadlet container
   * @param request the request body carrying the form fields to validate and apply
   * @param ctx the current toadlet context used for security checks and HTML rendering
   * @throws ToadletContextClosedException if the client connection closes before the response is
   *     written
   * @throws IOException if writing the HTML response or redirect fails
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (LOG.isDebugEnabled() && uri != null) {
      LOG.debug("Handling POST for {}", uri);
    }
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    FormModel formModel = new FormModel(request);

    if (formModel.isValid()) {
      formModel.save();
      super.writeTemporaryRedirect(ctx, "Wizard complete", WelcomeToadlet.ROOT_PATH);
    }

    // form model not valid
    showForm(ctx, formModel.toModel());
  }

  private void showForm(ToadletContext ctx, Map<String, Object> model)
      throws IOException, ToadletContextClosedException {
    model.put("formPassword", core.getToadletContainer().getFormPassword());
    PageNode page =
        ctx.getPageMaker()
            .getPageNode(
                l10n("homepageTitle"),
                ctx,
                new PageMaker.RenderParameters().renderNavigationLinks(false).renderStatus(false));
    page.addCustomStyleSheet("/static/first-time-wizard.css");
    addChild(page.getContentNode(), "first-time-wizard", model, L10N_PREFIX);
    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Returns the public HTTP path where this toadlet is registered.
   *
   * <p>The path is static and aligns with {@link #TOADLET_URL}, enabling callers to reference the
   * wizard entry point when composing navigation links or redirects. The container invokes this to
   * mount the toadlet under the shared FProxy namespace.
   *
   * @return the URL prefix for the JavaScript-first wizard flow, always {@value #TOADLET_URL}
   */
  @Override
  public String path() {
    return TOADLET_URL;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  private static String l10n(String key, String value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, value);
  }

  private class FormModel {

    private String knowSomeone = "";

    private String connectToStrangers = "";

    private String haveMonthlyLimit = "";

    private String downloadLimit = "10240";

    private String uploadLimit = "1024";

    private String bandwidthMonthlyLimit = "500";

    private final String storageLimit;

    private final String minStorageLimit =
        String.format(Locale.ENGLISH, "%.2f", (float) MIN_STORAGE_LIMIT / DatastoreUtil.ONE_GIB);

    private String setPassword = "";

    private String password = "";

    private String downloadLimitDetected;

    private String uploadLimitDetected;

    private final Map<String, String> errors = new HashMap<>();

    FormModel() {
      float storage = 100;
      Option<Long> sizeOption =
          network.crypta.config.Config.longOption(config.get("node"), "storeSize");
      if (!sizeOption.isDefault()) {
        Option<Long> clientCacheSizeOption =
            network.crypta.config.Config.longOption(config.get("node"), "clientCacheSize");
        Option<Long> slashdotCacheSizeOption =
            network.crypta.config.Config.longOption(config.get("node"), "slashdotCacheSize");
        long totalSize =
            sizeOption.getValue()
                + clientCacheSizeOption.getValue()
                + slashdotCacheSizeOption.getValue();
        storage = (float) totalSize / DatastoreUtil.ONE_GIB;
      } else {
        long autodetectedDatastoreSize = DatastoreUtil.autodetectDatastoreSize(core, config);
        if (autodetectedDatastoreSize > 0) {
          storage = (float) autodetectedDatastoreSize / DatastoreUtil.ONE_GIB;
        }
      }
      // format with English locale to ensure that the decimal point is "." as required for the form
      // value
      storageLimit = String.format(Locale.ENGLISH, "%.2f", storage);

      detectBandwidthLimit();
      if (downloadLimitDetected != null) {
        downloadLimit = downloadLimitDetected;
      }
      if (uploadLimitDetected != null) {
        uploadLimit = uploadLimitDetected;
      }
    }

    FormModel(HTTPRequest request) {
      knowSomeone = request.getPartAsStringFailsafe("knowSomeone", 20);
      connectToStrangers = request.getPartAsStringFailsafe("connectToStrangers", 20);
      haveMonthlyLimit = request.getPartAsStringFailsafe("haveMonthlyLimit", 20);
      downloadLimit = request.getPartAsStringFailsafe("downLimit", 100);
      uploadLimit = request.getPartAsStringFailsafe("upLimit", 100);
      bandwidthMonthlyLimit = request.getPartAsStringFailsafe("monthlyLimit", 100);
      storageLimit = request.getPartAsStringFailsafe("storage", 100);
      setPassword = request.getPartAsStringFailsafe("setPassword", 20);
      password =
          request.getPartAsStringFailsafe(
              "password", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH + 1);
      String passwordConfirmation =
          request.getPartAsStringFailsafe(
              "confirmPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);

      validateInputs(passwordConfirmation);
    }

    private void validateInputs(String passwordConfirmation) {
      if (haveMonthlyLimit.isEmpty()) {
        validateBandwidthLimits();
      } else {
        validateMonthlyLimit();
      }
      validateStorageLimit();
      validatePassword(passwordConfirmation);
    }

    private void validateBandwidthLimits() {
      validateDownloadLimit();
      validateUploadLimit();
    }

    private void validateDownloadLimit() {
      try {
        long parsedDownloadLimit =
            downloadLimit.isEmpty() ? 0 : Fields.parseInt(downloadLimit + "KiB");
        if (parsedDownloadLimit < Node.getMinimumBandwidth()) {
          errors.put(
              DOWNLOAD_LIMIT_ERROR_KEY,
              l10n("valid.downloadLimit", Integer.toString(Node.getMinimumBandwidth() / KIB)));
        }
      } catch (NumberFormatException e) {
        errors.put(
            DOWNLOAD_LIMIT_ERROR_KEY,
            l10n("valid.number.prefix.downloadLimit") + " " + e.getMessage());
      }
    }

    private void validateUploadLimit() {
      try {
        long parsedUploadLimit = uploadLimit.isEmpty() ? 0 : Fields.parseInt(uploadLimit + "KiB");
        if (parsedUploadLimit < Node.getMinimumBandwidth()) {
          errors.put(
              UPLOAD_LIMIT_ERROR_KEY,
              l10n("valid.uploadLimit", Integer.toString(Node.getMinimumBandwidth() / KIB)));
        }
        int nanosInSecond = (int) SECONDS.toNanos(1);
        if (nanosInSecond < parsedUploadLimit) { // see Node set outputBandwidthLimit
          errors.put(
              UPLOAD_LIMIT_ERROR_KEY,
              l10n("valid.uploadLimitMax", Integer.toString(nanosInSecond / KIB)));
        }
      } catch (NumberFormatException e) {
        errors.put(
            UPLOAD_LIMIT_ERROR_KEY, l10n("valid.number.prefix.uploadLimit") + " " + e.getMessage());
      }
    }

    private void validateMonthlyLimit() {
      try {
        double monthlyLimitValue = 0;
        if (!bandwidthMonthlyLimit.isEmpty()) {
          monthlyLimitValue = Double.parseDouble(bandwidthMonthlyLimit);
        }
        if (monthlyLimitValue < BandwidthLimit.minMonthlyLimit) {
          errors.put(
              "bandwidthMonthlyLimitError",
              l10n(
                  "valid.bandwidthMonthlyLimit", "%.2f".formatted(BandwidthLimit.minMonthlyLimit)));
        }
      } catch (NumberFormatException e) {
        errors.put(
            "bandwidthMonthlyLimitError",
            l10n("valid.number.prefix.bandwidthMonthlyLimit") + " " + e.getMessage());
      }
    }

    private void validateStorageLimit() {
      try {
        long storageLimitValue =
            storageLimit.isEmpty() ? 0 : Fields.parseLong(storageLimit + "GiB");
        if (storageLimitValue
            < MIN_STORAGE_LIMIT) { // min store size + 10% for client cache + 10% for slashdot cache
          errors.put(
              STORAGE_LIMIT_ERROR_KEY,
              NodeL10n.getBase().getString("Node.invalidMinStoreSizeWithCaches"));
        } else {
          long maxDatastoreSize = DatastoreUtil.maxDatastoreSize();
          if (storageLimitValue > maxDatastoreSize) {
            errors.put(
                STORAGE_LIMIT_ERROR_KEY,
                NodeL10n.getBase()
                    .getString(
                        "Node.invalidMaxStoreSize",
                        "%.2f".formatted((float) maxDatastoreSize / DatastoreUtil.ONE_GIB)));
          }
        }
      } catch (NumberFormatException e) {
        errors.put(
            STORAGE_LIMIT_ERROR_KEY,
            l10n("valid.number.prefix.storageLimit") + " " + e.getMessage());
      }
    }

    private void validatePassword(String passwordConfirmation) {
      if (setPassword.isEmpty()) {
        return;
      }
      if (password.isEmpty()) {
        errors.put(
            PASSWORD_ERROR_KEY,
            NodeL10n.getBase().getString("SecurityLevels.passwordNotZeroLength"));
      }
      if (password.length() > SecurityLevelsToadlet.MAX_PASSWORD_LENGTH) {
        errors.put(
            PASSWORD_ERROR_KEY, NodeL10n.getBase().getString("SecurityLevels.passwordTooLong"));
      }
      if (!password.equals(passwordConfirmation)) {
        errors.put(
            PASSWORD_ERROR_KEY, NodeL10n.getBase().getString("SecurityLevels.passwordsDoNotMatch"));
      }
    }

    private boolean isValid() {
      return errors.isEmpty();
    }

    private void detectBandwidthLimit() {
      try {
        BandwidthLimit detected =
            BandwidthManipulator.detectBandwidthLimits(
                core.getNode().getIpDetector().getBandwidthIndicator());

        // Detected limits reasonable; add half of both as recommended option.
        downloadLimitDetected = Long.toString(detected.downBytes / 2 / KIB);
        uploadLimitDetected = Long.toString(detected.upBytes / 2 / KIB);
      } catch (PluginNotFoundException | IllegalValueException e) {
        LOG.info(e.getMessage(), e);
      }
    }

    private Map<String, Object> toModel() {
      HashMap<String, Object> model = new HashMap<>();
      model.put("knowSomeone", !knowSomeone.isEmpty() ? CHECKED_VALUE : "");
      model.put("connectToStrangers", !connectToStrangers.isEmpty() ? CHECKED_VALUE : "");
      model.put("haveMonthlyLimit", !haveMonthlyLimit.isEmpty() ? CHECKED_VALUE : "");
      model.put("downloadLimit", downloadLimit);
      model.put("uploadLimit", uploadLimit);
      model.put("bandwidthMonthlyLimit", bandwidthMonthlyLimit);
      model.put("minBandwidthMonthlyLimit", "%.2f".formatted(BandwidthLimit.minMonthlyLimit));
      model.put("storageLimit", storageLimit);
      model.put("minStorageLimit", minStorageLimit);
      if (!isPasswordAlreadySet) {
        model.put("setPassword", !setPassword.isEmpty() ? CHECKED_VALUE : "");
      }
      model.put("isPasswordAlreadySet", isPasswordAlreadySet);

      if (downloadLimitDetected == null || uploadLimitDetected == null) {
        detectBandwidthLimit();
      }
      model.put(
          "downloadLimitDetected",
          downloadLimitDetected != null
              ? downloadLimitDetected
              : l10n("bandwidthCommonInternetConnectionSpeedsDetectedUnavailable"));
      model.put(
          "uploadLimitDetected",
          uploadLimitDetected != null
              ? uploadLimitDetected
              : l10n("bandwidthCommonInternetConnectionSpeedsDetectedUnavailable"));

      model.put("errors", errors);

      return model;
    }

    private void save() {
      if (knowSomeone.isEmpty()) {
        // Opennet + Darknet (possible)
        core.getNode()
            .getSecurityLevels()
            .setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
      } else {
        if (connectToStrangers.isEmpty()) {
          // Darknet
          core.getNode()
              .getSecurityLevels()
              .setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.HIGH);
        } else {
          // Opennet + Darknet
          core.getNode()
              .getSecurityLevels()
              .setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
        }
      }

      try {
        if (haveMonthlyLimit.isEmpty()) { // save download & uploadLimit
          config.get("node").set("inputBandwidthLimit", downloadLimit + "KiB");
          config.get("node").set("outputBandwidthLimit", uploadLimit + "KiB");
        } else { // save bandwidthMonthlyLimit
          BandwidthLimit bandwidth =
              new BandwidthLimit(Fields.parseLong(bandwidthMonthlyLimit + "GiB"));
          config.get("node").set("inputBandwidthLimit", Long.toString(bandwidth.downBytes));
          config.get("node").set("outputBandwidthLimit", Long.toString(bandwidth.upBytes));
        }
      } catch (ConfigException e) {
        LOG.error(UNEXPECTED_ERROR_MESSAGE, e, e);
      }

      DATASTORE_SIZE.setDatastoreSize(storageLimit + "GiB", config, this);

      if (!isPasswordAlreadySet) {
        try {
          if (setPassword.isEmpty()) { // no password protection requested
            core.getNode()
                .getSecurityLevels()
                .setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
            core.getNode().setMasterPassword("", true);
          } else {
            core.getNode()
                .getSecurityLevels()
                .setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
            core.getNode().setMasterPassword(password, true);
          }
        } catch (Node.AlreadySetPasswordException
            | MasterKeysWrongPasswordException
            | MasterKeysFileSizeException
            | IOException e) {
          LOG.error(UNEXPECTED_ERROR_MESSAGE, e, e);
        }
      }

      try {
        config.get("fproxy").set("hasCompletedWizard", true);
      } catch (ConfigException e) {
        LOG.error(UNEXPECTED_ERROR_MESSAGE, e, e);
      }
      core.storeConfig();
    }
  }
}
