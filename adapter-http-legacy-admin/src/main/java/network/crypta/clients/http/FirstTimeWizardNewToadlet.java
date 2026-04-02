package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.support.Fields;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JavaScript-based First-Time-Wizard toadlet that guides new nodes through the minimum secure setup
 * steps. The regular wizard redirects here when both FProxy and the user's browser have JavaScript
 * enabled so that the richer, single-page flow can be used.
 *
 * <p>This toadlet orchestrates the entire first-run experience using one detached runtime port: it
 * renders the shared template, validates request-local input, and delegates the remaining daemon
 * reads and writes to {@link FirstTimeWizardPort}. Instances are not thread-safe on their own but
 * are typically created once and invoked by the toadlet container on request threads.
 *
 * <ul>
 *   <li>Collects threat-level and bandwidth choices through the shared HTML template system.
 *   <li>Validates submitted values against detached runtime bounds and suggested defaults.
 *   <li>Redirects to {@link WelcomeToadlet#ROOT_PATH} after successful completion.
 * </ul>
 *
 * @see WebTemplateToadlet
 * @see WelcomeToadlet
 * @see FirstTimeWizardPort
 */
public class FirstTimeWizardNewToadlet extends WebTemplateToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(FirstTimeWizardNewToadlet.class);

  /**
   * Public URL prefix under which the wizard is mounted; used by {@link #path()} and redirects from
   * the legacy flow. The value is stable, so bookmarks and deep links continue to work across
   * releases.
   */
  public static final String TOADLET_URL = "/wiz/";

  private final FirstTimeWizardPort wizardPort;

  private static final String L10N_PREFIX = "FirstTimeWizardToadlet.";

  private static final long KIB = 1024L;
  private static final long MAX_INT_BACKED_BANDWIDTH_LIMIT_BYTES = Integer.MAX_VALUE;

  private static final String DOWNLOAD_LIMIT_ERROR_KEY = "downloadLimitError";

  private static final String UPLOAD_LIMIT_ERROR_KEY = "uploadLimitError";

  private static final String STORAGE_LIMIT_ERROR_KEY = "storageLimitError";

  private static final String PASSWORD_ERROR_KEY = "passwordError";

  private static final String CHECKED_VALUE = "checked";

  FirstTimeWizardNewToadlet(HighLevelSimpleClient client, FirstTimeWizardPort wizardPort) {
    super(client);
    this.wizardPort = Objects.requireNonNull(wizardPort, "wizardPort");
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

    showForm(ctx, new FormModel(wizardPort.snapshot()).toModel());
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
   * method performs no partial saves on invalid input, keeping the configuration atomic.
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

    FirstTimeWizardSnapshot snapshot = wizardPort.snapshot();
    FormModel formModel = new FormModel(request, snapshot);

    if (formModel.isValid()) {
      wizardPort.applySubmission(formModel.toSubmission());
      super.writeTemporaryRedirect(ctx, "Wizard complete", WelcomeToadlet.ROOT_PATH);
      return;
    }

    // form model not valid
    showForm(ctx, formModel.toModel());
  }

  private void showForm(ToadletContext ctx, Map<String, Object> model)
      throws IOException, ToadletContextClosedException {
    model.put("formPassword", ctx.getFormPassword());
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

  private static final class FormModel {
    private final boolean passwordAlreadySet;
    private final String minStorageLimit;
    private final long minStorageLimitBytes;
    private final String maxStorageLimit;
    private final long maxStorageLimitBytes;
    private final long minBandwidthKiB;
    private final long maxUploadLimitKiB;
    private final String minBandwidthMonthlyLimit;
    private final String downloadLimitDetected;
    private final String uploadLimitDetected;

    private String knowSomeone = "";

    private String connectToStrangers = "";

    private String haveMonthlyLimit = "";

    private String downloadLimit = "10240";

    private String uploadLimit = "1024";

    private String bandwidthMonthlyLimit = "500";

    private final String storageLimit;

    private String setPassword = "";

    private String password = "";

    private final Map<String, String> errors = new HashMap<>();

    FormModel(FirstTimeWizardSnapshot snapshot) {
      this.passwordAlreadySet = snapshot.passwordAlreadySet();
      this.storageLimit = snapshot.initialStorageLimitGiB();
      this.minStorageLimit = snapshot.minStorageLimitGiB();
      this.minStorageLimitBytes = snapshot.minStorageLimitBytes();
      this.maxStorageLimit = snapshot.maxStorageLimitGiB();
      this.maxStorageLimitBytes = snapshot.maxStorageLimitBytes();
      this.minBandwidthKiB = snapshot.minBandwidthKiB();
      this.maxUploadLimitKiB = snapshot.maxUploadLimitKiB();
      this.minBandwidthMonthlyLimit = snapshot.minBandwidthMonthlyLimitGiB();
      this.downloadLimitDetected = snapshot.detectedDownloadLimitKiB();
      this.uploadLimitDetected = snapshot.detectedUploadLimitKiB();
      if (!downloadLimitDetected.isEmpty()) {
        downloadLimit = downloadLimitDetected;
      }
      if (!uploadLimitDetected.isEmpty()) {
        uploadLimit = uploadLimitDetected;
      }
    }

    FormModel(HTTPRequest request, FirstTimeWizardSnapshot snapshot) {
      this.passwordAlreadySet = snapshot.passwordAlreadySet();
      this.minStorageLimit = snapshot.minStorageLimitGiB();
      this.minStorageLimitBytes = snapshot.minStorageLimitBytes();
      this.maxStorageLimit = snapshot.maxStorageLimitGiB();
      this.maxStorageLimitBytes = snapshot.maxStorageLimitBytes();
      this.minBandwidthKiB = snapshot.minBandwidthKiB();
      this.maxUploadLimitKiB = snapshot.maxUploadLimitKiB();
      this.minBandwidthMonthlyLimit = snapshot.minBandwidthMonthlyLimitGiB();
      this.downloadLimitDetected = snapshot.detectedDownloadLimitKiB();
      this.uploadLimitDetected = snapshot.detectedUploadLimitKiB();
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
            downloadLimit.isEmpty() ? 0 : Fields.parseLong(downloadLimit + "KiB");
        if (parsedDownloadLimit > MAX_INT_BACKED_BANDWIDTH_LIMIT_BYTES) {
          throw new NumberFormatException("value exceeds the maximum supported bandwidth limit");
        }
        if (parsedDownloadLimit < minBandwidthKiB * KIB) {
          errors.put(
              DOWNLOAD_LIMIT_ERROR_KEY,
              l10n("valid.downloadLimit", Long.toString(minBandwidthKiB)));
        }
      } catch (NumberFormatException e) {
        errors.put(
            DOWNLOAD_LIMIT_ERROR_KEY,
            FirstTimeWizardNewToadlet.l10n("valid.number.prefix.downloadLimit")
                + " "
                + e.getMessage());
      }
    }

    private void validateUploadLimit() {
      try {
        long parsedUploadLimit = uploadLimit.isEmpty() ? 0 : Fields.parseLong(uploadLimit + "KiB");
        if (parsedUploadLimit < minBandwidthKiB * KIB) {
          errors.put(
              UPLOAD_LIMIT_ERROR_KEY, l10n("valid.uploadLimit", Long.toString(minBandwidthKiB)));
        }
        if (maxUploadLimitKiB * KIB < parsedUploadLimit) {
          errors.put(
              UPLOAD_LIMIT_ERROR_KEY,
              l10n("valid.uploadLimitMax", Long.toString(maxUploadLimitKiB)));
        }
      } catch (NumberFormatException e) {
        errors.put(
            UPLOAD_LIMIT_ERROR_KEY,
            FirstTimeWizardNewToadlet.l10n("valid.number.prefix.uploadLimit")
                + " "
                + e.getMessage());
      }
    }

    private void validateMonthlyLimit() {
      try {
        long monthlyLimitValue =
            bandwidthMonthlyLimit.isEmpty() ? 0 : Fields.parseLong(bandwidthMonthlyLimit + "GiB");
        long minMonthlyLimitValue = Fields.parseLong(minBandwidthMonthlyLimit + "GiB");
        if (monthlyLimitValue < minMonthlyLimitValue) {
          errors.put(
              "bandwidthMonthlyLimitError",
              l10n("valid.bandwidthMonthlyLimit", minBandwidthMonthlyLimit));
        }
      } catch (NumberFormatException e) {
        errors.put(
            "bandwidthMonthlyLimitError",
            FirstTimeWizardNewToadlet.l10n("valid.number.prefix.bandwidthMonthlyLimit")
                + " "
                + e.getMessage());
      }
    }

    private void validateStorageLimit() {
      try {
        long storageLimitValue =
            storageLimit.isEmpty() ? 0 : Fields.parseLong(storageLimit + "GiB");
        if (storageLimitValue < minStorageLimitBytes) {
          errors.put(
              STORAGE_LIMIT_ERROR_KEY,
              NodeL10n.getBase().getString("Node.invalidMinStoreSizeWithCaches"));
        } else if (storageLimitValue > maxStorageLimitBytes) {
          errors.put(
              STORAGE_LIMIT_ERROR_KEY,
              NodeL10n.getBase().getString("Node.invalidMaxStoreSize", maxStorageLimit));
        }
      } catch (NumberFormatException e) {
        errors.put(
            STORAGE_LIMIT_ERROR_KEY,
            FirstTimeWizardNewToadlet.l10n("valid.number.prefix.storageLimit")
                + " "
                + e.getMessage());
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

    private Map<String, Object> toModel() {
      HashMap<String, Object> model = new HashMap<>();
      model.put("knowSomeone", !knowSomeone.isEmpty() ? CHECKED_VALUE : "");
      model.put("connectToStrangers", !connectToStrangers.isEmpty() ? CHECKED_VALUE : "");
      model.put("haveMonthlyLimit", !haveMonthlyLimit.isEmpty() ? CHECKED_VALUE : "");
      model.put("downloadLimit", downloadLimit);
      model.put("uploadLimit", uploadLimit);
      model.put("bandwidthMonthlyLimit", bandwidthMonthlyLimit);
      model.put("minBandwidthMonthlyLimit", minBandwidthMonthlyLimit);
      model.put("storageLimit", storageLimit);
      model.put("minStorageLimit", minStorageLimit);
      if (!passwordAlreadySet) {
        model.put("setPassword", !setPassword.isEmpty() ? CHECKED_VALUE : "");
      }
      model.put("isPasswordAlreadySet", passwordAlreadySet);
      model.put(
          "downloadLimitDetected",
          !downloadLimitDetected.isEmpty()
              ? downloadLimitDetected
              : FirstTimeWizardNewToadlet.l10n(
                  "bandwidthCommonInternetConnectionSpeedsDetectedUnavailable"));
      model.put(
          "uploadLimitDetected",
          !uploadLimitDetected.isEmpty()
              ? uploadLimitDetected
              : FirstTimeWizardNewToadlet.l10n(
                  "bandwidthCommonInternetConnectionSpeedsDetectedUnavailable"));

      model.put("errors", errors);

      return model;
    }

    private FirstTimeWizardSubmission toSubmission() {
      return new FirstTimeWizardSubmission(
          !knowSomeone.isEmpty(),
          !connectToStrangers.isEmpty(),
          !haveMonthlyLimit.isEmpty(),
          downloadLimit,
          uploadLimit,
          bandwidthMonthlyLimit,
          storageLimit,
          !setPassword.isEmpty(),
          password);
    }

    private static String l10n(String key, String value) {
      return NodeL10n.getBase().getString(L10N_PREFIX + key, value);
    }
  }
}
