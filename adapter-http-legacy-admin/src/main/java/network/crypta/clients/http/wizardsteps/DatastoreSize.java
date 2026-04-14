package network.crypta.clients.http.wizardsteps;

import java.util.Objects;
import java.util.function.LongSupplier;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.DatastoreSizingSupport;
import network.crypta.config.Option;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;

/**
 * Wizard step that renders and applies a datastore sizing choice.
 *
 * <p>This step is used by the HTTP first-time wizard to present a dropdown of sensible datastore
 * sizes based on the local environment. The UI is populated from the current {@link Config} (when
 * present) and from detached runtime snapshot values, including the legacy datastore cap exported
 * through the first-time-wizard port.
 *
 * <p>When the user submits the form, this step updates multiple related configuration keys under
 * {@code node.*} (datastore size and cache sizes) in a consistent way. On the first run it also
 * sets the corresponding {@code *Type} options to the expected defaults. No live daemon reads are
 * performed here beyond consuming the detached wizard snapshot.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Always offers a minimum selectable size of 1&nbsp;GiB in the UI.
 *   <li>Clamps auto-detected and user-selected sizes to a computed maximum.
 *   <li>Derives cache sizes as a fraction of the selection, with explicit caps.
 * </ul>
 *
 * @see FirstTimeWizardToadlet
 * @see Step
 */
public class DatastoreSize implements Step {
  private static final String ATTR_SELECTED = "selected";
  private static final String ATTR_VALUE = "value";
  private static final String TAG_OPTION = "option";

  private final FirstTimeWizardPort wizardPort;
  private final Config config;

  /**
   * Creates a wizard step bound to the detached wizard runtime.
   *
   * <p>The instance is lightweight and holds references to the provided objects; it does not
   * perform any environment detection until {@link #getStep(HTTPRequest, PageHelper)} is called.
   * Callers typically construct this step as part of the wizard flow and reuse it for the lifetime
   * of a single request.
   *
   * @param wizardPort detached wizard runtime used for datastore suggestions and size bounds
   * @param config mutable configuration that receives the selected datastore and cache settings
   */
  public DatastoreSize(FirstTimeWizardPort wizardPort, Config config) {
    this.config = Objects.requireNonNull(config, "config");
    this.wizardPort = Objects.requireNonNull(wizardPort, "wizardPort");
  }

  /**
   * Renders the datastore size selection UI for this wizard step.
   *
   * <p>This method populates a {@code <select>} element with options derived from three sources:
   * the current configured sizes (when non-default), a best-effort auto-detected size (when
   * available), and a set of fixed fallback sizes. The resulting options are additionally bounded
   * by the detached legacy datastore cap from {@link FirstTimeWizardSnapshot} so the page preserves
   * its historical dropdown thresholds without consulting live daemon objects directly.
   *
   * <p>This method does not mutate {@link Config}; it only constructs the HTML content for the
   * current request.
   *
   * @param request the current HTTP request, used only for step context and localization behavior
   * @param helper helper responsible for creating page structure and form elements for the wizard
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    FirstTimeWizardSnapshot snapshot = wizardPort.snapshot();
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("step4Title"));
    HTMLNode bandwidthInfoboxContent =
        helper.getInfobox(
            "infobox-header", WizardL10n.l10n("datastoreSize"), contentNode, null, false);

    bandwidthInfoboxContent.addChild("#", WizardL10n.l10n("datastoreSizeLong"));
    HTMLNode bandwidthForm = helper.addFormChild(bandwidthInfoboxContent, ".", "dsForm");
    HTMLNode result = bandwidthForm.addChild("select", "name", "ds");

    long maxSize = snapshot.legacyMaxStorageLimitBytes();
    long autodetectedSize = snapshot.autodetectedStorageLimitBytes();
    if (maxSize < autodetectedSize) autodetectedSize = maxSize;

    Option<Long> sizeOption = Config.longOption(config.get("node"), "storeSize");
    Option<Long> clientCacheSizeOption = Config.longOption(config.get("node"), "clientCacheSize");
    Option<Long> slashdotCacheSizeOption =
        Config.longOption(config.get("node"), "slashdotCacheSize");
    addDatastoreSizeOptions(
        result,
        maxSize,
        autodetectedSize,
        sizeOption,
        clientCacheSizeOption,
        slashdotCacheSizeOption);

    // Put buttons below dropdown.
    HTMLNode below = bandwidthForm.addChild("div");
    below.addChild(
        "input",
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
    below.addChild(
        "input",
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Applies the datastore size selection submitted for this wizard step.
   *
   * <p>The selected size is read from the {@code ds} form field and passed through the same parsing
   * and validation logic used by {@link #setDatastoreSize(String, Config, LongSupplier)}. When this
   * step is executed as part of the full wizard flow (i.e., not in single-step mode), it advances
   * to the bandwidth step; otherwise it returns the completion step.
   *
   * @param request HTTP request containing the submitted {@code ds} selection and optional flags
   * @return the next wizard step name, suitable for {@code FirstTimeWizardToadlet.WIZARD_STEP}
   */
  @Override
  public String postStep(HTTPRequest request) {
    // drop down options may be 6 chars or fewer, but formatted ones e.g., old value if re-running
    // can
    // be more
    boolean firsttime = !request.isPartSet("singlestep");
    FirstTimeWizardSnapshot snapshot = wizardPort.snapshot();

    DatastoreSizingSupport.setDatastoreSize(
        request.getPartAsStringFailsafe("ds", 20),
        firsttime,
        config,
        snapshot::legacyMaxStorageLimitBytes);
    if (firsttime) {
      return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH.name();
    } else {
      return FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name();
    }
  }

  /**
   * Convenience entry point to apply a datastore size selection to a {@link Config}.
   *
   * <p>This method is intended for first-time configuration flows. It parses the provided size
   * string (as produced by the wizard UI), validates it against the current maximum, and writes the
   * derived {@code node.storeSize}, {@code node.clientCacheSize}, and {@code
   * node.slashdotCacheSize} values. On first-time configuration it also sets the related {@code
   * *Type} options to their expected defaults.
   *
   * @param selectedStoreSize datastore size selection string, typically including a unit suffix
   * @param config configuration instance that will be updated in-place with the derived values
   * @param maxDatastoreSizeSupplier detached maximum datastore size bound used to validate the
   *     selection
   */
  public static void setDatastoreSize(
      String selectedStoreSize, Config config, LongSupplier maxDatastoreSizeSupplier) {
    DatastoreSizingSupport.setDatastoreSize(selectedStoreSize, config, maxDatastoreSizeSupplier);
  }

  private static void addDatastoreSizeOptions(
      HTMLNode result,
      long maxSize,
      long autodetectedSize,
      Option<Long> sizeOption,
      Option<Long> clientCacheSizeOption,
      Option<Long> slashdotCacheSizeOption) {
    if (!sizeOption.isDefault()) {
      long current =
          sizeOption.getValue()
              + clientCacheSizeOption.getValue()
              + slashdotCacheSizeOption.getValue();
      result.addChild(
          TAG_OPTION,
          new String[] {ATTR_VALUE, ATTR_SELECTED},
          new String[] {SizeUtil.formatSize(current), "on"},
          WizardL10n.l10n("currentPrefix") + " " + SizeUtil.formatSize(current));
    } else if (autodetectedSize != -1) {
      result.addChild(
          TAG_OPTION,
          new String[] {ATTR_VALUE, ATTR_SELECTED},
          new String[] {SizeUtil.formatSize(autodetectedSize), "on"},
          SizeUtil.formatSize(autodetectedSize));
    }

    if (autodetectedSize != 512L * 1024 * 1024) {
      result.addChild(TAG_OPTION, ATTR_VALUE, "512M", "512 MiB");
    }

    // We always allow at least 1GB
    result.addChild(TAG_OPTION, ATTR_VALUE, "1G", "1 GiB");

    if (maxSize >= 2L * 1024 * 1024 * 1024) {
      if (autodetectedSize != -1 || !sizeOption.isDefault()) {
        result.addChild(TAG_OPTION, ATTR_VALUE, "2G", "2 GiB");
      } else {
        result.addChild(
            TAG_OPTION,
            new String[] {ATTR_VALUE, ATTR_SELECTED},
            new String[] {"2G", "on"},
            "2GiB");
      }
    }
    if (maxSize >= 3L * 1024 * 1024 * 1024) result.addChild(TAG_OPTION, ATTR_VALUE, "3G", "3 GiB");
    if (maxSize >= 5L * 1024 * 1024 * 1024) result.addChild(TAG_OPTION, ATTR_VALUE, "5G", "5 GiB");
    if (maxSize >= 10L * 1024 * 1024 * 1024)
      result.addChild(TAG_OPTION, ATTR_VALUE, "10G", "10 GiB");
    if (maxSize >= 20L * 1024 * 1024 * 1024)
      result.addChild(TAG_OPTION, ATTR_VALUE, "20G", "20 GiB");
    if (maxSize >= 50L * 1024 * 1024 * 1024)
      result.addChild(TAG_OPTION, ATTR_VALUE, "50G", "50 GiB");
    if (maxSize >= 200L * 1024 * 1024 * 1024)
      result.addChild(TAG_OPTION, ATTR_VALUE, "200G", "200GiB");
    if (maxSize >= 500L * 1024 * 1024 * 1024)
      result.addChild(TAG_OPTION, ATTR_VALUE, "500G", "500GiB");
  }
}
