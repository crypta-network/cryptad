package network.crypta.clients.http.wizardsteps;

import static network.crypta.support.io.DatastoreUtil.ONE_GIB;

import java.io.File;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStarter;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.DatastoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wizard step that renders and applies a datastore sizing choice.
 *
 * <p>This step is used by the HTTP first-time wizard to present a dropdown of sensible datastore
 * sizes based on the local environment. The UI is populated from the current {@link Config} (when
 * present) and from a best-effort auto-detection via {@link DatastoreUtil}; it also considers hard
 * limits derived from available disk space and a memory-based upper bound for slot filters.
 *
 * <p>When the user submits the form, this step updates multiple related configuration keys under
 * {@code node.*} (datastore size and cache sizes) in a consistent way. On the first run it also
 * sets the corresponding {@code *Type} options to the expected defaults. No I/O is performed beyond
 * querying the node's store directory for free space.
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
  private static final Logger LOG = LoggerFactory.getLogger(DatastoreSize.class);
  private static final String ATTR_SELECTED = "selected";
  private static final String ATTR_VALUE = "value";
  private static final String TAG_OPTION = "option";

  private final NodeClientCore core;
  private final Config config;

  /**
   * Creates a wizard step bound to a specific node core and configuration.
   *
   * <p>The instance is lightweight and holds references to the provided objects; it does not
   * perform any environment detection until {@link #getStep(HTTPRequest, PageHelper)} is called.
   * Callers typically construct this step as part of the wizard flow and reuse it for the lifetime
   * of a single request.
   *
   * @param core node core used for environment-aware sizing heuristics and store directory access
   * @param config mutable configuration that receives the selected datastore and cache settings
   */
  public DatastoreSize(NodeClientCore core, Config config) {
    this.config = config;
    this.core = core;
  }

  /**
   * Renders the datastore size selection UI for this wizard step.
   *
   * <p>This method populates a {@code <select>} element with options derived from three sources:
   * the current configured sizes (when non-default), a best-effort auto-detected size (when
   * available), and a set of fixed fallback sizes. The resulting options are additionally bounded
   * by {@link #maxDatastoreSize(Node)} to avoid offering sizes that exceed current disk or
   * memory-based constraints.
   *
   * <p>This method does not mutate {@link Config}; it only constructs the HTML content for the
   * current request.
   *
   * @param request current HTTP request, used only for step context and localization behavior
   * @param helper helper responsible for creating page structure and form elements for the wizard
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("step4Title"));
    HTMLNode bandwidthInfoboxContent =
        helper.getInfobox(
            "infobox-header", WizardL10n.l10n("datastoreSize"), contentNode, null, false);

    bandwidthInfoboxContent.addChild("#", WizardL10n.l10n("datastoreSizeLong"));
    HTMLNode bandwidthForm = helper.addFormChild(bandwidthInfoboxContent, ".", "dsForm");
    HTMLNode result = bandwidthForm.addChild("select", "name", "ds");

    long maxSize = maxDatastoreSize(core.getNode());

    long autodetectedSize = canAutoconfigureDatastoreSize();
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
   * and validation logic used by {@link #setDatastoreSize(String, Config)}. When this step is
   * executed as part of the full wizard flow (i.e., not in single-step mode), it advances to the
   * bandwidth step; otherwise it returns the completion step.
   *
   * @param request HTTP request containing the submitted {@code ds} selection and optional flags
   * @return the next wizard step name, suitable for {@code FirstTimeWizardToadlet.WIZARD_STEP}
   */
  @Override
  public String postStep(HTTPRequest request) {
    // drop down options may be 6 chars or fewer, but formatted ones e.g. old value if re-running
    // can
    // be more
    boolean firsttime = !request.isPartSet("singlestep");

    setDatastoreSizeInternal(request.getPartAsStringFailsafe("ds", 20), firsttime, config);
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
   */
  public static void setDatastoreSize(String selectedStoreSize, Config config) {
    setDatastoreSizeInternal(selectedStoreSize, true, config);
  }

  private static void setDatastoreSizeInternal(
      String selectedStoreSize, boolean firsttime, Config config) {
    try {
      long size = Fields.parseLong(selectedStoreSize);

      long maxDatastoreSize = DatastoreUtil.maxDatastoreSize();
      if (size > maxDatastoreSize) {
        throw new InvalidConfigValueException(
            "Attempting to set DatastoreSize ("
                + size
                + ") larger than maxDatastoreSize ("
                + maxDatastoreSize / ONE_GIB
                + " GiB)");
      }

      // client cache: 10% up to 200MB
      long clientCacheSize = Math.min(size / 10, 200L * 1024 * 1024);
      // recent requests cache / slashdot cache / ULPR cache
      int upstreamLimit = config.get("node").getInt("outputBandwidthLimit");
      int downstreamLimit = config.get("node").getInt("inputBandwidthLimit");
      // is used for remote stuff, so go by the minimum of the two
      int limit;
      if (downstreamLimit <= 0) limit = upstreamLimit;
      else limit = Math.min(downstreamLimit, upstreamLimit);
      // 35KB/sec limit has been seen to have 0.5 store writes per second.
      // So saying we want to have space to cache everything is only doubling that ...
      // OTOH most stuff is at low enough HTL to go to the datastore and thus not to
      // the slashdot cache, so we could probably cut this significantly...
      long lifetime = config.get("node").getLong("slashdotCacheLifetime");
      long maxSlashdotCacheSize = (lifetime / 1000) * limit;
      long slashdotCacheSize = Math.min(size / 10, maxSlashdotCacheSize);

      long storeSize = size - (clientCacheSize + slashdotCacheSize);

      if (LOG.isInfoEnabled()) {
        LOG.info("Setting datastore size to {}", Fields.longToString(storeSize, true));
      }
      config.get("node").set("storeSize", Fields.longToString(storeSize, true));
      if (firsttime) config.get("node").set("storeType", "salt-hash");
      if (LOG.isInfoEnabled()) {
        LOG.info("Setting client cache size to {}", Fields.longToString(clientCacheSize, true));
      }
      config.get("node").set("clientCacheSize", Fields.longToString(clientCacheSize, true));
      if (firsttime) config.get("node").set("clientCacheType", "salt-hash");
      if (LOG.isInfoEnabled()) {
        LOG.info(
            "Setting slashdot/ULPR/recent requests cache size to {}",
            Fields.longToString(slashdotCacheSize, true));
      }
      config.get("node").set("slashdotCacheSize", Fields.longToString(slashdotCacheSize, true));

      LOG.info("The storeSize has been set to {}", selectedStoreSize);
    } catch (ConfigException e) {
      LOG.error("Unexpected configuration error; please report this issue.", e);
    }
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

  /**
   * Computes an upper bound for the datastore size for the given node.
   *
   * <p>The returned value is expressed in bytes and is derived from two independent constraints: a
   * memory-based cap (used to avoid over-allocating slot filters) and the usable free space in the
   * node's store directory. When free space is considered, the implementation assumes the datastore
   * is currently empty and adds the sizes of existing files in the store directory back into the
   * free-space estimate. A margin of 1&nbsp;GiB is reserved to reduce the chance of exhausting the
   * filesystem.
   *
   * @param node node whose store directory and runtime constraints are used for the calculation
   * @return maximum datastore size in bytes based on current environment constraints
   */
  public static long maxDatastoreSize(Node node) {
    long maxMemory = NodeStarter.getMemoryLimitBytes();
    if (maxMemory == Long.MAX_VALUE) return ONE_GIB; // Treat as don't know.
    if (maxMemory < 128L * 1024 * 1024)
      return ONE_GIB; // 1GB default if you don't know or very small memory.
    long maxSize = maxDatastoreSizeFromMemory(maxMemory);

    // Datastore can never be larger than free disk space, assuming datastore is zero now.
    File storeDir = node.getStoreDir();
    long freeSpace = storeDir.getUsableSpace();
    File[] files = storeDir.listFiles();

    if (files != null) {
      for (File file : files) {
        freeSpace += file.length();
      }
    }

    if (freeSpace < maxSize) {
      maxSize = freeSpace;
    }

    // Leave some margin.
    maxSize = maxSize - ONE_GIB;

    return maxSize;
  }

  private static long maxDatastoreSizeFromMemory(long maxMemory) {
    // Don't use the first 100MB for slot filters.
    long available = maxMemory - 100L * 1024 * 1024;
    // Don't use more than 50% of available memory for slot filters.
    available = available / 2;
    // Slot filters are 4 bytes per slot.
    long slots = available / 4;
    // There are 3 types of keys. We want the number of { SSK, CHK, pubkey } i.e. the number of
    // slots in each store.
    slots /= 3;
    // We return the total size, so we don't need to worry about cache vs store or even client
    // cache.
    // One key of all 3 types combined uses NodeStorageSubsystem.SIZE_PER_KEY bytes on disk.
    return slots * network.crypta.node.subsystem.NodeStorageSubsystem.SIZE_PER_KEY;
  }

  private long canAutoconfigureDatastoreSize() {
    return DatastoreUtil.autodetectDatastoreSize(core, config);
  }
}
