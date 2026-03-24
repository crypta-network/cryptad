package network.crypta.runtime.alerts;

import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.Version;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.DatastoreUtil;

/**
 * User alert indicating that the configured datastore capacity is below a safe minimum relative to
 * the available disk space.
 *
 * <p>This alert evaluates the datastore size from the node configuration rather than inspecting the
 * current on‑disk usage. That distinction is important because a resize may already be queued or in
 * progress; the intent is to guide users toward a sustainable configuration that will apply after
 * any pending resize completes. The message recommends allocating roughly 20% of available disk
 * space to the datastore while only warning if the configured size drops below 10%. This deliberate
 * gap encourages choosing a margin that avoids repeated warnings during normal changes in free
 * space.
 *
 * <p>When dismissed, the alert remains hidden until the node is upgraded to a newer build. This
 * throttling avoids repeatedly prompting the user to make the same decision across restarts while
 * still re‑evaluating the guidance for future versions. The alert provides both plain‑text and HTML
 * variants and includes a direct link to the First‑Time Wizard step for datastore sizing so the
 * user can immediately adjust settings.
 *
 * <ul>
 *   <li>Computes thresholds based on the same heuristic used by the setup wizard.
 *   <li>Considers only configured sizes (store, client cache, slashdot cache).
 *   <li>Advises at 20% of free space; warns only below 10%.
 *   <li>Dismissal is remembered per build number.
 * </ul>
 *
 * @see UserAlert
 * @see network.crypta.node.NodeClientCore
 */
public class DatastoreTooSmallAlert implements UserAlert {
  private final NodeClientCore core;

  private static final String KEY_STORE_SIZE = "storeSize";
  private static final String KEY_CLIENT_CACHE_SIZE = "clientCacheSize";
  private static final String KEY_SLASHDOT_CACHE_SIZE = "slashdotCacheSize";

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("DataStoreTooSmallAlert." + key);
  }

  private static String l10n(String key, String value) {
    return NodeL10n.getBase().getString("DataStoreTooSmallAlert." + key, "size", value);
  }

  /**
   * Creates a new alert bound to the provided node core.
   *
   * <p>The alert reads configuration through the core when generating text and determining
   * validity. It does not cache derived values; each call evaluates the current configuration
   * state, so changes take effect immediately.
   *
   * @param core non-null node core used to access configuration, localization, and utilities; the
   *     reference is retained for the lifetime of the alert but is not modified.
   */
  public DatastoreTooSmallAlert(NodeClientCore core) {
    this.core = core;
  }

  /**
   * Indicates that the user may hide the alert from the UI.
   *
   * <p>The dismissal is persisted by {@link #onDismiss()} and suppresses the alert until the node
   * runs a newer build. This method is idempotent and does not consult configuration.
   *
   * @return {@code true} because this alert is advisory and user-dismissible.
   */
  @Override
  public boolean userCanDismiss() {
    return true;
  }

  /**
   * Returns a concise, localized title for the alert.
   *
   * <p>The title is suitable for list views or notification headers and does not contain dynamic
   * values. The message text is provided by {@link #getText()} and {@link #getHTMLText()}.
   *
   * @return localized title string; never {@code null}.
   */
  @Override
  public String getTitle() {
    return l10n("title");
  }

  /**
   * Provides a short summary suitable for compact UI placements.
   *
   * <p>For this alert the short text is equivalent to the title. Callers should prefer {@link
   * #getText()} or {@link #getHTMLText()} when a fuller explanation or actionable guidance is
   * needed.
   *
   * @return brief localized summary; identical to {@link #getTitle()}.
   */
  @Override
  public String getShortText() {
    return getTitle();
  }

  /**
   * Builds a localized, plain-text description of the alert, including the current configured size
   * and a recommended minimum.
   *
   * <p>The current size is computed from the configured datastore components and rounded to GiB.
   * The recommended minimum is 20% of the available size as determined by the First‑Time Wizard’s
   * heuristic, bounded by implementation limits. This method performs no I/O and reads only the
   * in-memory configuration.
   *
   * @return human-readable description that explains the recommendation and current settings.
   */
  @Override
  public String getText() {
    Config config = core.getNode().getConfig();

    // Datastore size as configured in the wizard is the sum of these three.
    long storeSize = config.get("node").getLong(KEY_STORE_SIZE);
    long clientCacheSize = config.get("node").getLong(KEY_CLIENT_CACHE_SIZE);
    long slashdotCacheSize = config.get("node").getLong(KEY_SLASHDOT_CACHE_SIZE);
    long totalSize = storeSize + clientCacheSize + slashdotCacheSize;
    // And this corrective factor, since size on disk is up towards 3.6% larger.
    totalSize = (long) (totalSize * 1.036);
    // And round it, in case manually configured and not exact multiple of GiB.
    long currentSize = (totalSize + 512 * 1024 * 1024) / (1024 * 1024 * 1024);
    // Calculate available size the same way as in wizard, recommend at least 20% of that.
    long availableSize = DatastoreUtil.maxDatastoreSize(core.getNode()) / (1024 * 1024 * 1024);
    long minSize = availableSize / 5;
    // Wizard never recommends sizes above 100 GiB, so claim a minimum of at most 50 GiB.
    if (minSize > 50) minSize = 50;

    return l10n("description", Long.toString(minSize))
        + " "
        + l10n("current", currentSize + " GiB")
        + l10n("available", availableSize + " GiB");
  }

  /**
   * Builds an HTML representation of the alert with line breaks and a link to the wizard step that
   * configures datastore size.
   *
   * <p>The structure is a {@code <div>} containing two paragraphs: the first paragraph explains the
   * recommendation; the second lists current and available sizes. A final anchor links to {@code
   * /wizard/?step=DATASTORE_SIZE&singlestep=true} to let the user reconfigure immediately.
   *
   * @return an {@link HTMLNode} tree safe for inclusion in the node’s web UI; never {@code null}.
   */
  @Override
  public HTMLNode getHTMLText() {
    Config config = core.getNode().getConfig();

    // Datastore size as configured in the wizard is the sum of these three.
    long storeSize = config.get("node").getLong(KEY_STORE_SIZE);
    long clientCacheSize = config.get("node").getLong(KEY_CLIENT_CACHE_SIZE);
    long slashdotCacheSize = config.get("node").getLong(KEY_SLASHDOT_CACHE_SIZE);
    long totalSize = storeSize + clientCacheSize + slashdotCacheSize;
    // And this corrective factor, since size on disk is up towards 3.6% larger.
    totalSize = (long) (totalSize * 1.036);
    // And round it, in case manually configured and not exact multiple of GiB.
    long currentSize = (totalSize + 512 * 1024 * 1024) / (1024 * 1024 * 1024);
    // Calculate available size the same way as in wizard, recommend at least 20% of that.
    long availableSize = DatastoreUtil.maxDatastoreSize(core.getNode()) / (1024 * 1024 * 1024);
    long minSize = availableSize / 5;
    // Wizard never recommends sizes above 100 GiB, so claim a minimum of at most 50 GiB.
    if (minSize > 50) minSize = 50;

    HTMLNode alertNode = new HTMLNode("div");
    alertNode.addChild("p", l10n("description", Long.toString(minSize)));
    HTMLNode sizesNode = new HTMLNode("p");
    sizesNode.addChild("#", l10n("current", currentSize + " GiB"));
    sizesNode.addChild("br");
    sizesNode.addChild("#", l10n("available", availableSize + " GiB"));
    alertNode.addChild(sizesNode);
    alertNode
        .addChild("a", "href", "/wizard/?step=DATASTORE_SIZE&singlestep=true")
        .addChild("#", l10n("submit"));

    return alertNode;
  }

  /**
   * Returns the alert priority class used for sorting and styling in the UI.
   *
   * <p>This alert is categorized as a warning rather than an error because the node can operate
   * with smaller datastores, albeit with reduced effectiveness.
   *
   * @return {@link UserAlert#WARNING} to indicate warning severity.
   */
  @Override
  public short getPriorityClass() {
    return UserAlert.WARNING;
  }

  /**
   * Determines whether the alert should currently be shown.
   *
   * <p>Validity is computed dynamically from the configuration on each call. The alert is valid
   * only when the configured size is below 10% of the available size (bounded), and the user has
   * not dismissed the alert for the current build.
   *
   * @return {@code true} if the alert should be displayed; otherwise {@code false}.
   */
  @Override
  public boolean isValid() {
    Config config = core.getNode().getConfig();

    // Datastore size as configured in the wizard is the sum of these three.
    long storeSize = config.get("node").getLong(KEY_STORE_SIZE);
    long clientCacheSize = config.get("node").getLong(KEY_CLIENT_CACHE_SIZE);
    long slashdotCacheSize = config.get("node").getLong(KEY_SLASHDOT_CACHE_SIZE);
    long totalSize = storeSize + clientCacheSize + slashdotCacheSize;
    // And this corrective factor, since size on disk is up towards 3.6% larger.
    totalSize = (long) (totalSize * 1.036);
    // And round it, in case manually configured and not exact multiple of GiB.
    long currentSize = (totalSize + 512 * 1024 * 1024) / (1024 * 1024 * 1024);
    // Calculate available size the same way as in wizard, only warn if below 10% of that.
    long availableSize = DatastoreUtil.maxDatastoreSize(core.getNode()) / (1024 * 1024 * 1024);
    long minSize = availableSize / 10;
    // Wizard never recommends sizes above 100 GiB, so never warn if above 25 GiB.
    if (minSize > 25) minSize = 25;

    // Check if a warning has already been dismissed on this Freenet version
    int currentVersion = Version.currentBuildNumber();
    int dismissedVersion =
        core.getNode().getConfig().get("node").getInt("datastoreTooSmallDismissed");

    return currentSize < minSize && currentVersion != dismissedVersion;
  }

  /**
   * No-op setter for validity.
   *
   * <p>The validity of this alert is derived from configuration and cannot be forced externally;
   * therefore, this override intentionally does nothing.
   *
   * @param validity ignored. Present to satisfy the {@link UserAlert} contract.
   */
  @Override
  public void isValid(boolean validity) {
    // Intentionally blank: validity is computed dynamically from configuration.
  }

  /**
   * Returns the localized label used for the dismiss/hide button.
   *
   * @return short, localized action text; never {@code null}.
   */
  @Override
  public String dismissButtonText() {
    return NodeL10n.getBase().getString("UserAlert.hide");
  }

  /**
   * Indicates that the alert should be unregistered once the user dismisses it.
   *
   * <p>Unregistering reduces UI churn: the alert will reappear only if it becomes valid again in a
   * further build.
   *
   * @return {@code true} to request unregistration after dismissal.
   */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    return true;
  }

  /**
   * Persists dismissal for the current build, so the alert remains hidden until the node is updated
   * to a newer version.
   *
   * <p>Failure to persist the flag is intentionally ignored so that runtime behavior is never
   * blocked by configuration write issues.
   */
  @Override
  public void onDismiss() {
    String currentVersion = Integer.toString(Version.currentBuildNumber());

    try {
      core.getNode().getConfig().get("node").set("datastoreTooSmallDismissed", currentVersion);
    } catch (ConfigException _) {
      // Intentionally ignore: inability to persist dismissal should not impact runtime.
    }
  }

  /**
   * Provides a stable, URL-safe anchor name for the alert.
   *
   * @return {@code "datastore-too-small"} used as a fragment or identifier in UIs.
   */
  @Override
  public String anchor() {
    return "datastore-too-small";
  }

  /**
   * Indicates whether this alert represents a transient event notification.
   *
   * <p>This alert conveys configuration guidance rather than a one-time event.
   *
   * @return {@code false} because it is not an event notification.
   */
  @Override
  public boolean isEventNotification() {
    return false;
  }

  /**
   * Returns a monotonic-ish update time to aid client-side caching and sorting.
   *
   * <p>The value reflects the current wall-clock time on each call and is not persisted.
   *
   * @return milliseconds since the Unix epoch from {@link System#currentTimeMillis()}.
   */
  @Override
  public long getUpdatedTime() {
    return System.currentTimeMillis();
  }

  /**
   * Produces an FCP feed message containing the alert content for consumption by FCP clients.
   *
   * <p>The message includes the title, summary, full text, priority, and an updated timestamp. The
   * content is generated on demand and reflects the current configuration.
   *
   * @return a new {@link FCPMessage} describing this alert; never {@code null}.
   */
  @Override
  public FCPMessage getFCPMessage() {
    return new FeedMessage(
        getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
  }
}
