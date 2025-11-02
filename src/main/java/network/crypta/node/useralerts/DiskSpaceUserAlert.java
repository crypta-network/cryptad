package network.crypta.node.useralerts;

import java.io.File;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.FilenameGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User alert that reports insufficient free disk space for core operations.
 *
 * <p>This alert continuously evaluates the available free space on the node's working directories
 * and surfaces a human‑readable message when thresholds are breached. Two limits are consulted from
 * {@link NodeClientCore}: a short‑term limit (affecting temporary operations such as browsing and
 * request completion) and a long‑term limit (affecting creation of persistent requests). The alert
 * classifies the situation into distinct severities and guides the user to free space or adjust
 * configuration.
 *
 * <p>Typical usage is internal to the node: an instance is registered with the {@link
 * UserAlertManager} and polled by the UI and FCP subsystems to render banners and feed entries. The
 * evaluation caches its result for a brief interval to avoid excessive filesystem probes. The class
 * is thread‑safe for callers in the sense that its public API does not require external
 * synchronization; internal status updates use synchronization where needed.
 *
 * <ul>
 *   <li><b>Short‑term breach</b>: temporary work cannot proceed reliably.
 *   <li><b>Long‑term breach</b>: starting persistent requests is blocked.
 *   <li><b>Completion breach</b>: finishing existing persistent requests is blocked.
 * </ul>
 *
 * @see NodeClientCore
 * @see UserAlert
 * @see HTMLNode
 * @see FCPMessage
 * @author toad
 */
public class DiskSpaceUserAlert implements UserAlert {
  private static final Logger LOG = LoggerFactory.getLogger(DiskSpaceUserAlert.class);

  final NodeClientCore core;
  private Status status;
  private long lastCheckedStatus;
  static final int UPDATE_TIME = 100;

  enum Status {
    /** Everything is OK. */
    OK,
    /**
     * Not enough space to start persistent requests: Space on persistent-temp-* < long term limit.
     */
    PERSISTENT,
    /**
     * Not enough space to start transient requests, finish persistent requests or do anything much:
     * Space on temp-* < short term limit
     */
    TRANSIENT,
    /**
     * Not enough space to complete persistent requests: Space on persistent-temp-* < short term
     * limit.
     */
    PERSISTENT_COMPLETION;

    public String getExplanation() {
      return l10n("explanation." + this);
    }
  }

  Status evaluate() {
    long shortTermLimit = core.getMinDiskFreeShortTerm();
    long longTermLimit = core.getMinDiskFreeLongTerm();
    File tempDir = core.getTempFilenameGenerator().getDir();
    if (tempDir.getUsableSpace() < shortTermLimit) return Status.TRANSIENT; // Takes precedence.
    FilenameGenerator fg = core.getPersistentFilenameGenerator();
    if (fg != null) {
      File persistentTempDir = fg.getDir();
      long space = persistentTempDir.getUsableSpace();
      if (space < shortTermLimit) return Status.PERSISTENT_COMPLETION;
      if (space < longTermLimit) return Status.PERSISTENT;
    }
    return Status.OK;
  }

  /**
   * Creates a new disk‑space alert backed by the provided core.
   *
   * <p>The core supplies the directory locations and the configured short‑term and long‑term free
   * space limits used to classify the current status. The instance does not take ownership of the
   * core and performs only read‑only queries against it.
   *
   * @param core the {@link NodeClientCore} from which to read thresholds and working directories;
   *     must be non‑{@code null} and remain valid for the lifetime of this alert instance
   */
  public DiskSpaceUserAlert(NodeClientCore core) {
    this.core = core;
  }

  /**
   * Indicates whether the alert can be dismissed by a user.
   *
   * <p>Dismissal hides the current banner/notification but does not change the underlying disk
   * condition. If the condition persists, the alert may reappear after re‑evaluation by the alert
   * system.
   *
   * @return {@code true} because the UI should allow users to hide the banner temporarily even if
   *     the free‑space condition remains unchanged
   */
  @Override
  public boolean userCanDismiss() {
    return true;
  }

  /**
   * Returns the localized title for this alert.
   *
   * <p>The title is short and suitable for headings, badges, or feed summaries. Localization is
   * performed via {@link NodeL10n} using the {@code DiskSpaceUserAlert.title} key.
   *
   * @return a concise, localized title string describing the disk‑space problem
   */
  @Override
  public String getTitle() {
    return l10n("title");
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("DiskSpaceUserAlert." + key);
  }

  private static String l10nNotEnoughSpaceIn(String whereValue) {
    return NodeL10n.getBase().getString("DiskSpaceUserAlert.notEnoughSpaceIn", "where", whereValue);
  }

  /**
   * Builds the full localized message explaining the current condition and suggested action.
   *
   * <p>The message combines: a location‑specific preface (which directory is constrained), a
   * severity‑specific explanation, and a general action hint. The text is suitable for plain‑text
   * renderers and may be wrapped by callers as needed. The content is derived from the current
   * {@link Status}, which is cached briefly to reduce filesystem calls.
   *
   * @return an aggregated, user‑facing message describing where space is low and what to do next
   */
  @Override
  public String getText() {
    Status currentStatus = getStatus();
    return l10nNotEnoughSpaceIn(getWhere(currentStatus).toString())
        + " "
        + currentStatus.getExplanation()
        + " "
        + l10n("action");
  }

  private File getWhere(Status status) {
    // Returns the directory currently being checked; mapping to the underlying filesystem
    // (e.g., a mount point) would require java.nio.file APIs.
    if (status == Status.PERSISTENT || status == Status.PERSISTENT_COMPLETION) {
      // Be very careful about race conditions!
      FilenameGenerator fg = core.getPersistentFilenameGenerator();
      if (fg != null) {
        return fg.getDir();
      }
    }
    return core.getTempFilenameGenerator().getDir();
  }

  private synchronized Status getStatus() {
    long now = System.currentTimeMillis();
    if (!(this.status == null || now - lastCheckedStatus > UPDATE_TIME)) return status;
    try {
      status = evaluate();
      lastCheckedStatus = now;
      return status;
    } catch (Exception e) {
      // This is an alert. If it fails, it can break the web interface completely.
      // Catch Exceptions to prevent UI disruption; allow Errors to propagate.
      LOG.error("Unable to check disk space: {}", e, e);
      return Status.OK;
    }
  }

  /**
   * Returns a minimal HTML representation of this alert's text.
   *
   * <p>The returned node consists of a simple anchor node containing the plain text from {@link
   * #getText()}. It is safe for insertion in contexts that expect basic HTML structure but do not
   * require rich markup.
   *
   * @return an {@link HTMLNode} wrapping the full message in a lightweight HTML container
   */
  @Override
  public HTMLNode getHTMLText() {
    return new HTMLNode("#", getText());
  }

  /**
   * Returns a compact, single‑line summary for the alert.
   *
   * <p>This is typically used where space is constrained (for example, in notification lists or
   * feed titles). For this alert it is identical to {@link #getTitle()}.
   *
   * @return the concise, localized title string
   */
  @Override
  public String getShortText() {
    return getTitle();
  }

  /**
   * Returns the severity class for this alert.
   *
   * <p>Disk‑space exhaustion can prevent core operations from proceeding; therefore, the alert is
   * classified as a critical error to ensure it is displayed prominently and surfaced over less
   * urgent notifications.
   *
   * @return {@link UserAlert#CRITICAL_ERROR} to indicate high severity
   */
  @Override
  public short getPriorityClass() {
    return UserAlert.CRITICAL_ERROR;
  }

  /**
   * Reports whether the alert is currently active.
   *
   * <p>An alert is considered valid when a recent evaluation determined that free space is below
   * one of the configured thresholds. The result is cached for a short interval; callers should be
   * prepared for the return value to change after subsequent evaluations.
   *
   * @return {@code true} when a short‑term, long‑term, or completion threshold is breached; {@code
   *     false} otherwise
   */
  @Override
  public boolean isValid() {
    Status currentStatus = getStatus();
    return currentStatus != Status.OK;
  }

  /**
   * Compatibility hook to set validity, ignored for this alert type.
   *
   * <p>The disk‑space alert derives its validity exclusively from live evaluation and does not
   * allow external forcing. The argument is accepted to satisfy the interface but has no effect.
   *
   * @param validity ignored; callers cannot override computed validity
   */
  @Override
  public void isValid(boolean validity) {
    // Ignore.
  }

  /**
   * Returns the localized label for the dismiss action.
   *
   * <p>The label is resolved through {@link NodeL10n} using the generic {@code UserAlert.hide} key
   * to remain consistent with other alerts.
   *
   * @return a localized button caption instructing the UI to hide the alert
   */
  @Override
  public String dismissButtonText() {
    return NodeL10n.getBase().getString("UserAlert.hide");
  }

  /**
   * Suggests whether the alert should be unregistered after dismissal.
   *
   * <p>For disk‑space issues, once the user dismisses the banner, the alert can be unregistered and
   * re‑added automatically on the next evaluation if the condition still applies. This keeps the UI
   * responsive and avoids stale banners.
   *
   * @return {@code true} to remove the alert on dismissal and rely on re‑evaluation to re‑emit it
   */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    return true;
  }

  /**
   * Callback invoked when the alert is dismissed; no additional action is required.
   *
   * <p>Disk‑space status is re‑checked independently on subsequent cycles, so there is nothing to
   * clean up locally when the current banner is hidden.
   */
  @Override
  public void onDismiss() {
    // Ignore.
  }

  /**
   * Returns a stable, URL‑friendly anchor identifier for this alert.
   *
   * <p>Callers may use this value as an HTML anchor or fragment identifier to enable in‑page
   * linking and testing.
   *
   * @return the constant anchor string {@code "not-enough-disk-space"}
   */
  @Override
  public String anchor() {
    return "not-enough-disk-space";
  }

  /**
   * Indicates whether this alert represents a transient event notification.
   *
   * <p>Disk‑space alerts track a condition rather than a single discrete event, so they are not
   * treated as event notifications.
   *
   * @return {@code false} because the alert reflects an ongoing condition
   */
  @Override
  public boolean isEventNotification() {
    return false;
  }

  /**
   * Produces an {@link FCPMessage} describing the alert for feed consumers.
   *
   * <p>The message carries the title, short text, full text, priority class, and the last updated
   * timestamp so remote clients can present and sort entries consistently. The payload contains no
   * filesystem paths beyond the directory name string already included in the text.
   *
   * @return an immutable FCP message representing the current alert state
   */
  @Override
  public FCPMessage getFCPMessage() {
    return new FeedMessage(
        getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
  }

  /**
   * Returns the timestamp (milliseconds since epoch) of the last status evaluation.
   *
   * <p>The value is updated whenever the alert re‑evaluates disk space and may lag behind current
   * wall‑clock time by up to the internal caching interval.
   *
   * @return the last evaluation time in milliseconds, suitable for sorting or freshness checks
   */
  @Override
  public synchronized long getUpdatedTime() {
    return lastCheckedStatus;
  }
}
