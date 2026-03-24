package network.crypta.node.runtime;

import java.util.Objects;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.store.alerts.StoreAlertSink;
import network.crypta.store.alerts.StoreMaintenanceAlertKind;
import network.crypta.store.alerts.StoreMaintenanceAlertSource;
import network.crypta.support.HTMLNode;

/**
 * Bridges store-maintenance alert sources into the runtime {@link UserAlertManager}.
 *
 * <p>The extracted store boundary exposes only live maintenance state via {@link
 * StoreMaintenanceAlertSource}. This adapter keeps that boundary narrow while preserving the
 * existing runtime behavior: it translates the source into a runtime-local {@link UserAlert},
 * resolves localized strings through {@link NodeL10n}, and registers the resulting alert with the
 * shared alert manager used by HTTP, FCP, and other operator-facing surfaces.
 *
 * <p>Each registration produces a lightweight wrapper that delegates back to the source whenever
 * alert text or validity is queried. That means progress values stay current without the store
 * having to emit pre-rendered text snapshots. The adapter is stateless apart from its reference to
 * the target alert manager and is safe to reuse for multiple stores.
 */
public final class UserAlertManagerStoreAlertSink implements StoreAlertSink {
  private static final String ALERTS_PREFIX = "SaltedHashCryptaStore.";

  private final UserAlertManager userAlertManager;

  /**
   * Creates an adapter that forwards store-maintenance alerts into the given runtime manager.
   *
   * <p>The manager is retained for the lifetime of this adapter and receives one runtime alert
   * wrapper for each registered maintenance source. Callers typically create one sink per node
   * storage subsystem and share it across multiple stores.
   *
   * @param userAlertManager runtime alert registry that should receive wrapped maintenance alerts;
   *     must not be {@code null}
   * @throws NullPointerException if {@code userAlertManager} is {@code null}
   */
  public UserAlertManagerStoreAlertSink(UserAlertManager userAlertManager) {
    this.userAlertManager = Objects.requireNonNull(userAlertManager, "userAlertManager");
  }

  /**
   * Wraps the store-maintenance source in a runtime alert and registers it with the manager.
   *
   * <p>The wrapper remains dynamic: text, progress, and validity are computed from the source each
   * time the runtime alert is queried. This preserves the old user-visible cleaner-progress
   * behavior while keeping localization and HTML generation outside the store layer.
   *
   * @param alert live maintenance source to expose through the runtime alert system; must not be
   *     {@code null}
   * @throws NullPointerException if {@code alert} is {@code null}
   */
  @Override
  public void register(StoreMaintenanceAlertSource alert) {
    userAlertManager.register(new StoreMaintenanceUserAlert(alert));
  }

  private static final class StoreMaintenanceUserAlert extends AbstractUserAlert {
    private static final String[] PROGRESS_PATTERNS = {"name", "processed", "total"};
    private static final String[] TITLE_PATTERNS = {"name"};

    private final StoreMaintenanceAlertSource source;

    private StoreMaintenanceUserAlert(StoreMaintenanceAlertSource source) {
      this.source = Objects.requireNonNull(source, "source");
    }

    @Override
    public String anchor() {
      return source.anchor();
    }

    @Override
    public String dismissButtonText() {
      return NodeL10n.getBase().getString("UserAlert.hide");
    }

    @Override
    public HTMLNode getHTMLText() {
      return new HTMLNode("#", getText());
    }

    @Override
    public short getPriorityClass() {
      return UserAlert.ERROR;
    }

    @Override
    public String getShortText() {
      return localizedProgressText(shortKey());
    }

    @Override
    public String getText() {
      return localizedProgressText(longKey());
    }

    @Override
    public String getTitle() {
      return NodeL10n.getBase()
          .getString(ALERTS_PREFIX + "cleanerAlertTitle", TITLE_PATTERNS, titleValues());
    }

    @Override
    public boolean isValid() {
      return source.isValid();
    }

    @Override
    public void isValid(boolean validity) {
      // Runtime validity is driven by the dynamic source.
    }

    @Override
    public void onDismiss() {
      // Non-dismissible alert; nothing to do.
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return true;
    }

    @Override
    public boolean userCanDismiss() {
      return false;
    }

    private String localizedProgressText(String key) {
      return NodeL10n.getBase().getString(ALERTS_PREFIX + key, PROGRESS_PATTERNS, progressValues());
    }

    private String shortKey() {
      if (source.kind() == StoreMaintenanceAlertKind.RESIZE_PROGRESS) {
        return "shortResizeProgress";
      }
      return source.newSlotFilter() ? "shortRebuildProgressNew" : "shortRebuildProgress";
    }

    private String longKey() {
      if (source.kind() == StoreMaintenanceAlertKind.RESIZE_PROGRESS) {
        return "longResizeProgress";
      }
      return source.newSlotFilter() ? "longRebuildProgressNew" : "longRebuildProgress";
    }

    private String[] progressValues() {
      return new String[] {
        source.storeName(), String.valueOf(source.processed()), String.valueOf(source.total())
      };
    }

    private String[] titleValues() {
      return new String[] {source.storeName()};
    }
  }
}
