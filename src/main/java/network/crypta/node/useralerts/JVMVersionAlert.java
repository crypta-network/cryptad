package network.crypta.node.useralerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.JVMVersion;

/**
 * Warns the user when the running Java runtime is at its vendor-declared end of life (EOL).
 *
 * <p>This alert is produced when the node detects that the current JVM version is below the
 * supported threshold and will stop working in a future release. It surfaces a succinct title and a
 * localized body describing the risk and the minimum version required, and it is presented as a
 * {@link UserAlert#WARNING warning}-level, user-dismissible notification. The text is fully
 * localized through {@link network.crypta.l10n.NodeL10n} and interpolates both the current Java
 * version and the threshold exposed by {@link network.crypta.support.JVMVersion#EOL_THRESHOLD}.
 *
 * <p>Typical usage is read-mostly: a producer constructs an instance and registers it with the
 * alert system; user interfaces query the title, text, and optional HTML fragment to render it.
 * Consumers should treat instances as immutable snapshots whose content is resolved dynamically at
 * call time from localization. The alert is dismissible by end users, and implementations may
 * unregister it when dismissed depending on the configured {@link
 * AbstractUserAlert.DismissOptions}.
 *
 * <ul>
 *   <li><b>Severity</b>: {@link UserAlert#WARNING} (non-fatal but action recommended).
 *   <li><b>Dismissal</b>: user can dismiss; dismissal requests unregistration.
 *   <li><b>Rendering</b>: plain text via {@link #getText()} and a minimal HTML wrapper via {@link
 *       #getHTMLText()}.
 *   <li><b>Thread-safety</b>: instances are not intrinsically synchronized; read a consistent view
 *       under external synchronization if combining multiple getters.
 * </ul>
 *
 * <p>Example:
 *
 * <pre>{@code
 * // Register a warning when the runtime is at/near EOL.
 * var alert = new JVMVersionAlert();
 * userAlertManager.register(alert);
 * }</pre>
 *
 * @see network.crypta.support.JVMVersion
 * @see network.crypta.l10n.NodeL10n
 * @see AbstractUserAlert
 */
public class JVMVersionAlert extends AbstractUserAlert {

  /**
   * Creates a warning-level, user-dismissible alert informing the user that the current Java
   * runtime is at EOL and that a newer version will be required in a future release.
   *
   * <p>The constructor wires common alert characteristics via the superclass: it marks the alert as
   * dismissible by end users, sets the {@link UserAlert#WARNING} priority, sets initial validity to
   * {@code true}, and configures a localized dismiss button label ({@code UserAlert.hide}) that
   * requests unregistration upon dismissal. The human-readable title and body are resolved lazily
   * on each call through {@link network.crypta.l10n.NodeL10n} so they remain consistent with the
   * active language.
   */
  public JVMVersionAlert() {
    super(
        true,
        null,
        null,
        UserAlert.WARNING,
        true,
        new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), true));
  }

  /** {@inheritDoc} */
  @Override
  public String getTitle() {
    return NodeL10n.getBase().getString("JavaEOLAlert.title");
  }

  /** {@inheritDoc} */
  @Override
  public String getText() {
    return NodeL10n.getBase()
        .getString(
            "JavaEOLAlert.body",
            new String[] {"current", "new"},
            new String[] {JVMVersion.getCurrent(), JVMVersion.EOL_THRESHOLD});
  }

  /** {@inheritDoc} */
  @Override
  public String getShortText() {
    return getTitle();
  }

  /** {@inheritDoc} */
  @Override
  public HTMLNode getHTMLText() {
    return new HTMLNode("div", getText());
  }
}
