package network.crypta.runtime.alerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

/**
 * A small, concrete {@link UserAlert} that wraps a title, plain text, and an optional short summary
 * into a ready-to-display alert with sensible defaults.
 *
 * <p>This implementation targets simple, one-off messages that do not require dynamic behavior or
 * custom lifecycle handling. It always constructs a valid alert and derives a minimal HTML fragment
 * by wrapping the plain-text body in a {@code <div>} so UIs that prefer HTML can render a
 * structured variant while text-only consumers rely on the plain body. Dismissal controls are
 * localized using {@link NodeL10n} with a “hide” label, and dismissal is configured to request
 * unregistering the alert from its manager when a user dismisses it.
 *
 * <p>Unlike more flexible subclasses, {@link #isValid(boolean)} is intentionally a no-op here. The
 * alert remains valid from creation until the producer unregisters it or the user dismisses it via
 * the UI. When you need programmatic validity toggling or custom state transitions, prefer using
 * {@link AbstractUserAlert} directly or another subclass designed for that purpose.
 *
 * <ul>
 *   <li>Responsibilities: simple construction, localized dismiss label, and unregister-on-dismiss.
 *   <li>Thread-safety: inherits the base class contract; callers should synchronize for multi-field
 *       reads to obtain a consistent snapshot.
 * </ul>
 *
 * @see AbstractUserAlert
 * @see UserAlert
 */
public class SimpleUserAlert extends AbstractUserAlert {

  /**
   * Constructs a simple alert with the supplied presentation and severity.
   *
   * <p>The alert is created in a valid state and uses the given title, full body, and short summary
   * for rendering. A minimal HTML fragment is synthesized as {@code <div>} containing the plain
   * text. The dismiss button label is localized via {@link NodeL10n} and dismissals request
   * unregistering this alert. Note that {@link #isValid(boolean)} is overridden to do nothing; if
   * your producer needs to toggle visibility, unregister and replace the alert instead.
   *
   * <pre>{@code
   * // Example: create a dismissible warning with a short summary
   * var alert = new SimpleUserAlert(true, "Low disk space",
   *     "Free space is below 5 GiB.", "Low free space", UserAlert.WARNING);
   * }</pre>
   *
   * @param canDismiss whether user interfaces should present a dismiss control; when {@code false}
   *     the alert is not user-dismissible and should be removed programmatically by its producer.
   * @param title localized, succinct title appropriate for list headers and banners; may be {@code
   *     null} if the consumer can infer or chooses to omit a title in its UI.
   * @param text full, plain-text body describing the condition or guidance for the user; may be
   *     {@code null} if a consumer relies solely on the short summary in constrained contexts.
   * @param shortText compact summary suitable for notifications and feeds; may be {@code null} when
   *     not applicable or when the full text is sufficiently brief for all contexts.
   * @param type severity class such as {@link UserAlert#CRITICAL_ERROR}, {@link UserAlert#ERROR},
   *     {@link UserAlert#WARNING}, or {@link UserAlert#MINOR}; controls ordering and emphasis.
   */
  public SimpleUserAlert(
      boolean canDismiss, String title, String text, String shortText, short type) {
    super(
        canDismiss,
        title,
        Body.of(text, shortText, new HTMLNode("div", text)),
        type,
        true,
        new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), true));
  }

  /**
   * {@inheritDoc}
   *
   * <p>This override is intentionally a no-op to keep {@code SimpleUserAlert} immutable in terms of
   * visibility. Producers should unregister the alert or replace it with a new instance rather than
   * toggling validity in place. Calling this method has no effect and is idempotent.
   *
   * @param validity ignored. The alert remains valid until it is unregistered or dismissed.
   */
  @Override
  public void isValid(boolean validity) {
    // Do nothing
  }
}
