package network.crypta.runtime.alerts;

import java.util.Objects;
import network.crypta.support.HTMLNode;

/**
 * A lightweight delegating {@link UserAlert} that forwards all queries and callbacks to a
 * dynamically attached target alert. The proxy can be set to {@code null} to disable presentation
 * or pointed at another alert at runtime, allowing producers to keep a stable registration with a
 * {@link UserAlertManager} while swapping the underlying content.
 *
 * <p>Use this type when an alert "slot" exists in the UI but the concrete alert varies over time or
 * may temporarily disappear. Consumers interact with the proxy as with any other alert; the proxy
 * in turn delegates to the current target. Methods that require a target use {@link
 * java.util.Objects#requireNonNull(Object)} and therefore throw {@link NullPointerException} when
 * no target is attached. The validity of the proxy mirrors the target’s validity, and updates are
 * forwarded when a target is present.
 *
 * <p>When constructed with {@code autoRegister = true}, the proxy self-registers with the provided
 * {@link UserAlertManager} the first time a non-{@code null} target is set, and unregisters itself
 * when the target is cleared. This preserves existing auto-registration semantics while avoiding
 * duplicate display of multiple alerts.
 *
 * <ul>
 *   <li>Delegation: All getters and lifecycle hooks delegate to the current target alert.
 *   <li>Attachment: {@link #setAlert(UserAlert)} accepts {@code null} (detaches) or a new target.
 *   <li>Validity: {@link #isValid()} is {@code true} only when a target exists and is valid.
 *   <li>Anchor: {@link #anchor()} is stable for the proxy instance, not for the target.
 *   <li>Concurrency: the class performs no synchronization; callers should coordinate if accessed
 *       from multiple threads.
 * </ul>
 *
 * @see UserAlert
 * @see AbstractUserAlert
 * @see UserAlertManager
 */
public class ProxyUserAlert extends AbstractUserAlert {

  private UserAlert alert;
  private final UserAlertManager uam;
  private final boolean autoRegister;

  /**
   * Creates a delegating proxy for alerts.
   *
   * <p>When {@code autoRegister} is {@code true}, the proxy automatically registers itself with the
   * supplied manager when a non-{@code null} target is first attached via {@link
   * #setAlert(UserAlert)}, and unregisters when the target is cleared. No registration changes are
   * performed when {@code autoRegister} is {@code false}.
   *
   * @param uam manager used for optional auto-registration and unregistration; must remain usable
   *     for the lifetime of this proxy instance; never {@code null}.
   * @param autoRegister whether the proxy should self-register on first target attachment and
   *     unregister on detachment; set to {@code false} to manage registry membership externally.
   */
  public ProxyUserAlert(UserAlertManager uam, boolean autoRegister) {
    this.uam = uam;
    this.autoRegister = autoRegister;
  }

  /**
   * Attaches or detaches the target alert that this proxy delegates to.
   *
   * <p>Passing {@code null} detaches the current target and, when {@code autoRegister} is {@code
   * true}, causes this proxy to be unregistered from the manager. Passing a non-{@code null} alert
   * updates the delegate and, when {@code autoRegister} is {@code true} and the previous target was
   * {@code null}, registers this proxy with the manager. The method does not synchronize; callers
   * should ensure external coordination if multiple threads may update or read concurrently.
   *
   * @param a the new target alert to delegate to, or {@code null} to detach and disable the proxy
   *     until another target is set.
   */
  public void setAlert(UserAlert a) {
    UserAlert old = alert;
    alert = a;
    if (autoRegister) {
      if (old == null && alert != null) {
        uam.register(this);
      } else if (alert == null) {
        uam.unregister(this);
      }
    }
  }

  /**
   * Returns whether a user may dismiss the current target alert. Requires a target to be attached.
   *
   * <p>The value is delegated directly to the target’s {@code userCanDismiss()} without additional
   * checks or translation.
   *
   * @return {@code true} if the target allows user dismissal; {@code false} otherwise.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public boolean userCanDismiss() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.userCanDismiss();
  }

  /**
   * Returns the title of the current target alert. Requires a target to be attached.
   *
   * <p>The proxy does not alter the title; it forwards the value unchanged.
   *
   * @return the target alert’s localized title suitable for headers and list displays.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public String getTitle() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.getTitle();
  }

  /**
   * Returns the plain-text body of the current target alert. Requires a target to be attached.
   *
   * <p>Callers that prefer richer presentation should use {@link #getHTMLText()} when the target
   * provides HTML content.
   *
   * @return the target alert’s plain-text description; never {@code null} for a valid target.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public String getText() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.getText();
  }

  /**
   * Returns the HTML fragment of the current target alert when available. Requires a target to be
   * attached.
   *
   * <p>When the target does not supply HTML, callers should fall back to {@link #getText()}.
   *
   * @return an {@code HTMLNode} representing the target’s HTML content, or {@code null} if the
   *     target does not provide one.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public HTMLNode getHTMLText() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.getHTMLText();
  }

  /**
   * Returns the priority class of the current target alert. Requires a target to be attached.
   *
   * <p>The value is one of the constants defined on {@link UserAlert} and is forwarded verbatim.
   *
   * @return the target alert’s priority class indicating severity and display prominence.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public short getPriorityClass() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.getPriorityClass();
  }

  /**
   * Reports whether the proxy is currently valid and should be displayed. The proxy is considered
   * valid only when a target alert is attached and that target reports itself as valid.
   *
   * @return {@code true} when a non-{@code null} target exists and is valid; otherwise {@code
   *     false}.
   */
  @Override
  public boolean isValid() {
    return alert != null && alert.isValid();
  }

  /**
   * Forwards a validity update to the current target alert when present. If no target is attached,
   * this method is a no-op.
   *
   * <p>Implementations of the target may ignore changes when they are not user-dismissible.
   *
   * @param validity {@code true} to mark the target valid and visible; {@code false} to hide it.
   */
  @Override
  public void isValid(boolean validity) {
    if (alert != null) alert.isValid(validity);
  }

  /**
   * Returns the label to display on a dismiss control for the current target alert. Requires a
   * target to be attached.
   *
   * @return the target alert’s localized dismissal button text; may be {@code null} when not
   *     applicable.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public String dismissButtonText() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.dismissButtonText();
  }

  /**
   * Indicates whether the current target alert should be unregistered when dismissed. Requires a
   * target to be attached.
   *
   * @return {@code true} if dismissing the target should unregister it from its manager; otherwise
   *     {@code false}.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.shouldUnregisterOnDismiss();
  }

  /**
   * Notifies the current target alert that it has been dismissed. If no target is attached, the
   * method returns without effect.
   */
  @Override
  public void onDismiss() {
    if (alert != null) alert.onDismiss();
  }

  /**
   * Returns a short, stable identifier for this proxy instance suitable for use as an anchor in
   * feeds or fragment links. The value is derived from this proxy’s {@link #hashCode()} and does
   * not depend on the current target. It remains constant for the lifetime of the proxy instance
   * but is not guaranteed to persist across process restarts.
   *
   * @return a proxy-specific anchor in the form {@code "anchor:" + hashCode()} without spaces.
   */
  @Override
  public String anchor() {
    return "anchor:" + hashCode();
  }

  /**
   * Returns a concise, single-line summary of the current target alert. Requires a target to be
   * attached.
   *
   * @return the target alert’s short text suitable for compact UI contexts.
   * @throws NullPointerException when no target is currently attached.
   */
  @Override
  public String getShortText() {
    UserAlert a = Objects.requireNonNull(alert);
    return a.getShortText();
  }

  /**
   * Reports whether the current target alert is an event-style notification. If no target is
   * attached, this method returns {@code false}.
   *
   * @return {@code true} when a target exists and is an event notification; {@code false} when no
   *     target is attached or the target reports non-event status.
   */
  @Override
  public boolean isEventNotification() {
    if (alert == null) return false;
    return alert.isEventNotification();
  }
}
