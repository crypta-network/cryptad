package network.crypta.runtime.alerts;

import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.support.HTMLNode;

/**
 * Abstract base implementation of a {@link UserAlert} that centralizes common storage and
 * boilerplate for user-facing alerts. Subclasses provide human-readable content (plain and optional
 * HTML), and may override behavior such as dismissal handling, validity updates, and feed
 * serialization.
 *
 * <p>Usage typically follows a read-mostly pattern: producers construct an alert and register it
 * with a manager; consumers read fields under appropriate synchronization to render a coherent
 * snapshot. The class stores a creation/update timestamp returned from {@link #getUpdatedTime()}, a
 * severity via {@link #getPriorityClass()}, and whether an end user may dismiss the alert via
 * {@link #userCanDismiss()}.
 *
 * <p>Concurrency: instances are not intrinsically thread-safe. Callers that read multiple fields to
 * present an alert should synchronize on the instance, check {@link #isValid()}, and then read the
 * remaining values to ensure a consistent view. Implementations that mutate state should do so in a
 * manner that external consumers can stabilize via said synchronization.
 *
 * <ul>
 *   <li>Responsibilities
 *       <ul>
 *         <li>Capture title, short/long text, and optional HTML fragment.
 *         <li>Track severity and default dismissal behavior.
 *         <li>Provide an {@link network.crypta.clients.fcp.FCPMessage FCP} representation for
 *             remote subscribers.
 *       </ul>
 * </ul>
 *
 * @author David &lsquo;Bombe&rsquo; Roden &lt;bombe@freenetproject.org&gt;
 * @version $Id$
 * @see UserAlert
 */
public abstract class AbstractUserAlert implements UserAlert {

  private final boolean userCanDismiss;
  private final String title;
  private final String text;
  private final String shortText;
  private final HTMLNode htmlText;
  private final short priorityClass;

  /**
   * Flag indicating whether this alert should currently be shown to end users. Consumers should
   * treat this value as read-mostly and take a consistent snapshot under synchronization when they
   * need to read multiple fields together.
   */
  protected boolean valid;

  private final String dismissButtonText;
  private final boolean shouldUnregisterOnDismiss;
  private final long creationTime;

  /**
   * Creates a default, valid alert with no title, text, or HTML content. Subclasses that use this
   * constructor typically override the content accessors and other behavior as needed before
   * registration.
   */
  protected AbstractUserAlert() {
    this.userCanDismiss = false;
    this.title = null;
    this.text = null;
    this.htmlText = null;
    this.priorityClass = 0;
    this.valid = true;
    this.dismissButtonText = null;
    this.shouldUnregisterOnDismiss = false;
    this.shortText = null;
    creationTime = System.currentTimeMillis();
  }

  /**
   * Creates an alert with explicit presentation, severity, and dismissal characteristics.
   *
   * <p>This constructor does not perform defensive copies; callers should avoid mutating the
   * contained values after construction. Callers may pass {@code null} for the {@code body} when a
   * subclass overrides content accessors.
   *
   * @param userCanDismiss whether a user interface should offer a dismiss control; when set to
   *     {@code false}, only producers should unregister or invalidate the alert.
   * @param title localized, succinct title suitable for list headers and notification banners; may
   *     be {@code null} if subclasses override {@link #getTitle()}.
   * @param body bundle of full plain text, short summary, and optional HTML fragment; callers may
   *     pass {@code null} when content is provided by overriding methods.
   * @param priorityClass severity class as one of {@link UserAlert#CRITICAL_ERROR}, {@link
   *     UserAlert#ERROR}, {@link UserAlert#WARNING}, or {@link UserAlert#MINOR}.
   * @param valid initial visibility flag; when {@code false}, the alert starts hidden until a
   *     producer revalidates it.
   * @param dismissOptions label and unregister policy for the dismissal action; may be {@code null}
   *     when callers do not want to expose a specific label or unregister behavior.
   */
  protected AbstractUserAlert(
      boolean userCanDismiss,
      String title,
      Body body,
      short priorityClass,
      boolean valid,
      DismissOptions dismissOptions) {
    this.userCanDismiss = userCanDismiss;
    this.title = title;
    this.text = body == null ? null : body.text();
    this.shortText = body == null ? null : body.shortText();
    this.htmlText = body == null ? null : body.htmlText();
    this.priorityClass = priorityClass;
    this.valid = valid;
    this.dismissButtonText = dismissOptions == null ? null : dismissOptions.dismissButtonText();
    this.shouldUnregisterOnDismiss =
        dismissOptions != null && dismissOptions.shouldUnregisterOnDismiss();
    creationTime = System.currentTimeMillis();
  }

  /** {@inheritDoc} */
  @Override
  public boolean userCanDismiss() {
    return userCanDismiss;
  }

  /** {@inheritDoc} */
  @Override
  public String getTitle() {
    return title;
  }

  /** {@inheritDoc} */
  @Override
  public String getText() {
    return text;
  }

  @Override
  public String getShortText() {
    return shortText;
  }

  /** {@inheritDoc} */
  @Override
  public HTMLNode getHTMLText() {
    return htmlText;
  }

  /** {@inheritDoc} */
  @Override
  public short getPriorityClass() {
    return priorityClass;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isValid() {
    return valid;
  }

  /** {@inheritDoc} */
  @Override
  public void isValid(boolean valid) {
    if (userCanDismiss()) {
      this.valid = valid;
    }
  }

  /** {@inheritDoc} */
  @Override
  public String dismissButtonText() {
    return dismissButtonText;
  }

  /** {@inheritDoc} */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    return shouldUnregisterOnDismiss;
  }

  /** {@inheritDoc} */
  @Override
  public void onDismiss() {}

  @Override
  public String anchor() {
    return Integer.toString(hashCode());
  }

  @Override
  public boolean isEventNotification() {
    return false;
  }

  /**
   * Reports whether this alert should be treated as an event entry rather than a persistent
   * operational alert. The default implementation returns {@code false}; subclasses that represent
   * transient activity may override to return {@code true}.
   *
   * @return {@code true} for event-style notifications, {@code false} otherwise.
   */
  public boolean isEvent() {
    return false;
  }

  @Override
  public long getUpdatedTime() {
    return creationTime;
  }

  @Override
  public FCPMessage getFCPMessage() {
    return new FeedMessage(
        getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
  }

  /**
   * Bundles the textual and optional HTML content of an alert.
   *
   * <p>Instances are immutable value carriers used to pass content into the base constructor. When
   * HTML is provided, it should be a safe, embeddable fragment and not rely on external scripts or
   * styles. Callers may pass {@code null} to convey the absence of a particular component.
   *
   * @param text full, plain-text body suitable for text-only renderers; may be {@code null} when
   *     the alert provides content dynamically.
   * @param shortText compact summary intended for constrained placements such as notifications; may
   *     be {@code null} if not applicable.
   * @param htmlText structured HTML fragment for richer rendering; may be {@code null} when only
   *     plain text is available.
   */
  public record Body(String text, String shortText, HTMLNode htmlText) {
    /**
     * Factory method for convenience when constructing a {@link Body} with the three content
     * components.
     *
     * @param text full, plain-text body; may be {@code null}.
     * @param shortText compact summary for constrained UI; may be {@code null}.
     * @param htmlText optional HTML fragment for rich presentation; may be {@code null}.
     * @return an immutable {@link Body} carrying the provided content components.
     */
    public static Body of(String text, String shortText, HTMLNode htmlText) {
      return new Body(text, shortText, htmlText);
    }
  }

  /**
   * Encapsulates dismissal-related options for an alert.
   *
   * <p>The button text is intended for direct display and should be localized. The unregister flag
   * indicates whether a dismissal should also remove the alert from its manager, rather than just
   * marking it invalid.
   *
   * @param dismissButtonText localized label to show on the dismiss action; may be {@code null} to
   *     use a default or omit the label entirely.
   * @param shouldUnregisterOnDismiss when {@code true}, dismissal should unregister the alert from
   *     the manager; when {@code false}, producers typically handle lifecycle explicitly.
   */
  public record DismissOptions(String dismissButtonText, boolean shouldUnregisterOnDismiss) {}
}
