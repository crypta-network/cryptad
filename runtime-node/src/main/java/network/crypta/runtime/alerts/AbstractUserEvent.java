package network.crypta.runtime.alerts;

/**
 * Skeleton base class for user-facing event notifications.
 *
 * <p>An {@code AbstractUserEvent} bridges the general alert machinery provided by {@link
 * AbstractUserAlert} with the categorical semantics of {@link UserEvent}. Subclasses typically
 * represent discrete occurrences such as successful uploads/downloads or background activities like
 * opennet announcing. The base class centralizes the common alert presentation aspects (title,
 * body, priority, validity, and dismissal policy) while carrying an associated {@linkplain
 * UserEvent.Type event type} for UI grouping and filtering.
 *
 * <p><strong>When to use:</strong> extend this class when you need a lightweight, mostly immutable
 * carrier for one-off, user-visible events that should be surfaced via the regular alert channels
 * and possibly aggregated in a “recent events” view. Construct an instance with the detailed
 * constructor when you have all presentation metadata available, or subclass with the no‑argument
 * constructor and override accessors to compute text on demand.
 *
 * <p><strong>Concurrency:</strong> instances are intended to be read‑mostly. The base class does
 * not provide intrinsic synchronization; consumers that need a consistent snapshot across multiple
 * fields should synchronize externally. Implementations should avoid heavy work in accessors and
 * prefer immutable fields where possible.
 *
 * <ul>
 *   <li><em>Responsibilities:</em> hold presentation data, expose severity, and provide an event
 *       category.
 *   <li><em>Notable behaviors:</em> UIs may use {@link UserEvent.Type#unregisterIndefinitely()} to
 *       suppress future events of the same category after dismissal.
 * </ul>
 *
 * @see AbstractUserAlert
 * @see UserEvent
 * @see UserEvent.Type
 */
public abstract class AbstractUserEvent extends AbstractUserAlert implements UserEvent {

  /**
   * Bundles presentation, severity, and dismissal metadata for user events.
   *
   * <p>This record consolidates parameters commonly supplied when constructing events, including
   * the {@link UserEvent.Type}, display content, priority, validity, and dismissal options.
   *
   * @param eventType categorical type used for grouping and suppression decisions
   * @param userCanDismiss whether a user interface should show a Dismiss control
   * @param title localized event title; may be {@code null}
   * @param body bundle containing full text, short text, and optional HTML fragment; may be {@code
   *     null}
   * @param priorityClass severity class such as {@link UserAlert#CRITICAL_ERROR}
   * @param valid initial visibility flag
   * @param dismissOptions label and unregister policy for dismissal
   */
  public record UserEventDetails(
      Type eventType,
      boolean userCanDismiss,
      String title,
      Body body,
      short priorityClass,
      boolean valid,
      DismissOptions dismissOptions) {}

  private Type eventType;

  /**
   * Creates an event with explicit presentation details and a categorical {@link UserEvent.Type}.
   *
   * <p>This constructor accepts a consolidated {@link AbstractUserAlert.Body Body} and {@link
   * AbstractUserAlert.DismissOptions DismissOptions} to keep parameters concise. It does not
   * defensively copy inputs; callers should refrain from mutating the provided values after
   * construction. The supplied {@code body} and {@code dismissOptions} may be {@code null} when a
   * subclass overrides the relevant accessors or when defaults are acceptable.
   *
   * <pre>{@code
   * // Example: constructing a transient, dismissible info event
   * var evt = new MyEvent(
   *     UserEvent.Type.GET_COMPLETED, true, "Download finished",
   *     AbstractUserAlert.Body.of("All parts verified.", "Download done", null),
   *     UserAlert.MINOR, true,
   *     new AbstractUserAlert.DismissOptions("OK", true));
   * }</pre>
   *
   * @param eventType category used by UIs to group and filter; implementations should supply a
   *     stable value for the lifetime of the event.
   * @param userCanDismiss whether user interfaces may present a dismiss control; {@code false}
   *     indicates producers control lifecycle explicitly.
   * @param title localized, succinct title shown in lists and notifications; may be {@code null} if
   *     subclasses override {@link #getTitle()}.
   * @param body bundle containing full text, short text, and optional HTML fragment; may be {@code
   *     null} if content is provided by overriding methods.
   * @param priorityClass severity class, one of {@link UserAlert#CRITICAL_ERROR}, {@link
   *     UserAlert#ERROR}, {@link UserAlert#WARNING}, or {@link UserAlert#MINOR}.
   * @param valid initial visibility flag; when {@code false}, the event starts hidden until
   *     revalidated by the producer.
   * @param dismissOptions label and unregister policy for dismissal; may be {@code null} to use
   *     defaults or omit a custom label.
   */
  protected AbstractUserEvent(
      Type eventType,
      boolean userCanDismiss,
      String title,
      Body body,
      short priorityClass,
      boolean valid,
      DismissOptions dismissOptions) {
    super(userCanDismiss, title, body, priorityClass, valid, dismissOptions);
    this.eventType = eventType;
  }

  /**
   * Creates an event using a consolidated parameter bundle.
   *
   * <p>This constructor mirrors the explicit argument constructor but accepts a {@link
   * UserEventDetails} so callers can share common parameter groupings across event types.
   *
   * @param details bundled event presentation and dismissal metadata
   */
  protected AbstractUserEvent(UserEventDetails details) {
    this(
        details.eventType(),
        details.userCanDismiss(),
        details.title(),
        details.body(),
        details.priorityClass(),
        details.valid(),
        details.dismissOptions());
  }

  /**
   * Creates an event with default presentation values; subclasses provide content via overrides.
   *
   * <p>This convenience constructor delegates to the protected base constructor with neutral
   * defaults. Subclasses that use it should override {@link #getEventType()} to provide a non-null
   * category for grouping. Typical overrides also supply title and body text by overriding the
   * corresponding accessors in {@link AbstractUserAlert}.
   */
  protected AbstractUserEvent() {}

  /**
   * Returns this event’s categorical type for UI policy and grouping decisions.
   *
   * <p>The returned value is intended to be stable once the event is constructed. Implementations
   * may compute it dynamically when using the no‑argument constructor; such implementations should
   * still return a consistent value across calls.
   *
   * @return the associated {@link UserEvent.Type}; consumers should not assume a particular
   *     cardinality or ordering across types.
   */
  @Override
  public Type getEventType() {
    return eventType;
  }
}
