package network.crypta.runtime.alerts.feed;

import java.util.Objects;

/**
 * Immutable runtime-side snapshot of the common fields shared by user-alert feed events.
 *
 * <p>This record is the smallest transport-neutral representation of an alert that still carries
 * the text shown to operators and external clients. Runtime alert implementations construct it when
 * they need only the basic header, summary, body text, priority class, and update timestamp.
 * Higher-level feed variants such as bookmark or URI announcements build on the same shape by
 * adding node-to-node metadata and payload-specific fields.
 *
 * <p>The record is intentionally simple: it owns only runtime concepts, it does not reference FCP
 * classes, and it is safe to hand across subsystem boundaries without additional locking or
 * copying. The {@code text} field is required because downstream feed bridges encode it as the
 * primary payload body.
 *
 * @param header short one-line title shown most prominently when clients render the alert
 * @param shortText secondary summary line that gives clients a concise preview of the alert
 * @param text full alert body text that downstream bridges encode into the feed payload
 * @param priorityClass numeric severity or priority class preserved from the originating alert
 * @param updatedTime epoch-millisecond timestamp describing when the originating alert last changed
 * @see BookmarkUserAlertFeedEvent
 * @see UriUserAlertFeedEvent
 * @see TextUserAlertFeedEvent
 */
public record BasicUserAlertFeedEvent(
    String header, String shortText, String text, short priorityClass, long updatedTime)
    implements UserAlertFeedEvent {

  /**
   * Creates a runtime-owned basic feed event snapshot.
   *
   * <p>The constructor performs only the validation needed to keep downstream encoding predictable.
   * It accepts nullable {@code header} and {@code shortText} values because existing alerts may
   * omit one or both summaries, but it requires a non-null body text because the feed bridge always
   * serializes the main text payload.
   *
   * @param header short one-line title shown most prominently when clients render the alert
   * @param shortText secondary summary line that gives clients a concise preview of the alert
   * @param text full alert body text that downstream bridges encode into the feed payload
   * @param priorityClass numeric severity or priority class preserved from the originating alert
   * @param updatedTime epoch-millisecond timestamp describing when the originating alert last
   *     changed
   * @throws NullPointerException if {@code text} is {@code null} and the payload would be undefined
   */
  public BasicUserAlertFeedEvent {
    Objects.requireNonNull(text, "text");
  }
}
