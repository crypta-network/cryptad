package network.crypta.client.events;

import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Event published when the client begins compressing content prior to storage or upload.
 *
 * <p>This event marks the moment the insertion pipeline switches from raw input to a compressed
 * representation. It carries the chosen compressor type so UIs and diagnostics can surface what
 * algorithm is being used. Instances of this class are immutable and thread-safe to read after
 * construction: a producer creates the event once and passes it to interested listeners without
 * further mutation. The event does not start or manage compression; it is strictly a notification
 * describing that compression is about to be attempted for the current item.
 *
 * <p>Typical flows emit this event shortly before bytes are fed to the compressor and will later
 * publish a corresponding completion/failure event. Consumers generally log the transition,
 * annotate progress, or update user-facing status. If {@code codec} is {@code null}, callers must
 * avoid dereferencing it; in particular, {@link #getDescription()} requires a non-{@code null}
 * codec. No delivery guarantees are provided by this type; ordering and fan-out are determined by
 * the surrounding event system.
 *
 * <ul>
 *   <li>Immutable snapshot of the selected compressor type
 *   <li>Emitted when compression is about to begin
 *   <li>Safe to share across threads after construction
 * </ul>
 *
 * @see network.crypta.client.events.FinishedCompressionEvent
 * @see network.crypta.client.events.ClientEventProducer
 * @see COMPRESSOR_TYPE
 */
public class StartedCompressionEvent implements ClientEvent {

  /**
   * The compressor algorithm selected for this operation.
   *
   * <p>This value reflects the upstream choice at the time the event is created. It is immutable
   * and may be {@code null} when the selection is deferred; callers that need a human-friendly
   * label should verify non-null before dereferencing.
   */
  public final COMPRESSOR_TYPE codec;

  /**
   * Creates a new event describing the start of a compression attempt.
   *
   * <p>The constructor records the compressor type that upstream code selected for the current
   * item. The instance is intended to be passed to an event producer immediately after creation.
   * Passing {@code null} is permitted, but note that some consumers, including {@link
   * #getDescription()}, assume a non-{@code null} codec and will throw a {@link
   * NullPointerException} if it is missing.
   *
   * @param codec the compressor algorithm that will be used for this operation; may be {@code null}
   *     if unknown at emit time, but consumers that render a description require a non-{@code null}
   *     value.
   */
  public StartedCompressionEvent(COMPRESSOR_TYPE codec) {
    this.codec = codec;
  }

  // Stable identifier for this event type
  static final int CODE = 0x08;

  /**
   * Returns a human-readable description of the event and selected codec.
   *
   * <p>The string is suitable for logs, progress panels, or diagnostics and includes the
   * human-friendly name exposed by the {@code codec}. The result does not contain sensitive file
   * details and is stable for a given codec value.
   *
   * @return a concise message indicating that compression started with the specified codec; the
   *     returned string is owned by the caller and may be cached.
   * @throws NullPointerException if {@link #codec} is {@code null} and its name is dereferenced
   */
  @Override
  public String getDescription() {
    return "Started compression attempt with " + codec.codecName;
  }

  /**
   * Returns the stable integer code that identifies this event type.
   *
   * <p>The code is intended for compact transport or storage and remains constant across releases
   * where compatibility is maintained. Consumers should not infer ordering or severity from the
   * numeric value.
   *
   * @return the constant {@code 0x08}, the identifier for {@code StartedCompressionEvent}
   */
  @Override
  public int getCode() {
    return CODE;
  }
}
