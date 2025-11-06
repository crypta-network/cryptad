package network.crypta.client.events;

/**
 * Event indicating the producer's currently expected MIME type for a payload or response.
 *
 * <p>This lightweight, immutable value object communicates content-type expectations to listeners
 * and user interfaces. Producers emit the event when they can infer or determine a MIME type ahead
 * of actually producing or receiving the bytes (for example, after parsing headers, reading a
 * manifest, or inspecting metadata). Downstream components can use this information to prime
 * renderers, select decoders, validate responses, or simply display a helpful hint to operators.
 * The class carries a stable {@linkplain #getCode() numeric code} for programmatic routing and a
 * concise {@linkplain #getDescription() description} suitable for logs and status panels.
 *
 * <p>Instances are thread-safe and read-only by construction: all fields are {@code final}, and no
 * mutation is provided. The {@link #expectedMIMEType} value is stored verbatim as supplied by the
 * producer; consumers should therefore tolerate variants such as parameters (e.g., {@code
 * "text/html; charset=UTF-8"}) or case differences. When the type is unknown, producers may supply
 * {@code null} and listeners should handle that case conservatively (for example, by falling back
 * to generic handling).
 *
 * <ul>
 *   <li><b>Responsibility:</b> surface the MIME type that the client currently expects.
 *   <li><b>Typical usage:</b> create an instance, then dispatch through a {@link ClientEvent}
 *       pipeline to interested listeners.
 *   <li><b>Scope:</b> conveys metadata only; it does not enforce validation or decoding.
 * </ul>
 *
 * @see ClientEvent
 */
public class ExpectedMIMEEvent implements ClientEvent {

  /**
   * Stable identifier for this event kind.
   *
   * <p>The value supports programmatic routing, filtering, and metrics. It remains constant across
   * releases for compatibility with downstream consumers that key on event codes.
   */
  static final int CODE = 0x0B;

  /**
   * The MIME type string that the producer expects for the associated content.
   *
   * <p>The value is stored as provided by the emitter and may be {@code null} when the type is not
   * yet known. It may include optional parameters (for example, a {@code charset}) and should be
   * treated as read-only by consumers. No normalization or validation is performed here.
   */
  public final String expectedMIMEType;

  /**
   * Creates a new event with the given expected MIME type string.
   *
   * <p>The constructor performs no validation or canonicalization. Callers may pass a parameterized
   * MIME value (such as {@code "application/json; charset=UTF-8"}) or {@code null} when the type is
   * unknown. Instances created via this constructor are immutable and safe to share across threads.
   *
   * @param type the expected MIME type string as reported by the producer; may be {@code null} when
   *     unknown and may include parameters; callers should avoid mutating referenced data after
   *     publishing the event.
   */
  public ExpectedMIMEEvent(String type) {
    this.expectedMIMEType = type;
  }

  /** {@inheritDoc} */
  @Override
  public int getCode() {
    return CODE;
  }

  /**
   * Returns a concise human-readable description including the expected MIME type.
   *
   * <p>The string is intended for logs and status displays and is not meant for machine parsing.
   * Use {@link #getCode()} and {@link #expectedMIMEType} for programmatic handling.
   *
   * @return a non-{@code null} sentence summarizing the expected MIME type; callers do not take
   *     ownership of the returned instance.
   */
  @Override
  public String getDescription() {
    return "Expected MIME type: " + expectedMIMEType;
  }
}
