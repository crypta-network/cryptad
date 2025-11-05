package network.crypta.client.events;

/**
 * Event indicating the producer's best-known expected size for a file or payload.
 *
 * <p>This lightweight, immutable value object is emitted by client operations when an estimated or
 * known content size becomes available. The value can be used to pre‑allocate buffers, present a
 * progress bar with a determinate maximum, or inform downstream logic about likely resource
 * requirements. The class carries a stable {@linkplain #getCode() numeric code} suitable for
 * filtering and a concise, human‑readable {@linkplain #getDescription() description} for logs or
 * user interfaces.
 *
 * <p>The {@link #expectedSize} is expressed in bytes and represented as a signed {@code long}. The
 * producing component defines the precise semantics (for example, whether negative values are used
 * as sentinels); consumers should therefore tolerate very large values and handle negative or
 * unknown sizes defensively. Instances are thread‑safe and read‑only by construction and can be
 * freely shared between threads without additional synchronization.
 *
 * <ul>
 *   <li><b>Responsibility:</b> convey an expected byte size to listeners.
 *   <li><b>Immutability:</b> fields are final; no setters or mutators.
 *   <li><b>Typical usage:</b> create, then dispatch through a {@link ClientEvent} pipeline.
 * </ul>
 *
 * <pre>{@code
 * // Example: create and forward the event
 * ClientEvent evt = new ExpectedFileSizeEvent(1024L);
 * int code = evt.getCode();           // stable identifier for routing
 * String desc = evt.getDescription(); // "Expected file size: 1024"
 * }</pre>
 *
 * @see ClientEvent
 */
public class ExpectedFileSizeEvent implements ClientEvent {

  /**
   * The expected size expressed in bytes as reported by the producer.
   *
   * <p>This value may reflect either an exact known size or an estimate, depending on the producing
   * component. It is represented as a signed {@code long} to accommodate very large content. While
   * callers often interpret non‑negative values as valid sizes, consumers should not assume a
   * particular sentinel for unknown values and should be resilient to negative numbers.
   */
  public final long expectedSize;

  /**
   * Creates a new event carrying the given expected size in bytes.
   *
   * <p>The constructor performs no validation and stores the value verbatim so that downstream
   * consumers can apply their own interpretation rules. Instances created via this constructor are
   * immutable and safe for publication across threads.
   *
   * @param size the expected size in bytes as provided by the producer; may be very large and may
   *     be negative depending on producer semantics; never {@code null} because it is a primitive
   *     value.
   */
  public ExpectedFileSizeEvent(long size) {
    expectedSize = size;
  }

  static final int CODE = 0x0C;

  /** {@inheritDoc} */
  @Override
  public int getCode() {
    return CODE;
  }

  /**
   * Returns a concise description intended for logs and user interfaces.
   *
   * <p>The description embeds the expected size in bytes and is stable enough for operators to
   * recognize recurring conditions. It is not intended for machine parsing; use {@link #getCode()}
   * and {@link #expectedSize} for programmatic handling.
   *
   * @return a non‑{@code null} human‑readable sentence including the expected byte size; callers do
   *     not take ownership of the returned instance.
   */
  @Override
  public String getDescription() {
    return "Expected file size: " + expectedSize;
  }
}
