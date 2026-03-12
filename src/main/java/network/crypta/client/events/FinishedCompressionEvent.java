package network.crypta.client.events;

/**
 * Event published when an attempted compression step has finished and the final sizes are known.
 *
 * <p>This value object is part of the client-facing event stream and captures the outcome of a
 * single compression attempt performed by a higher-level operation (for example, a splitfile
 * insert). It records which codec identifier was used as well as the original, uncompressed size
 * and the resulting compressed size. Consumers typically use this to produce progress logs, surface
 * metrics, or decide whether the compressed form should be retained. The class is immutable and
 * thread-safe for concurrent read access once constructed.
 *
 * <p>Typical usage is to create an instance after a compressor finishes and dispatch it to any
 * registered listeners alongside other progress events. When {@link #codec} is {@code -1}, the
 * payload is uncompressed and {@link #compressedSize} is expected to equal {@link #originalSize}.
 * No I/O or computation happens inside this type; it merely conveys already-computed values.
 *
 * <ul>
 *   <li>Responsibilities: carry the codec identifier and size figures after compression.
 *   <li>Mutability: immutable; all fields are {@code final} and exposed for read-only use.
 *   <li>Thread-safety: safe for concurrent reads without external synchronization.
 * </ul>
 *
 * @see ClientEvent
 * @see StartedCompressionEvent
 */
public class FinishedCompressionEvent implements ClientEvent {

  /**
   * Stable code identifying this event kind within the client event set.
   *
   * <p>The numeric value remains constant across releases to support programmatic routing,
   * filtering, and metrics. It is returned by {@link #getCode()} and may be compared directly
   * against other event codes for equality.
   */
  static final int CODE = 0x09;

  /**
   * Compression codec identifier used for the attempt; {@code -1} denotes no compression.
   *
   * <p>The concrete mapping of integers to codec implementations is defined by higher-level
   * components. A value of {@code -1} indicates an uncompressed payload. The field is immutable and
   * safe to read concurrently.
   */
  public final int codec;

  /**
   * Size of the original, uncompressed data in bytes.
   *
   * <p>This value reflects the exact byte length of the input presented to the compressor. It is
   * non-negative and does not change after construction. Consumers may use it to compute
   * compression ratios or to validate that {@link #compressedSize} is sensible for the chosen
   * {@link #codec}.
   */
  public final long originalSize;

  /**
   * Size of the compressed output in bytes (or original size when uncompressed).
   *
   * <p>When {@link #codec} equals {@code -1}, this value typically matches {@link #originalSize}.
   * For successful compression attempts, it is less than or equal to the original size. The field
   * is immutable and suitable for use in logs, metrics, or UI summaries.
   */
  public final long compressedSize;

  /**
   * Creates a new event instance describing the outcome of a compression attempt.
   *
   * <p>The constructor accepts the codec identifier and the measured sizes in bytes. It does not
   * perform validation or I/O; callers are expected to supply consistent values. Instances are
   * immutable and safe to share across threads without further synchronization.
   *
   * @param codec integer identifier of the compression codec; use {@code -1} to indicate that the
   *     data remained uncompressed and that {@code compressedSize} should equal {@code origSize}.
   * @param origSize original uncompressed size in bytes; must be non-negative and represent the
   *     exact byte length of the input provided to the compressor.
   * @param compressedSize resulting size in bytes after applying the codec; for uncompressed data
   *     it should equal the original size; otherwise it is typically less than or equal to it.
   */
  public FinishedCompressionEvent(int codec, long origSize, long compressedSize) {
    this.codec = codec;
    this.originalSize = origSize;
    this.compressedSize = compressedSize;
  }

  /**
   * Returns a concise, human-readable summary of the compression outcome.
   *
   * <p>The description includes the codec identifier and both the original and compressed sizes in
   * bytes. It is intended for logs, user interfaces, or diagnostic output and is not guaranteed to
   * be stable for machine parsing.
   *
   * @return a short summary string describing the codec, original size, and compressed size in
   *     bytes; callers must treat the returned instance as read-only.
   */
  @Override
  public String getDescription() {
    return "Compressed data: codec="
        + codec
        + ", origSize="
        + originalSize
        + ", compressedSize="
        + compressedSize;
  }

  /**
   * Returns the stable numeric code that identifies this event type.
   *
   * <p>The value is suitable for programmatic routing, filtering, and metric labeling and is
   * guaranteed to match {@link #CODE}.
   *
   * @return the event identifier code that remains stable across releases; equal to {@link #CODE}.
   */
  @Override
  public int getCode() {
    return CODE;
  }
}
