package network.crypta.client.events;

import network.crypta.client.InsertContext.CompatibilityMode;

/**
 * Event describing the compatibility window and encoding flags chosen for a splitfile operation.
 *
 * <p>This value object is emitted by higher-level insert/fetch logic to announce the selected
 * {@link CompatibilityMode} range a splitfile should honor as it is encoded or interpreted, along
 * with auxiliary properties that influence the on-disk representation. The event is useful for
 * operators and UIs that want to display why a particular splitfile layout was picked, and for
 * programmatic consumers that gate behavior based on a stable event code exposed via {@link
 * #getCode()}.
 *
 * <p>Instances carry a lower and upper bound for compatibility, an optional cryptographic key
 * associated with the splitfile, and two booleans that indicate compression and layer context. The
 * fields are final; however, the {@code byte[]} reference is exposed directly and is not copied. Do
 * not modify its contents after construction. Treat instances as read-mostly; mutating the array
 * would be visible to other threads and consumers.
 *
 * <ul>
 *   <li>Responsibilities: convey the selected compatibility window and related flags.
 *   <li>Immutability: fields are final; the key array must be treated as read-only.
 *   <li>Thread-safety: safe for concurrent reads when the array is not mutated by callers.
 * </ul>
 *
 * @see ClientEvent
 * @see CompatibilityMode
 */
public class SplitfileCompatibilityModeEvent implements ClientEvent {

  /**
   * The minimum {@link CompatibilityMode} that the operation must satisfy.
   *
   * <p>This lower bound constrains how data is laid out so previously deployed readers can still
   * process the splitfile. It is typically determined by configuration or the environment’s
   * defaults. The value is inclusive; producers choose parameters at or above this level depending
   * on the {@link #maxCompatibilityMode} bound.
   */
  public final CompatibilityMode minCompatibilityMode;

  /**
   * The maximum {@link CompatibilityMode} that the operation may target.
   *
   * <p>This upper bound allows newer, more efficient layouts to be used when available while still
   * honoring {@link #minCompatibilityMode}. It is inclusive and represents the highest mode that a
   * consumer of the resulting data is expected to understand.
   */
  public final CompatibilityMode maxCompatibilityMode;

  /**
   * Opaque cryptographic key material associated with the splitfile, if any.
   *
   * <p>The contents and length are defined by upstream components. The reference is stored as is
   * and not defensively copied; callers must not modify the array after passing it to the
   * constructor. The field may be {@code null} when no key is applicable for the current context.
   */
  public final byte[] splitfileCryptoKey;

  /**
   * Whether compression should be disabled for the relevant splitfile layer.
   *
   * <p>When {@code true}, producers skip applying compression for the associated portion of the
   * splitfile, preserving exact bytes at the cost of larger size. When {@code false}, compression
   * policy is left to the producer’s defaults.
   */
  public final boolean dontCompress;

  /**
   * Whether the event pertains specifically to the bottom layer of the splitfile.
   *
   * <p>This flag allows consumers to distinguish configuration for the lowest layer (data blocks)
   * from higher metadata or header layers, which may be treated differently by encoders.
   */
  public final boolean bottomLayer;

  /**
   * Stable integer identifier for this event kind.
   *
   * <p>The code can be used for programmatic routing, counters, or filtering policies in logs and
   * UIs. The value is stable within the producing component and equals {@code 0x0D}.
   */
  public static final int CODE = 0x0D;

  /**
   * Returns the stable integer identifier for this event type.
   *
   * <p>Clients may switch on this code to aggregate metrics or to route the event to specialized
   * handlers. The value is constant for all instances of this class and does not depend on field
   * contents.
   *
   * @return a stable integer code identifying the compatibility-mode event; suitable for
   *     comparisons and counters across instances.
   */
  @Override
  public int getCode() {
    return CODE;
  }

  /**
   * Returns a concise, human-readable summary of the compatibility range.
   *
   * <p>The description lists the lower and upper {@link CompatibilityMode} bounds selected for the
   * splitfile. It is intended for logs, progress displays, and diagnostics and should not be parsed
   * programmatically. Use {@link #getCode()} for machine handling when needed.
   *
   * <pre>{@code
   * // Example: record the chosen window
   * LOG.info("Selected: {}", event.getDescription());
   * }</pre>
   *
   * @return a non-null summary describing the minimum and maximum compatibility modes in plain
   *     text; callers must treat the returned string as read-only.
   */
  @Override
  public String getDescription() {
    return "CompatibilityMode between " + minCompatibilityMode + " and " + maxCompatibilityMode;
  }

  /**
   * Creates a new event with the provided compatibility window and flags.
   *
   * <p>The array reference for {@code splitfileCryptoKey} is stored directly and is not copied.
   * Pass a fresh or immutable instance if later modification is a concern. Booleans control
   * compression policy and layer context used by producers or UIs.
   *
   * @param min the lower, inclusive {@link CompatibilityMode} bound to honor; must not be {@code
   *     null} when a concrete mode is required by the producer.
   * @param max the upper, inclusive {@link CompatibilityMode} bound allowed for encoding; must not
   *     be {@code null} when a concrete mode is required by the producer.
   * @param splitfileCryptoKey optional key bytes associated with the splitfile; reference is stored
   *     as-is and must not be mutated after construction; may be {@code null}.
   * @param dontCompress {@code true} to disable compression for the relevant layer; {@code false}
   *     to allow default compression behavior.
   * @param bottomLayer {@code true} when the configuration applies to the bottom layer; otherwise
   *     refers to a higher layer or global context.
   */
  public SplitfileCompatibilityModeEvent(
      CompatibilityMode min,
      CompatibilityMode max,
      byte[] splitfileCryptoKey,
      boolean dontCompress,
      boolean bottomLayer) {
    this.minCompatibilityMode = min;
    this.maxCompatibilityMode = max;
    this.splitfileCryptoKey = splitfileCryptoKey;
    this.dontCompress = dontCompress;
    this.bottomLayer = bottomLayer;
  }
}
