package network.crypta.node;

/**
 * Null object implementation of both {@link SendableRequestItem} and {@link
 * SendableRequestItemKey}.
 *
 * <p>This class represents the absence of an actionable request item. It is used as a lightweight
 * sentinel in flows where a {@code SendableRequestItem} is required but no per-item state is
 * needed. The instance is immutable and stateless; callers typically reuse the shared {@link
 * #nullItem} to avoid allocations.
 *
 * <p>Behavior:
 *
 * <ul>
 *   <li>{@link #dump()} is a no-op.
 *   <li>{@link #getKey()} returns {@code this}, providing a stable sentinel identity. The default
 *       {@code equals} and {@code hashCode} from {@link Object} are sufficient for this singleton
 *       use.
 * </ul>
 */
@SuppressWarnings("java:S6548")
public class NullSendableRequestItem implements SendableRequestItem, SendableRequestItemKey {

  /**
   * Shared singleton instance for use wherever a placeholder item is required. The instance is
   * thread-safe and may be reused across requests.
   */
  public static final NullSendableRequestItem nullItem = new NullSendableRequestItem();

  /**
   * Creates a null-item sentinel.
   *
   * <p>Callers normally reuse {@link #nullItem} instead of allocating additional instances, but the
   * constructor remains public to preserve the historical surface of this lightweight marker type.
   */
  public NullSendableRequestItem() {}

  /** No-op for the null item; there are no resources to release. */
  @Override
  public void dump() {
    // No operation: this item holds no resources.
  }

  /**
   * Returns {@code this} as the identifying key.
   *
   * @return the singleton instance, used as a stable sentinel key
   */
  @Override
  public SendableRequestItemKey getKey() {
    return this;
  }
}
