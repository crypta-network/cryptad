package network.crypta.client;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.Nullable;

/**
 * Container for the data and client-provided context that make up a single insert operation.
 *
 * <p>This type groups a {@link RandomAccessBucket} carrying the payload, optional {@link
 * ClientMetadata}, and an optional desired {@link FreenetURI}. Instances are lightweight holders;
 * they do not perform I/O by themselves. The {@code RandomAccessBucket} is an external resource
 * that may own file descriptors or buffers. Callers should ensure it is eventually released by
 * invoking {@link #free()} or by transferring ownership via {@link #nullData()} when the bucket
 * becomes managed elsewhere.
 *
 * <p>Concurrency: state transitions that affect ownership ({@link #getData()}, {@link #nullData()},
 * and the synchronized portion of {@link #free()}) are serialized on {@code this}. The actual
 * {@code RandomAccessBucket#free()} call occurs outside the monitor to prevent blocking other
 * threads on potentially slow I/O.
 *
 * <ul>
 *   <li>Mutability: fields are mutable and can be nulled to denote transfer of ownership.
 *   <li>Lifecycle: newly constructed blocks start in the “owned” state; after {@link #free()} the
 *       data is no longer accessible via this instance.
 *   <li>Error handling: this class itself does not throw; underlying bucket operations may.
 * </ul>
 *
 * <p>WARNING: Changing non-transient members on classes that are Serializable can result in losing
 * uploads.
 */
public class InsertBlock implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Payload container for the insert. May be {@code null} after {@link #nullData()} or {@link
   * #free()}.
   */
  // Buckets are not serializable and are external resources; do not serialize them.
  @SuppressWarnings("java:S1948")
  private RandomAccessBucket data;

  /** Guard flag indicating whether {@link #free()} has been called and the bucket released. */
  private boolean isFreed;

  /**
   * Optional, caller-supplied target URI describing where the content is intended to be inserted.
   * When {@code null}, the insert mechanism selects or derives an appropriate key as needed.
   */
  @Nullable public FreenetURI desiredURI;

  /**
   * Optional metadata supplied by the client to accompany the insert. This object may carry a
   * content type or other advisory attributes; it is not interpreted by this class. May be {@code
   * null}.
   */
  @Nullable public ClientMetadata clientMetadata;

  /**
   * Creates a new {@code InsertBlock} with payload data and optional client context.
   *
   * <p>The {@code data} bucket is considered owned by this instance until either {@link #free()} is
   * called or ownership is transferred via {@link #nullData()}. If {@code metadata} is {@code
   * null}, a new {@link ClientMetadata} is created to ensure a non-null metadata holder is
   * available to downstream code.
   *
   * @param data the payload bucket to insert; must be non-null and open for reading; ownership is
   *     initially held by this instance until freed or explicitly disowned.
   * @param metadata optional client metadata; when {@code null}, a default {@link ClientMetadata}
   *     is created; callers may pass a mutable instance that they continue to own.
   * @param desiredURI optional desired target {@link FreenetURI}; when {@code null}, routing or key
   *     selection may occur elsewhere depending on the caller’s protocol.
   */
  public InsertBlock(
      RandomAccessBucket data, @Nullable ClientMetadata metadata, @Nullable FreenetURI desiredURI) {
    this.data = Objects.requireNonNull(data, "data");
    this.isFreed = false;
    if (metadata == null) clientMetadata = new ClientMetadata();
    else clientMetadata = metadata;
    this.desiredURI = desiredURI;
  }

  /**
   * Returns the payload bucket if still owned by this block.
   *
   * <p>When the block has been {@linkplain #free() freed} or when ownership was transferred via
   * {@link #nullData()}, this method returns {@code null}. Callers must not assume the returned
   * bucket remains valid if another thread may concurrently call {@link #free()}.
   *
   * @return the current {@link RandomAccessBucket} if not yet freed or disowned; otherwise {@code
   *     null}. The caller does not acquire ownership and should not free it here.
   */
  public synchronized RandomAccessBucket getData() {
    return (isFreed ? null : data);
  }

  /**
   * Releases the owned payload bucket, if any, and marks this block as freed.
   *
   * <p>This operation is safe to call multiple times; further invocations are no-ops. The method
   * synchronizes only during state transition and gets a local reference, then performs the
   * potentially slow {@link RandomAccessBucket#free()} call outside the monitor to avoid blocking
   * contending threads. After completion, {@link #getData()} will return {@code null}.
   */
  public void free() {
    RandomAccessBucket toFree;
    synchronized (this) {
      if (isFreed) return;
      isFreed = true;
      if (data == null) return;
      toFree = data;
      data = null;
    }
    // Call outside synchronized block to avoid holding the monitor during external I/O.
    toFree.free();
  }

  /**
   * Disowns the data bucket so it is not released by {@link #free()} through this instance.
   *
   * <p>Use this when ownership of the {@link RandomAccessBucket} has been transferred elsewhere and
   * the recipient will manage its lifecycle. After calling, {@link #getData()} returns {@code null}
   * and invoking {@link #free()} will not release the previously attached bucket.
   */
  public synchronized void nullData() {
    data = null;
  }

  /**
   * Clears the desired URI so it is not managed by this instance.
   *
   * <p>Use this when the {@link #desiredURI} has been handed off to other code that will manage or
   * resolve it. After calling, {@link #desiredURI} will be {@code null}.
   */
  public void nullURI() {
    this.desiredURI = null;
  }

  /**
   * Clears the client metadata reference to indicate it is handled elsewhere.
   *
   * <p>After calling, {@link #clientMetadata} will be {@code null}. Use this to avoid duplication
   * or double-disposal when metadata ownership moves to another component.
   */
  public void nullMetadata() {
    this.clientMetadata = null;
  }
}
