package network.crypta.support.api;

import java.io.IOException;

/**
 * Bucket variant that can be turned into a random‑access buffer efficiently.
 *
 * <p>Use this type when callers initially need a streaming {@link Bucket} but will later require
 * random access via {@link LockableRandomAccessBuffer}. A separate interface exists because the
 * APIs differ in important ways: notably, a {@link RandomAccessBuffer} has a fixed length, whereas
 * a {@link Bucket} may be grown while writing. Converting to a random‑access buffer typically seals
 * the size at the moment of conversion.
 *
 * <p>Implementations should avoid copying the underlying data where feasible when converting to a
 * random‑access form; some implementations may still copy for small in‑memory data. Unless a
 * specific implementation documents otherwise, callers should treat both the source bucket and the
 * resulting buffer as read‑only after conversion to prevent divergence between the two views.
 *
 * <p><strong>Finalization.</strong> Persistent {@code RandomAccessBucket} implementations must not
 * rely on finalizers to release durable resources. Transient implementations may free resources
 * during finalization only if neither the bucket nor any derived {@link RandomAccessBuffer} remains
 * reachable.
 */
public interface RandomAccessBucket extends Bucket {

  /**
   * Converts this bucket to a {@link LockableRandomAccessBuffer} without unnecessary copying.
   *
   * <p>The returned buffer provides fixed‑size, random‑access I/O over the current content. Many
   * implementations mark the bucket and/or the returned buffer read‑only to preserve consistency;
   * callers should not rely on mutability of either after conversion. Freeing the returned buffer
   * is sufficient to release any shared resources; freeing the bucket separately is not required in
   * typical implementations.
   *
   * @return a random‑access view of this bucket's content
   * @throws IOException if the conversion fails or the content cannot be exposed as a random‑access
   *     buffer
   */
  LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException;

  /**
   * Creates a shallow, read‑only view of this bucket with a covariant return type.
   *
   * <p>Semantics match {@link Bucket#createShadow()} but the return type is narrowed to {@code
   * RandomAccessBucket} when a shadow is available. The shadow may become invalid if the original
   * bucket is freed or deleted; readers should handle I/O failures accordingly.
   *
   * @return a read‑only shadow bucket sharing the same underlying storage, or {@code null} if
   *     shadowing is unsupported for this implementation
   */
  @Override
  RandomAccessBucket createShadow();
}
