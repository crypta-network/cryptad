package network.crypta.runtime.persistence;

import network.crypta.support.SimpleFieldSet;

/**
 * Contract for objects that export a persistable snapshot as a {@link SimpleFieldSet}.
 *
 * <p>The interface models components whose state is written to durable storage using the {@link
 * SimpleFieldSet} textual format. Implementations commonly use it to expose throttling or
 * rate‑limiting configuration. This type performs no I/O itself; callers get a snapshot and persist
 * it via {@link SimpleFieldSet#writeTo(java.io.Writer)} or {@link SimpleFieldSet#toString()}.
 *
 * <p>Threading: the consistency of the snapshot with respect to concurrent updates is
 * implementation‑specific.
 */
public interface Persistable {

  /**
   * Build a snapshot of throttling‑related settings for persistence.
   *
   * <p>The returned structure is a self‑contained, hierarchical representation suitable for writing
   * to disk using {@link SimpleFieldSet#writeTo(java.io.OutputStream)} or converting to text. No
   * I/O occurs in this method.
   *
   * @return a {@link SimpleFieldSet} describing the state to persist; may be empty when there is
   *     nothing to persist.
   */
  SimpleFieldSet persistThrottlesToFieldSet();
}
