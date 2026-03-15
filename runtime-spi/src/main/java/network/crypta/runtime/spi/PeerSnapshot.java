package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Represents an immutable point-in-time export of one peer tree.
 *
 * <p>This snapshot is the management-facing value produced by {@link PeerPort} for the current FCP
 * peer-management family. It intentionally carries only the root tree node and does not encode
 * request identifiers or other protocol-specific metadata, leaving those concerns to the caller's
 * wire format.
 *
 * <p>The record is immutable and safe to retain after the originating daemon operation completes.
 * It should be treated as a detached export value that captures one point in time, not as a handle
 * for later peer mutation or lazy field access.
 *
 * @param root root field-set tree for the exported peer
 * @see PeerFieldSet
 * @see PeerPort
 */
public record PeerSnapshot(PeerFieldSet root) {
  /**
   * Creates an immutable peer snapshot.
   *
   * @param root root field-set tree for the export; must not be {@code null}
   * @throws NullPointerException if {@code root} is {@code null}
   */
  public PeerSnapshot {
    Objects.requireNonNull(root, "root");
  }

  /**
   * Returns an empty peer snapshot.
   *
   * <p>This is primarily useful for tests or for call paths that need a canonical "no exported peer
   * data" value before any subsets are attached.
   *
   * @return snapshot whose root tree has no direct values or subsets
   */
  public static PeerSnapshot empty() {
    return new PeerSnapshot(PeerFieldSet.empty());
  }

  /**
   * Returns whether the exported root tree contains no data.
   *
   * <p>This delegates to {@link PeerFieldSet#isEmpty()} on the root node and does not inspect any
   * state outside the stored snapshot.
   *
   * @return {@code true} when the root field-set tree is empty
   */
  public boolean isEmpty() {
    return root.isEmpty();
  }
}
