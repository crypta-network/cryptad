package network.crypta.client;

import java.io.IOException;
import java.io.Serializable;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Minimal contract for runtime metadata fragments that still require deferred resolution.
 *
 * <p>This interface lets {@link MetadataUnresolvedException} live in {@code :kernel-content}
 * without depending on the runtime-owned {@code Metadata} implementation. Runtime code still
 * supplies concrete metadata objects, but leaf-safe callers only need the ability to serialize a
 * fragment, mark it resolved under an archive entry name, and check whether that resolution has
 * already happened.
 *
 * <p>The contract is intentionally narrow. It covers only the operations needed by insert and
 * archive-building flows that may discover unresolved nested metadata, defer that work, and then
 * resume once a stable archive-local name exists. Implementations are expected to be mutable in a
 * limited, request-scoped way: unresolved instances usually start without a name, become resolved
 * exactly once during archive assembly, and can then be serialized again with references rewritten
 * to the new location.
 *
 * <p>Implementations must remain {@link Serializable} because {@link MetadataUnresolvedException}
 * is serializable and exposes unresolved targets through its public {@code mustResolve} field. That
 * keeps the persisted failure state compatible with higher layers that only know this leaf-safe
 * interface rather than the runtime-owned metadata class.
 */
public interface MetadataResolutionTarget extends Serializable {

  /**
   * Serializes this unresolved metadata fragment into a new random-access bucket.
   *
   * <p>Callers use this method when they need a stable byte representation for a deferred metadata
   * fragment, typically before inserting it or storing it alongside a parent archive manifest. The
   * returned bucket should be ready for downstream consumers to read without further mutation. If
   * serialization discovers additional unresolved child metadata, implementations should fail fast
   * with {@link MetadataUnresolvedException} rather than emitting a partial or misleading payload.
   *
   * @param bucketFactory factory used to allocate the destination bucket; implementations may use
   *     it to choose an appropriate temporary or persistent backing store for the serialized bytes
   * @return a read-only bucket containing the serialized metadata bytes, suitable for immediate
   *     handoff to insert or archive assembly code
   * @throws MetadataUnresolvedException if nested metadata must be resolved before a stable byte
   *     representation can be produced
   * @throws IOException if allocating the bucket or writing the serialized bytes fails
   */
  RandomAccessBucket toBucket(BucketFactory bucketFactory)
      throws MetadataUnresolvedException, IOException;

  /**
   * Marks this metadata fragment as resolved under an archive-local name.
   *
   * <p>This method records the archive entry name that should be used for later references to the
   * serialized fragment. Callers typically invoke it after a child metadata object has been stored
   * as a separate archive member and before re-serializing the parent structure. Implementations
   * should treat the provided name as the authoritative archive-local identifier for subsequent
   * serialization work.
   *
   * @param name archive entry name that now identifies the serialized metadata fragment; callers
   *     should pass the final stored name rather than a provisional placeholder
   */
  void resolve(String name);

  /**
   * Indicates whether this metadata fragment already has a resolved identifier.
   *
   * <p>This check lets higher layers avoid re-serializing or re-inserting metadata fragments that
   * already point at a stable archive-local or URI-based target. The method reports resolution
   * state only; it does not guarantee that the referenced data is still present in a cache or has
   * been persisted successfully elsewhere.
   *
   * @return {@code true} when a resolved name or URI is already present and future serialization
   *     can use that identifier; otherwise {@code false}
   */
  boolean isResolved();
}
