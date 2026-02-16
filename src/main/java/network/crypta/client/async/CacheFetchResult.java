package network.crypta.client.async;

import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchResult;
import network.crypta.support.api.Bucket;

/**
 * Result object for fetches that originate from a local cache or otherwise short‑circuited path.
 *
 * <p>This type is a thin, immutable extension of {@code FetchResult} that adds a single boolean
 * flag indicating whether the binary payload has already been passed through any applicable
 * filtering or post-processing steps earlier in the pipeline. Callers can use this information to
 * avoid reapplying potentially expensive or lossy filters when they know a cache hit already
 * produced data in the final, consumer-ready form.
 *
 * <p>Aside from that marker, the instance behaves exactly like a regular {@code FetchResult}: it
 * exposes the client metadata (for example, the MIME type), provides access to the payload via a
 * {@code Bucket}, and offers convenience methods to inspect the content and size. The class holds
 * only final references and performs no mutation after construction; thread‑safety therefore
 * depends entirely on the provided bucket implementation and how it is used by the caller.
 *
 * <ul>
 *   <li>Immutability: all fields are final; no setters are provided.
 *   <li>Scope: conveys the presence of prior filtering without enforcing any particular policy.
 *   <li>Lifecycle: callers are responsible for closing/freeing the underlying bucket when done.
 * </ul>
 */
public class CacheFetchResult extends FetchResult {
  private static final String NULL_METADATA_MESSAGE = "ClientMetadata must not be null";
  private static final String NULL_BUCKET_MESSAGE = "Bucket must not be null";

  private static ClientMetadata requireMetadata(ClientMetadata dm) {
    if (dm == null) throw new IllegalArgumentException(NULL_METADATA_MESSAGE);
    return dm;
  }

  private static Bucket requireBucket(Bucket fetched) {
    if (fetched == null) throw new IllegalArgumentException(NULL_BUCKET_MESSAGE);
    return fetched;
  }

  /**
   * Marker that the payload was filtered earlier in the pipeline.
   *
   * <p>When {@code true}, the data contained in {@code asBucket()} (and consequently returned by
   * {@code asByteArray()}) is expected to have already undergone the standard content filtering or
   * normalization that would otherwise be performed after a network fetch. The exact filtering
   * semantics are defined by higher‑level components; this flag merely communicates that such work
   * has already been applied to the current payload. The value is fixed at construction time and
   * never changes for the lifetime of the instance.
   */
  public final boolean alreadyFiltered;

  /**
   * Construct a cache‑aware fetch result.
   *
   * <p>Creates an instance that wraps the supplied client metadata and data bucket and records
   * whether the payload was filtered before being placed into the cache or otherwise returned.
   * Neither argument is copied; references are stored as‑is. The constructor performs the same
   * validations as {@code FetchResult}: both {@code dm} and {@code fetched} must be non‑null.
   *
   * <pre>{@code
   * // Example: creating a result from a cache hit
   * CacheFetchResult r = new CacheFetchResult(meta, bucket, true);
   * }</pre>
   *
   * @param dm client metadata describing the payload (for example, MIME type); must not be {@code
   *     null}; the reference is retained for later access via {@code getMetadata()}.
   * @param fetched bucket providing the binary data; must not be {@code null}; callers manage its
   *     lifecycle (close/free) according to the bucket’s contract.
   * @param alreadyFiltered {@code true} when the content has already undergone filtering or
   *     normalization earlier in the pipeline; callers may use this to skip redundant work.
   */
  public CacheFetchResult(ClientMetadata dm, Bucket fetched, boolean alreadyFiltered) {
    super(requireMetadata(dm), requireBucket(fetched));
    this.alreadyFiltered = alreadyFiltered;
  }
}
