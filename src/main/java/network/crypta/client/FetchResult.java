package network.crypta.client;

import java.io.IOException;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;

/**
 * Immutable holder for the outcome of a client fetch operation.
 *
 * <p>This type bundles the {@link ClientMetadata} that describes the fetched object (for example,
 * its MIME type) together with the binary payload stored in a {@link Bucket}. It is returned by
 * higher-level client APIs after a successful retrieval and acts as a simple transfer object
 * between layers. The instance does not copy the underlying data; it merely references the provided
 * {@code Bucket} as-is.
 *
 * <p>Typical usage patterns include inspecting the MIME type to decide on downstream handling,
 * reading the size via {@link #size()}, and then either streaming bytes from the bucket or
 * materializing the content into a byte array through {@link #asByteArray()}. Large payloads should
 * preferably be consumed via the bucket streaming interfaces to avoid unnecessary memory pressure.
 *
 * <p>Thread-safety: this class only stores final references and performs no mutation or
 * synchronization. Concurrency characteristics therefore depend on the provided {@code Bucket}
 * implementation. Callers must coordinate access to the bucket if it is not inherently thread-safe.
 */
public final class FetchResult {

  /** The ClientMetadata, i.e. MIME type. Must not be null. */
  final ClientMetadata metadata;

  /** The data. */
  final Bucket data;

  /**
   * Create a new fetch result.
   *
   * <p>Constructs a result from the provided {@link ClientMetadata} and data {@link Bucket}. Both
   * arguments must be non-{@code null}. The references are stored directly; the constructor does
   * not copy the payload and performs no I/O.
   *
   * @param dm non-null client metadata describing the fetched object, including MIME type and
   *     related attributes; must not be {@code null}.
   * @param fetched non-null data bucket containing the retrieved payload; ownership remains with
   *     the caller; must not be {@code null}.
   * @throws IllegalArgumentException if {@code dm} or {@code fetched} is {@code null}.
   */
  public FetchResult(ClientMetadata dm, Bucket fetched) {
    if (dm == null) throw new IllegalArgumentException("ClientMetadata must not be null");
    if (fetched == null) throw new IllegalArgumentException("Bucket must not be null");
    metadata = dm;
    data = fetched;
  }

  /**
   * Create a fetch result that reuses metadata but replaces the data bucket.
   *
   * <p>This convenience constructor forms a new instance that carries over the metadata from an
   * existing result and associates it with a different {@link Bucket}. It is useful when data has
   * been transformed or re-encoded while the descriptive metadata remains valid.
   *
   * @param fr source result whose {@link #getMetadata()} is reused; must not be {@code null}.
   * @param output replacement bucket that provides the new payload; must not be {@code null} and is
   *     not copied.
   */
  public FetchResult(FetchResult fr, Bucket output) {
    this.data = output;
    this.metadata = fr.metadata;
  }

  /**
   * Return the MIME type of the fetched data.
   *
   * <p>The value is obtained from the associated {@link ClientMetadata}. When the type is unknown
   * or could not be inferred, implementations typically return {@code "application/octet-stream"}.
   *
   * @return a non-null MIME type string representing the content type of the payload; if unknown, a
   *     generic binary type is returned.
   */
  public String getMimeType() {
    return metadata.getMIMEType();
  }

  /**
   * Return the client-level metadata for this result.
   *
   * <p>The metadata describes the payload and may include the MIME type and other attributes that
   * help downstream consumers decide how to process the data.
   *
   * @return the non-null {@link ClientMetadata} associated with the fetched payload; the object is
   *     the same reference supplied at construction time.
   */
  public ClientMetadata getMetadata() {
    return metadata;
  }

  /**
   * Return the size of the fetched data in bytes.
   *
   * <p>This method delegates to the underlying {@link Bucket}. The value reflects the current
   * number of readable bytes available from the bucket and may incur a small constant-time query on
   * some implementations.
   *
   * @return the exact payload size in bytes as reported by the underlying bucket implementation.
   */
  public long size() {
    return data.size();
  }

  /**
   * Return the payload as a materialized byte array.
   *
   * <p>This method fully reads the underlying {@link Bucket} into memory and returns a new byte
   * array containing the content. For large payloads this may require substantial heap space;
   * prefer streaming from the bucket when possible to limit memory usage.
   *
   * @return a newly allocated byte array containing the entire payload; the caller owns and may
   *     modify the returned array without affecting the source bucket.
   * @throws IOException if an I/O error occurs while reading from the underlying bucket.
   */
  public byte[] asByteArray() throws IOException {
    return BucketTools.toByteArray(data);
  }

  /**
   * Return the underlying {@link Bucket}.
   *
   * <p>The returned instance is the same reference supplied at construction time. Callers are
   * responsible for closing or otherwise releasing any resources held by the bucket according to
   * its contract to avoid leaks.
   *
   * @return the non-null bucket that provides access to the fetched payload; no copy is performed.
   */
  public Bucket asBucket() {
    return data;
  }
}
