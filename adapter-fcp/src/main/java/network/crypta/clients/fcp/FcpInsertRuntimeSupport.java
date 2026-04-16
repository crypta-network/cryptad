package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Narrow runtime support seam for the FCP insert and USK subscription path.
 *
 * <p>This adapter keeps insert request creation, upload bucket allocation, and USK subscription
 * wiring independent of direct {@code NodeClientCore} access while preserving the current runtime
 * behavior. It exposes only the insert-specific services needed by {@link ClientPutBase}, {@link
 * ClientPut}, {@link ClientPutDir}, {@link ClientPutPreparedDataFactory}, {@link ClientPutMessage},
 * and {@link SubscribeUSK}: the default persistent detached insert-context handle, transfer-policy
 * checks, bucket factories, forever-persistent upload allocation, URI normalization, and opaque
 * execution handle creation.
 *
 * <p>Typical call paths get one instance from {@link FCPServer} and thread it through request
 * constructors while they normalize URIs, validate disk access, allocate temporary buckets, and
 * register USK listeners. The seam remains owned by {@code clients.fcp} even though core-backed
 * implementations now live under runtime bootstrap wiring. It is public only so those runtime-owned
 * adapters can implement it from outside the package. It is not a general FCP runtime facade and
 * does not widen {@code runtime-spi}; callers should add new methods only when a later refactoring
 * needs a demonstrably insert- or USK-specific seam.
 *
 * <p>Implementations are expected to be lightweight adapters over live daemon services rather than
 * detached snapshots. Callers therefore treat returned collaborators as the current runtime state
 * and should not assume ownership of shared resources beyond the normal contracts of the underlying
 * types.
 */
public interface FcpInsertRuntimeSupport {

  /**
   * Returns the default persistent detached insert-context template for new put requests.
   *
   * <p>Callers typically get this baseline once during request construction and immediately tune
   * retries, compression, caching, and compatibility flags for the specific insert being assembled.
   * The returned handle should therefore match the daemon's current persistent insert defaults
   * while remaining adapter-owned and serializable.
   *
   * @return persistent detached insert-context defaults supplied by the daemon runtime
   */
  FcpInsertContextHandle defaultPersistentInsertContextHandle();

  /**
   * Returns the transfer-access policy used for upload validation and DDA checks.
   *
   * <p>Disk-backed inserts consult this policy before accepting local files or directories. Keeping
   * the lookup behind the seam preserves the legacy allow/deny behavior while removing direct core
   * access from the insert request classes.
   *
   * @return transfer policy for disk-upload validation
   */
  TransferAccessPort transferAccess();

  /**
   * Returns the bucket factory appropriate for the requested persistence class.
   *
   * <p>Insert helpers use this when they need to synthesize metadata buckets, especially for
   * redirect uploads that must follow the same persistence rules as the surrounding request.
   *
   * @param persistentForever whether the request persists forever
   * @return bucket factory aligned with the insert persistence mode
   */
  BucketFactory bucketFactory(boolean persistentForever);

  /**
   * Builds a redirect metadata bucket aligned with the insert persistence mode.
   *
   * <p>Single-file put requests use this when {@code UploadFrom=redirect} is selected. Keeping the
   * metadata construction behind the runtime seam lets the adapter prepare redirect inserts without
   * importing the runtime-owned metadata implementation.
   *
   * @param metadata client metadata to embed in the redirect document
   * @param redirectTarget redirect target URI
   * @param persistentForever whether the surrounding request persists forever
   * @return bucket containing serialized redirect metadata
   * @throws MetadataUnresolvedException if the redirect metadata cannot be serialized
   * @throws IOException if bucket allocation or serialization fails
   */
  RandomAccessBucket createRedirectMetadataBucket(
      ClientMetadata metadata, FreenetURI redirectTarget, boolean persistentForever)
      throws MetadataUnresolvedException, IOException;

  /**
   * Allocates a forever-persistent upload bucket for inbound FCP payloads.
   *
   * <p>This is used by the live message path when the client requests {@code FOREVER} persistence
   * and the server must stage upload bytes in the persistent temporary bucket store.
   * Implementations should throw rather than silently downgrade when the persistent store is
   * unavailable.
   *
   * @param length expected payload length
   * @return newly allocated persistent upload bucket
   * @throws IOException if the underlying bucket factory cannot allocate the bucket
   * @throws PersistenceDisabledException if forever-persistent uploads are unavailable
   */
  RandomAccessBucket allocatePersistentUploadBucket(long length)
      throws IOException, PersistenceDisabledException;

  /**
   * Normalizes insert URIs that omit routing or document names.
   *
   * <p>This preserves the legacy {@code SSK@} handling used by FCP insert requests while keeping
   * the randomness source hidden behind the runtime bridge.
   *
   * @param uri candidate insert URI
   * @param filename filename to apply when the URI lacks a document name
   * @return original or normalized insert URI
   */
  FreenetURI normalizeInsertUri(FreenetURI uri, String filename);

  /**
   * Creates a single-file insert execution handle.
   *
   * @param executionSpec detached execution inputs for the request attempt
   * @return opaque live execution handle
   * @throws IOException if the runtime cannot construct the execution
   */
  ClientPutExecution createSingleFileExecution(ClientPutExecutionSpec executionSpec)
      throws IOException;

  /**
   * Creates a directory/manifest insert execution handle.
   *
   * @param executionSpec detached execution inputs for the request attempt
   * @return opaque live execution handle
   */
  ClientPutDirExecution createDirectoryExecution(ClientPutDirExecutionSpec executionSpec)
      throws network.crypta.client.async.TooManyFilesInsertException;

  /**
   * Creates and registers a USK subscription handle.
   *
   * @param message parsed subscription request
   * @param callbacks adapter-owned callback surface receiving runtime events
   * @param handler owning FCP connection handler
   * @return opaque live subscription handle
   */
  UskSubscriptionHandle subscribeUSK(
      SubscribeUSKMessage message, SubscribeUSKCallbacks callbacks, FCPConnectionHandler handler);
}
