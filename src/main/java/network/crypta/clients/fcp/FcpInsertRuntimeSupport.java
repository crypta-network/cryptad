package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.USKManager;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Narrow runtime support seam for the FCP insert and USK subscription path.
 *
 * <p>This package-local adapter keeps insert request creation, upload bucket allocation, and USK
 * subscription wiring independent of direct {@code NodeClientCore} access while preserving the
 * current runtime behavior. It exposes only the insert-specific services needed by {@link
 * ClientPutBase}, {@link ClientPut}, {@link ClientPutDir}, {@link ClientPutPreparedDataFactory},
 * {@link ClientPutMessage}, and {@link SubscribeUSK}: the live {@link ClientContext}, the default
 * persistent {@link InsertContext}, transfer-policy checks, bucket factories, forever-persistent
 * upload allocation, and the {@link USKManager}.
 *
 * <p>Typical call paths get one instance from {@link FCPServer} and thread it through request
 * constructors while they normalize URIs, validate disk access, allocate temporary buckets, and
 * register USK listeners. The seam is intentionally small and local to {@code clients.fcp}. It is
 * not a general FCP runtime facade and does not widen {@code runtime-spi}; callers should add new
 * methods only when a later refactoring needs a demonstrably insert- or USK-specific seam.
 *
 * <p>Implementations are expected to be lightweight adapters over live daemon services rather than
 * detached snapshots. Callers therefore treat returned collaborators as the current runtime state
 * and should not assume ownership of shared resources beyond the normal contracts of the underlying
 * types.
 */
interface FcpInsertRuntimeSupport {

  /**
   * Returns the live client context used to start, resume, or validate insert requests.
   *
   * <p>Insert assembly uses this context when it needs request-level defaults that still depend on
   * the live daemon, for example, generating placeholder SSKs or starting the resulting putter from
   * {@link FCPConnectionHandler}. Implementations should return the current context in effect for
   * the owning node rather than a cached copy.
   *
   * @return current client context backing FCP insert operations
   */
  ClientContext clientContext();

  /**
   * Returns the default persistent insert context template for new put requests.
   *
   * <p>Callers typically get this baseline once during request construction and immediately tune
   * retries, compression, caching, and compatibility flags for the specific insert being assembled.
   * The returned context should therefore match the daemon's current persistent insert defaults.
   *
   * @return persistent insert context defaults supplied by the daemon runtime
   */
  InsertContext defaultPersistentInsertContext();

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
   * Returns the live USK manager used by subscription flows.
   *
   * <p>{@link SubscribeUSK} uses the returned manager to register, poll, and later remove USK
   * subscriptions. The seam does not abstract USK behavior further; it only provides the concrete
   * manager instance needed by the existing FCP subscription workflow.
   *
   * @return current USK manager backing FCP subscriptions
   */
  USKManager uskManager();
}
