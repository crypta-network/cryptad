package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.async.ClientContext;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;

/**
 * Narrow runtime support seam for the FCP GET/fetch path.
 *
 * <p>This package-local adapter keeps the GET request creation and getter wiring independent of
 * direct {@code NodeClientCore} access while preserving the current runtime behavior. It exposes
 * only the fetch-specific services needed by {@link ClientGet}, {@link ClientGetFactory}, and
 * {@link ClientGetGetterFactory}: the live {@link ClientContext}, the default persistent {@link
 * FetchContext}, transfer-policy checks, and binary-blob bucket allocation.
 *
 * <p>The interface is intentionally small and local to {@code clients.fcp}. It is not a general FCP
 * runtime facade and does not widen {@code runtime-spi}; callers should add new methods only when a
 * later refactoring needs a demonstrably GET-specific seam. Typical call flow starts with {@link
 * ClientGetFactory} reading the default context and transfer policy during request construction,
 * then {@link ClientGet} and {@link ClientGetGetterFactory} using the same support object again
 * when the request starts or allocates Binary Blob output.
 */
interface FcpFetchRuntimeSupport {

  /**
   * Returns the live client context used to start or resume fetch requests.
   *
   * <p>The returned context is the same runtime object that request code should pass into start or
   * resume operations. Callers should treat it as a live daemon state rather than a detached
   * snapshot.
   *
   * @return current client context backing FCP fetch operations
   */
  ClientContext clientContext();

  /**
   * Returns the default persistent fetch context template for new GET requests.
   *
   * <p>Factories typically clone or adjust the returned context immediately for one request. The
   * value acts as the persistent-fetch baseline from which request-specific flags and limits are
   * derived.
   *
   * @return persistent fetch context defaults supplied by the daemon runtime
   */
  FetchContext defaultPersistentFetchContext();

  /**
   * Returns the transfer-access policy used for disk-return planning.
   *
   * <p>This policy must stay aligned with the owning FCP server runtime, so default download
   * directories and DDA decisions match the rest of the server's request handling.
   *
   * @return transfer policy for download path validation and defaults
   */
  TransferAccessPort transferAccess();

  /**
   * Allocates a bucket for binary-blob output when a request has no caller-provided return bucket.
   *
   * <p>The request path uses this only for Binary Blob fetches that still need a storage target.
   * The caller handles ordinary return planning earlier.
   *
   * @param maxOutputLength maximum expected payload size for the fetch
   * @param persistentForever whether the request persists forever and therefore needs the forever
   *     bucket factory
   * @return newly allocated bucket for binary-blob output
   * @throws IOException if bucket allocation fails
   */
  Bucket allocateBinaryBlobBucket(long maxOutputLength, boolean persistentForever)
      throws IOException;
}
