package network.crypta.client.async;

import network.crypta.client.InsertException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Callback contract for client put operations, including site inserts.
 *
 * <p>Implementations receive progress and completion notifications for ongoing insert operations.
 * Calls occur on the database thread when the request is persistent; transient requests invoke the
 * callbacks on the thread that completes the work (in that case the container may be {@code null}).
 * Typical usage is for a higher‑level client component to implement this interface alongside {@link
 * ClientBaseCallback} so it can resume state after restarts and report insert progress back to the
 * application boundary.
 *
 * <p>Events are advisory unless otherwise stated. For example, {@link
 * #onFetchable(BaseClientPutter)} is a hint that the data is likely retrievable, but callers must
 * still handle races and visibility delays. Implementations should be quick and avoid blocking
 * scheduler threads for extended periods. Where applicable, callers are responsible for freeing any
 * {@link Bucket} instances as documented below to avoid resource leaks.
 *
 * <ul>
 *   <li>Emits a final success or failure signal with associated cleanup responsibilities.
 *   <li>Optionally reports a generated {@link FreenetURI} or early metadata in lieu of a URI.
 *   <li>May indicate that content has become fetchable before overall completion.
 * </ul>
 *
 * @see BaseClientPutter
 * @see ClientBaseCallback
 * @see ClientContext
 */
public interface ClientPutCallback extends ClientBaseCallback {
  /**
   * Notifies that the final insert {@link FreenetURI} is known.
   *
   * <p>This callback is typically invoked once the encoder has produced the required top‑level
   * blocks (for example, after encoding all CHK blocks) and a stable URI can be determined. It is
   * not invoked if the operation is configured to return metadata instead of a URI. Implementations
   * may use the URI for user display, caching, or to enqueue dependent tasks. The method is not
   * guaranteed to be the final notification; success or failure is delivered separately.
   *
   * @param uri Non-null {@link FreenetURI} representing the content address produced by the insert;
   *     callers should treat it as immutable and suitable for later retrieval.
   * @param state The original {@link BaseClientPutter} returned by the {@code insert()} that
   *     started this operation; can be downcast to the concrete putter type used by the caller.
   */
  void onGeneratedURI(FreenetURI uri, BaseClientPutter state);

  /**
   * Notifies that metadata is returned instead of a URI.
   *
   * <p>This path is used when the originator supplied a metadata threshold and the metadata became
   * available below that threshold, avoiding the need to insert a top block. The provided {@link
   * Bucket} contains the metadata payload. Ownership is transferred to the recipient, who may
   * retain it temporarily but must eventually free it to release resources. The caller of this
   * method does not free the bucket.
   *
   * @param metadata A {@link Bucket} holding the returned metadata; persistent if the insert is
   *     persistent; the recipient assumes responsibility for freeing it when no longer needed.
   * @param state The original {@link BaseClientPutter} returned by the {@code insert()} that
   *     started this operation; can be downcast to the concrete putter type used by the caller.
   */
  void onGeneratedMetadata(Bucket metadata, BaseClientPutter state);

  /**
   * Hints that the inserted data has become fetchable.
   *
   * <p>This is an advisory signal and may arrive before overall completion. Clients should treat it
   * as a best‑effort indication and still handle races, eventual consistency, or caching delays
   * when attempting to fetch. Ordering relative to other callbacks is not strictly guaranteed.
   *
   * @param state The original {@link BaseClientPutter} returned by the {@code insert()} that
   *     started this operation; can be downcast to the concrete putter type used by the caller.
   */
  void onFetchable(BaseClientPutter state);

  /**
   * Signals that the insert completed successfully.
   *
   * <p>Implementations should perform any final bookkeeping and resource cleanup. In particular, if
   * the caller provided an input {@link Bucket} for the insert, it must be freed here to prevent
   * leaks. This method represents terminal success for the operation; no further callbacks for this
   * putter are expected after invocation.
   *
   * @param state The original {@link BaseClientPutter} returned by the {@code insert()} that
   *     started this operation; may be cast to the concrete type to access the input {@link
   *     Bucket}.
   */
  void onSuccess(BaseClientPutter state);

  /**
   * Signals that the insert failed or was canceled.
   *
   * <p>Implementations should perform final cleanup, including freeing any input {@link Bucket}
   * associated with the request. The provided {@link InsertException} describes the failure reason
   * and may be surfaced to a user or logged for diagnostics. This method represents terminal
   * completion for the operation; no further callbacks for this putter are expected after
   * invocation.
   *
   * @param e The {@link InsertException} detailing why the insert failed or was canceled; may
   *     include nested causes and error codes for higher-level handling.
   * @param state The original {@link BaseClientPutter} returned by the {@code insert()} that
   *     started this operation; may be cast to the concrete type to access the input {@link
   *     Bucket}.
   */
  void onFailure(InsertException e, BaseClientPutter state);
}
