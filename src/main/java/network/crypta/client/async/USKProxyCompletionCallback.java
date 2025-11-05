package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.support.compress.Compressor;

/**
 * Proxy {@link GetCompletionCallback} that keeps {@link USK} metadata in sync and transparently
 * forwards events to a downstream callback.
 *
 * <p>This lightweight adapter updates the {@link USKManager} with the latest known-good edition for
 * a USK whenever a request completes or when certain redirect conditions are observed. It also
 * normalizes error reporting for USK workflows: if a failure exposes a temporary SSK-based {@link
 * FreenetURI}, the proxy converts it back to the corresponding USK form so client code sees a
 * stable URI shape across retries and restarts. Apart from these side effects, all progress and
 * terminal events are delegated unchanged to the wrapped callback.
 *
 * <p>Persistence and lifecycle: instances of this class are serialized as part of persistent
 * requests. The downstream callback reference is therefore intentionally non-transient so resuming
 * a request after a restart preserves the delegation chain and avoids null-pointer failures. The
 * adapter itself is stateless and thread-confinement matches the invoker: callbacks may arrive at
 * worker threads provided by the client layer, and implementations should assume no special
 * synchronization beyond the usual callback contracts.
 *
 * <ul>
 *   <li>Updates the USK manager with a "known good" edition on success and certain failures.
 *   <li>Converts failure {@code newURI} values from SSK to USK when applicable.
 *   <li>Delegates all callbacks to the supplied downstream without altering payloads.
 * </ul>
 *
 * @see GetCompletionCallback
 * @see USK
 * @see USKManager
 * @see ClientGetState
 * @author toad
 */
public class USKProxyCompletionCallback implements GetCompletionCallback, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Target USK for which the proxy updates the manager's known-good edition.
   *
   * <p>The instance is retained for the lifetime of this proxy and is not modified. Its {@link
   * USK#suggestedEdition} value is used when recording progress in the {@link USKManager}.
   */
  final USK usk;

  /**
   * Downstream callback that receives all delegated events unchanged.
   *
   * <p>This field is deliberately non-transient: the proxy is serialized for persistent requests
   * and must retain its delegation target across restarts to avoid null-pointer failures when the
   * request resumes.
   */
  @SuppressWarnings("java:S1948")
  final GetCompletionCallback cb;

  /**
   * Indicates whether the owning request is persistent across restarts.
   *
   * <p>The flag is stored for bookkeeping and diagnostic purposes only; it does not change
   * delegation behavior. Callers typically propagate the same value used for the request itself.
   */
  final boolean persistent;

  /**
   * Create a proxy callback that maintains USK state and forwards all events to a downstream
   * callback.
   *
   * <p>The {@code persistent} flag records the intended lifecycle of the owning request. It does
   * not change delegation behavior, but callers commonly propagate this information alongside the
   * callback to aid diagnostics and consistent construction in surrounding code.
   *
   * @param usk the target {@link USK} whose suggested edition is used to update the manager; must
   *     not be {@code null}; the instance is retained for the life of this proxy
   * @param cb the downstream {@link GetCompletionCallback} that receives all delegated events; must
   *     be non-null and serializable when used in persistent requests; the proxy never wraps or
   *     buffers payloads before forwarding
   * @param persistent whether the owning request is long-lived and persisted across restarts;
   *     stored for bookkeeping and potential diagnostics; does not alter callback semantics
   */
  public USKProxyCompletionCallback(USK usk, GetCompletionCallback cb, boolean persistent) {
    this.usk = usk;
    this.cb = cb;
    this.persistent = persistent;
  }

  /**
   * Reports a successful completion, updates USK state, and forwards the event.
   *
   * <p>The proxy first records the USK's suggested edition as known-good via the {@link USKManager}
   * available from the supplied {@link ClientContext}. It then passes the provided stream,
   * metadata, and decompressor stack to the downstream callback unchanged.
   *
   * @param streamGenerator generator that yields the final decoded data stream for the request;
   *     consumers should read promptly to avoid holding internal resources longer than necessary
   * @param clientMetadata descriptive metadata such as MIME type and parameters determined during
   *     the fetch; treated as read-only by this proxy and forwarded as received
   * @param decompressors ordered list of decompressors that may apply to the stream; forwarded as
   *     provided without modification or inspection by this proxy
   * @param state final client state associated with the completion; useful for logging and tracing;
   *     not accessed or altered by this proxy
   * @param context client context providing access to managers and helpers; used here solely to
   *     update the USK manager with the latest known-good edition prior to delegation
   */
  @Override
  public void onSuccess(
      StreamGenerator streamGenerator,
      ClientMetadata clientMetadata,
      List<? extends Compressor> decompressors,
      ClientGetState state,
      ClientContext context) {
    context.uskManager.updateKnownGood(usk, usk.suggestedEdition, context);
    cb.onSuccess(streamGenerator, clientMetadata, decompressors, state, context);
  }

  /**
   * Reports a terminal failure, optionally updates USK state, and forwards the event.
   *
   * <p>When the failure mode is {@link
   * FetchException.FetchExceptionMode#NOT_ENOUGH_PATH_COMPONENTS} or {@link
   * FetchException.FetchExceptionMode#PERMANENT_REDIRECT}, the proxy records the USK's suggested
   * edition as known-good before delegation. If the exception carries a {@code newURI} referring to
   * an SSK constructed during resolution, it is converted to the corresponding USK form and a
   * cloned {@link FetchException} is forwarded. In all other cases the original exception instance
   * is forwarded unchanged.
   *
   * @param e the failure raised by the client layer; may be wrapped into a new instance when {@code
   *     newURI} is convertible from SSK to USK; otherwise forwarded as received
   * @param state the last known client state for the request; forwarded to the downstream callback
   *     without modification
   * @param context client context used to update the USK manager for select modes; never stored or
   *     retained beyond the scope of this call
   */
  @Override
  public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
    if (e.mode == FetchException.FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS
        || e.mode == FetchException.FetchExceptionMode.PERMANENT_REDIRECT) {
      context.uskManager.updateKnownGood(usk, usk.suggestedEdition, context);
    }
    FreenetURI uri = e.newURI;
    if (uri != null) {
      uri = usk.turnMySSKIntoUSK(uri);
      e = new FetchException(e, uri);
    }
    cb.onFailure(e, state, context);
  }

  /** {@inheritDoc} */
  @Override
  public void onBlockSetFinished(ClientGetState state, ClientContext context) {
    cb.onBlockSetFinished(state, context);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This proxy intentionally suppresses delegation for state transitions, as the downstream
   * callback is expected to receive only terminal and progress events relevant to content delivery.
   */
  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {
    // Ignore
  }

  /** {@inheritDoc} */
  @Override
  public void onExpectedMIME(ClientMetadata metadata, ClientContext context) throws FetchException {
    cb.onExpectedMIME(metadata, context);
  }

  /** {@inheritDoc} */
  @Override
  public void onExpectedSize(long size, ClientContext context) {
    cb.onExpectedSize(size, context);
  }

  /** {@inheritDoc} */
  @Override
  public void onFinalizedMetadata() {
    cb.onFinalizedMetadata();
  }

  /** {@inheritDoc} */
  @Override
  public void onExpectedTopSize(
      long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
    cb.onExpectedTopSize(size, compressed, blocksReq, blocksTotal, context);
  }

  /** {@inheritDoc} */
  @Override
  public void onSplitfileCompatibilityMode(
      CompatibilityMode min,
      CompatibilityMode max,
      byte[] splitfileKey,
      boolean dontCompress,
      boolean bottomLayer,
      boolean definitiveAnyway,
      ClientContext context) {
    cb.onSplitfileCompatibilityMode(
        min, max, splitfileKey, dontCompress, bottomLayer, definitiveAnyway, context);
  }

  /** {@inheritDoc} */
  @Override
  public void onHashes(HashResult[] hashes, ClientContext context) {
    cb.onHashes(hashes, context);
  }
}
