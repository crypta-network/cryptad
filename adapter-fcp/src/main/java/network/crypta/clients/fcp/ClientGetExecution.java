package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.FetchException;
import network.crypta.client.async.ClientRequester;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Opaque adapter-owned handle for one live FCP GET execution.
 *
 * <p>This interface is the adapter-side control surface for a fetch that is actually implemented by
 * the runtime bridge. {@link ClientGet} and its helper classes use it to start work, inspect the
 * best-known result metadata, and persist just enough transient state to support the existing
 * restart and replay flows. The concrete runtime fetcher remains hidden behind this boundary, which
 * keeps {@code :adapter-fcp} independent of daemon-owned execution classes while preserving the
 * long-lived request behavior expected by the FCP protocol.
 *
 * <p>Implementations are expected to represent a single execution attempt for a single request.
 * They may observe mutable runtime state, but callers treat them as request-scoped handles rather
 * than reusable services. Methods that expose expected MIME type, size, or Binary Blob state return
 * the current best-known view from the underlying fetcher and may therefore change as the fetch
 * progresses.
 *
 * <ul>
 *   <li>Lifecycle control: {@link #start()}, {@link #canRestart()}, and {@link #restart(FreenetURI,
 *       boolean)}.
 *   <li>Observation: {@link #requester()}, {@link #expectedMime()}, {@link #expectedSize()}, and
 *       {@link #blobBucket()}.
 *   <li>Minimal resume support: {@link #writeTrivialProgress(DataOutputStream)} and {@link
 *       #resumeFromTrivialProgress(DataInputStream)}.
 * </ul>
 */
public interface ClientGetExecution {

  /**
   * Returns the low-level requester currently backing this execution.
   *
   * <p>The request lifecycle uses this value for diagnostics, persistent tagging, and other legacy
   * integration points that still operate on the common requester abstraction. The returned object
   * belongs to the live runtime execution and should be treated as an observational handle rather
   * than as an ownership transfer.
   *
   * @return runtime-backed requester associated with this fetch attempt.
   */
  ClientRequester requester();

  /**
   * Starts the live fetch using the runtime-bound execution context.
   *
   * <p>Callers use this exactly when a configured request moves from setup into active execution.
   * The method is expected to delegate to the runtime fetch engine that owns scheduling, network
   * I/O, and callback delivery. It does not describe completion; success and failure are still
   * reported asynchronously through the owning {@link ClientGet}.
   *
   * @throws FetchException if the runtime rejects the start request before asynchronous execution
   *     begins.
   */
  void start() throws FetchException;

  /**
   * Returns whether the current live execution can be restarted.
   *
   * <p>This is primarily used by redirect and retry logic to decide whether the existing runtime
   * fetcher can be reused. A return value of {@code false} means the caller must treat the current
   * attempt as non-restartable and rely on the existing failure handling path instead of issuing a
   * restart.
   *
   * @return {@code true} when the underlying runtime fetcher supports restart for the current
   *     state.
   */
  boolean canRestart();

  /**
   * Restarts the live execution with a new redirect target and filtering choice.
   *
   * <p>The redirect URI is normally supplied by fetch failure handling after the runtime reports a
   * restartable redirect. The {@code filterData} flag preserves the FCP-visible decision about
   * whether the restarted attempt should run the content filter. Implementations may reject the
   * restart when the runtime fetcher is no longer in a restartable state.
   *
   * @param redirect redirect target that should replace the previous fetch URI.
   * @param filterData whether the restarted fetch should apply content filtering.
   * @return {@code true} when the runtime accepted the restart request.
   * @throws FetchException if restart setup fails before the restarted attempt is handed back to
   *     the runtime engine.
   */
  boolean restart(FreenetURI redirect, boolean filterData) throws FetchException;

  /**
   * Returns the best-known expected MIME type, if any.
   *
   * <p>This value is advisory status information from the underlying fetcher. It may be unavailable
   * early in the request lifecycle and may become more specific as metadata is discovered.
   *
   * @return expected MIME type, or {@code null} when the runtime has not determined one.
   */
  String expectedMime();

  /**
   * Returns the best-known expected payload size.
   *
   * <p>The size is a best-effort estimate reported by the live fetcher. Callers use it for status
   * reporting and planning decisions only; it is not a guarantee that the final payload will match
   * exactly.
   *
   * @return expected payload size in bytes, or {@code 0} when the runtime cannot currently predict
   *     one.
   */
  long expectedSize();

  /**
   * Returns the Binary Blob bucket associated with this execution.
   *
   * <p>This is only meaningful when the request was configured for Binary Blob recording. For
   * ordinary GET requests, implementations may return {@code null}. Callers should treat the
   * returned bucket as runtime-owned storage that exists to preserve current FCP Binary Blob
   * behavior rather than as a general output channel.
   *
   * @return Binary Blob bucket for this execution, or {@code null} when Binary Blob recording is
   *     not active.
   */
  Bucket blobBucket();

  /**
   * Writes the minimal transient state needed for trivial resume.
   *
   * <p>This is the lightest-weight persistence hook used by the existing GET replay path. It is
   * intentionally narrower than full request serialization and should only emit the extra runtime
   * state that cannot be reconstructed from the persisted adapter-owned request fields alone.
   *
   * @param dos stream that receives the compact transient progress payload.
   * @return {@code true} when trivial progress data was written for the current execution state.
   * @throws IOException if the progress payload cannot be serialized to {@code dos}.
   */
  boolean writeTrivialProgress(DataOutputStream dos) throws IOException;

  /**
   * Attempts to restore the minimal transient state previously written by {@link
   * #writeTrivialProgress(DataOutputStream)}.
   *
   * <p>Implementations use this during request replay to rebuild the live fetcher as cheaply as
   * possible. A return value of {@code false} indicates that the trivial resume payload was not
   * enough and the caller should continue with the heavier recovery path already defined by the
   * request lifecycle.
   *
   * @param dis stream positioned at a previously written trivial-progress payload.
   * @return {@code true} when the runtime fetcher was rebuilt from the trivial payload.
   * @throws IOException if the payload cannot be read or is structurally invalid for trivial
   *     resume.
   */
  boolean resumeFromTrivialProgress(DataInputStream dis) throws IOException;

  /**
   * Returns whether trivial resume rebuilt the underlying fetcher successfully.
   *
   * <p>This is a post-resume status check used by the legacy replay flow. It allows the request to
   * distinguish between merely reading the trivial payload and actually ending up with a live
   * runtime fetcher that can continue execution.
   *
   * @return {@code true} when the runtime fetcher is available after trivial resume handling.
   */
  boolean resumedFetcher();
}
