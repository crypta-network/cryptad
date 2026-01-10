package network.crypta.client.async;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.FoundURICallback;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.client.filter.TagReplacerCallback;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.MultiHashInputStream;
import network.crypta.keys.FreenetURI;
import network.crypta.support.compress.CompressionOutputSizeException;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Worker thread that post-processes fetched object data and writes it to its final destination.
 *
 * <p>This thread is responsible for a sequence of I/O-bound steps after the network layer has
 * produced a decoded stream: optionally hash the bytes while they are read, optionally pass the
 * content through the {@link network.crypta.client.filter.ContentFilter} (for MIME type
 * determination and HTML filtering/link discovery), and finally copy the resulting bytes into a
 * caller-supplied {@link java.io.OutputStream}. When hashing is enabled, computed digests are
 * compared against the expected {@link network.crypta.crypt.HashResult} values and a mismatch is
 * treated as a terminal error. When filtering is enabled, {@link ClientGetWorkerThread.Options}
 * controls callbacks and parameters for the filter pipeline.
 *
 * <p>The life-cycle is simple: construct a new instance, start the thread, and call {@link
 * #waitFinished()} to block until completion. The instance exposes a small amount of metadata
 * extracted by the content filter via {@link #getClientMetadata()}. Errors that occur on the worker
 * thread are recorded and rethrown on the calling thread when it invokes {@link #waitFinished()}
 * (via {@link #getError()}).
 *
 * <p><strong>Concurrency</strong>: instances are single-use. The worker executes on its dedicated
 * thread; callers coordinate using {@link #waitFinished()}. The implementation uses a simple
 * monitor ({@code synchronized}) and a completion flag. If the waiting thread is interrupted, it
 * keeps waiting for completion but restores the interrupt status after the monitor is released so
 * callers can observe the interruption without risking a deadlock.
 *
 * <ul>
 *   <li>Hashing: optional, uses {@link network.crypta.crypt.MultiHashInputStream}.
 *   <li>Filtering: optional, uses {@link network.crypta.client.filter.ContentFilter}.
 *   <li>Output: required, caller-owned {@link java.io.OutputStream}.
 * </ul>
 *
 * @see network.crypta.client.filter.ContentFilter
 * @see network.crypta.crypt.MultiHashInputStream
 * @see ClientGetWorkerThread.Options
 */
public class ClientGetWorkerThread extends Thread {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetWorkerThread.class);

  private final InputStream input;
  private final String schemeHostAndPort;
  private final URI uri;
  private final HashResult[] hashes;
  private final boolean filterData;
  private final String charset;
  private final FoundURICallback prefetchHook;
  private final TagReplacerCallback tagReplacer;

  /** Link filter exception provider. */
  private final LinkFilterExceptionProvider linkFilterExceptionProvider;

  private final String mimeType;
  private final OutputStream output;
  private boolean finished = false;
  private Throwable error = null;
  private ClientMetadata clientMetadata = null;

  private static int counter;

  private static synchronized int counter() {
    return counter++;
  }

  /**
   * Container for optional processing options that customize filtering and metadata extraction.
   *
   * <p>All components are optional unless otherwise stated. When filtering is disabled, MIME type
   * and charset are not used for content transformation, but may still be recorded as metadata when
   * available.
   *
   * @param mimeType Declared MIME type to guide filtering. May be {@code null}; XHTML is normalized
   *     to {@code text/html} to enable HTML-oriented processing.
   * @param schemeHostAndPort Origin scheme/host/port used by the filter when resolving relative
   *     links. Pass {@code null} to skip link resolution that needs an absolute base.
   * @param filterData Whether to enable content filtering. When {@code true}, data are passed
   *     through the filter; when {@code false}, bytes are copied directly to the output.
   * @param charset Character set hint used by the filter when present. May be {@code null} to allow
   *     detection or defaults inside the filter.
   * @param prefetchHook Callback invoked by the filter on discovered URIs for prefetching or
   *     inspection. May be {@code null} to disable prefetch notifications.
   * @param tagReplacer Callback that can rewrite or replace selected tags during filtering. May be
   *     {@code null} when no tag replacements are required.
   * @param linkFilterExceptionProvider Strategy for reporting and mapping link-related exceptions
   *     produced by the filter. May be {@code null} to use default behavior.
   */
  public record Options(
      String mimeType,
      String schemeHostAndPort,
      boolean filterData,
      String charset,
      FoundURICallback prefetchHook,
      TagReplacerCallback tagReplacer,
      LinkFilterExceptionProvider linkFilterExceptionProvider) {}

  /**
   * Creates a new worker for post-processing and persisting a fetched object.
   *
   * <p>The worker can hash the content as it is read, validate hashes (when provided), apply the
   * {@link network.crypta.client.filter.ContentFilter} (when enabled via {@link Options}), and copy
   * the resulting bytes into the supplied {@link java.io.OutputStream}. Constructed instances are
   * single-use; call {@link #start()} to begin processing, then {@link #waitFinished()} to observe
   * completion and surface any terminal error.
   *
   * @param input Source stream of decoded content bytes to consume. Must remain readable until the
   *     worker finishes. Must not be {@code null}.
   * @param output Destination stream that receives the final bytes. The worker closes this stream
   *     after processing. Must not be {@code null}.
   * @param uri Logical URI of the fetched object for use by the content filter (base URL, link
   *     processing). May be {@code null} to disable filter behaviors that require an absolute base.
   * @param hashes Expected content hashes. When non-{@code null}, the worker computes digests and
   *     verifies them against these values; a mismatch is treated as an error.
   * @param options Optional configuration for filtering and callbacks. May be {@code null} to use
   *     default behavior (no filtering, no callbacks).
   * @throws URISyntaxException if {@code uri} cannot be represented as a {@link URI} with a
   *     trailing slash for relative resolution.
   */
  public ClientGetWorkerThread(
      InputStream input, OutputStream output, FreenetURI uri, HashResult[] hashes, Options options)
      throws URISyntaxException {
    super("ClientGetWorkerThread-" + counter());
    this.input = input;
    if (uri != null) this.uri = uri.toURI("/");
    else this.uri = null;
    String normalizedMimeType = options == null ? null : options.mimeType();
    if (normalizedMimeType != null && normalizedMimeType.equals("application/xhtml+xml"))
      normalizedMimeType = "text/html";
    this.mimeType = normalizedMimeType;
    this.schemeHostAndPort = options == null ? null : options.schemeHostAndPort();
    this.hashes = hashes;
    this.output = output;
    this.filterData = options != null && options.filterData();
    this.charset = options == null ? null : options.charset();
    this.prefetchHook = options == null ? null : options.prefetchHook();
    this.tagReplacer = options == null ? null : options.tagReplacer();
    this.linkFilterExceptionProvider =
        options == null ? null : options.linkFilterExceptionProvider();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Created worker thread for {} mime type {} filter data = {} charset {}",
          uri,
          normalizedMimeType,
          this.filterData,
          this.charset);
  }

  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    logStart();
    try (InputStream managedInput = new BufferedInputStream(input);
        OutputStream managedOutput = output) {
      HashingContext hashing = setupHashing(managedInput);
      processData(hashing.input, managedOutput);
      drainRemaining(hashing.input);
      verifyHashesIfPresent(hashing.hashStream);
      onFinish();
    } catch (Throwable t) {
      logProcessingException(t);
      setError(t);
    }
  }

  private void logStart() {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Starting worker thread for {} mime type {} filter data = {} charset {}",
          uri,
          mimeType,
          filterData,
          charset);
    }
  }

  private record HashingContext(InputStream input, MultiHashInputStream hashStream) {}

  private HashingContext setupHashing(InputStream in) {
    if (hashes == null) return new HashingContext(in, null);
    MultiHashInputStream hs = new MultiHashInputStream(in, HashResult.makeBitmask(hashes));
    return new HashingContext(hs, hs);
  }

  private void processData(InputStream currentInput, OutputStream managedOutput)
      throws IOException {
    if (filterData) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Running content filter... Prefetch hook: {} tagReplacer: {}",
            prefetchHook,
            tagReplacer);
      }
      if (mimeType == null || uri == null || currentInput == null || managedOutput == null) {
        throw new IOException("Insufficient arguments to worker thread");
      }
      // Send XHTML as HTML because we can't use web-pushing on XHTML.
      ContentFilterRequest request =
          new ContentFilterRequest(
              currentInput, managedOutput, mimeType, charset, schemeHostAndPort, null);
      ContentFilterCallbacks callbacks =
          new ContentFilterCallbacks(uri, prefetchHook, tagReplacer, linkFilterExceptionProvider);
      FilterStatus filterStatus = ContentFilter.filter(request, callbacks);

      String detectedMIMEType =
          filterStatus.mimeType.concat(
              filterStatus.charset == null ? "" : "; charset=" + filterStatus.charset);
      synchronized (this) {
        clientMetadata = new ClientMetadata(detectedMIMEType);
      }
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Ignoring content filter. The final result has not been written. Writing now.");
    }
    FileUtil.copy(currentInput, managedOutput, -1);
  }

  private void drainRemaining(InputStream currentInput) throws IOException {
    try {
      while (true) {
        byte[] buf = new byte[4096];
        int r = currentInput.read(buf);
        if (r < 0) break;
      }
    } catch (EOFException _) {
      // End of stream reached; nothing to do.
    }
  }

  private void verifyHashesIfPresent(MultiHashInputStream hashStream) throws FetchException {
    if (hashes == null) return;
    HashResult[] results = hashStream.getResults();
    if (!HashResult.strictEquals(results, hashes)) {
      LOG.error(
          "Hashes failed verification (length read is {})  for {}", hashStream.getReadBytes(), uri);
      throw new FetchException(FetchExceptionMode.CONTENT_HASH_FAILED);
    }
  }

  private void logProcessingException(Throwable t) {
    if (!(t instanceof FetchException
        || t instanceof UnsafeContentTypeException
        || t instanceof CompressionOutputSizeException)) {
      LOG.error("Exception caught while processing fetch", t);
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Exception caught while processing fetch", t);
    }
  }

  /**
   * Returns metadata determined by the content filter, when filtering is enabled.
   *
   * <p>The metadata typically includes the effective MIME type and optional charset derived from
   * the processed content. When filtering is disabled or has not yet produced metadata, this method
   * may return {@code null}.
   *
   * @return metadata derived from the content filter, or {@code null} if unavailable or filtering
   *     was not performed.
   */
  public synchronized ClientMetadata getClientMetadata() {
    return clientMetadata;
  }

  /**
   * Records a terminal error and awakens any threads blocked in {@link #waitFinished()}.
   *
   * <p>Only the first error is retained; subsequent calls are ignored to preserve the original
   * failure cause. Callers should invoke {@link #waitFinished()} (or {@link #getError()}) to
   * surface the stored error on their thread.
   *
   * @param t the failure to record. A {@code null} value is ignored.
   */
  public synchronized void setError(Throwable t) {
    if (error != null) return;
    error = t;
    onFinish();
  }

  /**
   * Throws any previously recorded error as an unchecked exception on the calling thread.
   *
   * <p>If no error has been recorded, this method returns normally. This is typically invoked after
   * {@link #waitFinished()} as a convenience to rethrow the worker’s terminal failure without
   * changing the method signature.
   */
  public synchronized void getError() {
    if (error != null) rethrowUnchecked(error);
  }

  /**
   * Marks the worker as finished and wakes any thread waiting in {@link #waitFinished()}.
   *
   * <p>This is invoked exactly once at normal completion and also by {@link #setError(Throwable)}
   * when a terminal failure occurs.
   */
  public synchronized void onFinish() {
    finished = true;
    notifyAll();
  }

  /**
   * Blocks until the worker signals completion and surfaces any terminal error.
   *
   * <p>This method waits for the worker to finish normal processing or to record a terminal
   * failure. If the waiting thread is interrupted, the method keeps waiting so the monitor can be
   * released by {@link Object#wait()} and the worker can complete; the interrupt status is restored
   * after leaving the synchronized block so callers can observe it.
   *
   * <p>Any terminal error raised on the worker thread is rethrown on the calling thread via {@link
   * #getError()} after the worker has finished.
   */
  @SuppressWarnings("java:S2142")
  public void waitFinished() {
    boolean interrupted = false;
    synchronized (this) {
      while (!finished) {
        try {
          wait();
        } catch (InterruptedException _) {
          // Record and continue waiting so the monitor can be released by wait().
          // We restore the interrupt status after exiting the synchronized block.
          interrupted = true;
        }
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
    getError();
  }

  /**
   * Rethrows the given throwable without declaring it.
   *
   * <p>This uses a generic type-erasure trick to bypass checked exception declarations; callers
   * should treat the result as an unchecked rethrow.
   */
  private static void rethrowUnchecked(Throwable t) {
    ClientGetWorkerThread.throwAny(t);
  }

  /**
   * Sneaky-throw helper that rethrows a checked exception as if it were unchecked.
   *
   * @param t the throwable to rethrow
   */
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void throwAny(Throwable t) throws T {
    throw (T) t;
  }
}
