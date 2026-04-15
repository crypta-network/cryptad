package network.crypta.clients.fcp;

import java.io.Serial;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores mutable runtime state for a {@link ClientGet} request.
 *
 * <p>The state object centralizes data that evolves during a fetch: progress snapshots, failure
 * metadata, compatibility hints, and any buckets retained for direct delivery. It keeps the core
 * request class focused on orchestration while allowing helper classes to update specific fields.
 * The state does not enforce synchronization; callers must coordinate access using the owning
 * request's lock to maintain consistent snapshots across threads.
 *
 * <p>Values stored here are intentionally mutable and are not safe to read concurrently without
 * locking. Accessors should be treated as point-in-time views, especially when a request is
 * actively fetching or restarting.
 *
 * <ul>
 *   <li><strong>Progress</strong>: length, MIME, and splitfile progress hints.
 *   <li><strong>Failure</strong>: cached {@link GetFailedMessage} and expected hashes.
 *   <li><strong>Compatibility</strong>: mode analysis and optional crypto key hints.
 * </ul>
 *
 * @see ClientGet
 */
final class ClientGetState implements Serializable {
  /** Serialization version for the mutable request state container. */
  @Serial private static final long serialVersionUID = 1L;

  private static final String LEGACY_COMPATIBILITY_ANALYSER_CLASS =
      "network.crypta.client.async.CompatibilityAnalyser";

  /** Logger for unexpected state transitions or duplicate metadata. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetState.class);

  /** Owning request used for cache updates and message routing. */
  private final ClientGet request;

  /** True, once the request has recorded a terminal success. */
  private boolean succeeded;

  /** Best-known payload length in bytes, or {@code -1} when unknown. */
  private long foundDataLength = -1;

  /** Best-known MIME type string, or {@code null} when not yet reported. */
  private String foundDataMimeType;

  /** Cached failure message for the most recent terminal failure, if any. */
  private GetFailedMessage getFailedMessage;

  /** The last splitfile progress snapshot captured for status reporting. */
  private transient SimpleProgressMessage progressPending;

  /** True once a {@link SendingToNetworkMessage} has been observed. */
  private boolean sentToNetwork;

  /**
   * Compatibility analysis accumulating splitfile compatibility hints.
   *
   * <p>The field intentionally tolerates a legacy serialized {@code CompatibilityAnalyser} object
   * until the first accessor normalizes it into {@link FcpCompatibilityAnalysis}.
   */
  private Object compatMode;

  /** Expected hashes derived from splitfile metadata, or {@code null} when unknown. */
  private ExpectedHashes expectedHashes;

  /** Bucket retained for direct delivery, or {@code null} when unused. */
  @SuppressWarnings("java:S1948")
  private Bucket returnBucketDirect;

  /**
   * Creates a new state container bound to a specific request.
   *
   * <p>The constructor initializes the compatibility analyzer so that compatibility hints can be
   * merged immediately when events arrive.
   *
   * @param request owning request used for cache updates and message routing.
   */
  ClientGetState(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
    this.compatMode = new FcpCompatibilityAnalysis();
  }

  /**
   * Reports whether the request has recorded a successful terminal state.
   *
   * @return {@code true} once success is recorded, {@code false} otherwise.
   */
  boolean hasSucceeded() {
    return succeeded;
  }

  /**
   * Records whether the request has reached a successful terminal state.
   *
   * @param succeeded {@code true} to mark success, {@code false} otherwise.
   */
  void setSucceeded(boolean succeeded) {
    this.succeeded = succeeded;
  }

  /**
   * Returns the best-known payload length in bytes.
   *
   * @return payload length, or {@code -1} when unknown.
   */
  long getFoundDataLength() {
    return foundDataLength;
  }

  /**
   * Updates the cached payload length in bytes.
   *
   * @param foundDataLength non-negative payload length, or {@code -1} when unknown.
   */
  void setFoundDataLength(long foundDataLength) {
    this.foundDataLength = foundDataLength;
  }

  /**
   * Returns the best-known MIME type reported for the payload.
   *
   * @return MIME type string, or {@code null} when not yet reported.
   */
  String getFoundDataMimeType() {
    return foundDataMimeType;
  }

  /**
   * Updates the cached MIME type for the payload.
   *
   * @param foundDataMimeType MIME type string, or {@code null} when unknown.
   */
  void setFoundDataMimeType(String foundDataMimeType) {
    this.foundDataMimeType = foundDataMimeType;
  }

  /**
   * Returns the most recent splitfile progress snapshot.
   *
   * @return last {@link SimpleProgressMessage}, or {@code null} when none exists.
   */
  SimpleProgressMessage getProgressPending() {
    return progressPending;
  }

  /**
   * Records the latest splitfile progress snapshot.
   *
   * @param progressPending progress snapshot to cache, or {@code null} to clear.
   */
  void setProgressPending(SimpleProgressMessage progressPending) {
    this.progressPending = progressPending;
  }

  /**
   * Returns whether a sending-to-network event has been observed.
   *
   * @return {@code true} when the event has been recorded.
   */
  boolean hasSentToNetwork() {
    return sentToNetwork;
  }

  /** Marks that a sending-to-network event has been received. */
  void markSentToNetwork() {
    sentToNetwork = true;
  }

  /**
   * Returns the expected hash metadata, if available.
   *
   * @return expected hashes instance, or {@code null} when unknown.
   */
  ExpectedHashes getExpectedHashes() {
    return expectedHashes;
  }

  /**
   * Sets the expected hash metadata directly.
   *
   * @param expectedHashes expected hash metadata, or {@code null} to clear.
   */
  void setExpectedHashes(ExpectedHashes expectedHashes) {
    this.expectedHashes = expectedHashes;
  }

  /**
   * Attempts to set the expected hash metadata only if it has not been set.
   *
   * @param hashes expected hash metadata to record.
   * @return {@code true} when the metadata was stored, {@code false} if already present.
   */
  boolean trySetExpectedHashes(ExpectedHashes hashes) {
    if (expectedHashes != null) {
      LOG.warn("Got a new ExpectedHashes");
      return false;
    }
    expectedHashes = hashes;
    return true;
  }

  /** Clears any cached expected hash metadata. */
  void clearExpectedHashes() {
    expectedHashes = null;
  }

  /**
   * Returns the cached failure message for the last terminal failure.
   *
   * @return failure message, or {@code null} when no failure is recorded.
   */
  GetFailedMessage getFailedMessage() {
    return getFailedMessage;
  }

  /**
   * Updates the cached failure message.
   *
   * @param message failure message to store, or {@code null} to clear.
   */
  void setFailedMessage(GetFailedMessage message) {
    getFailedMessage = message;
  }

  /**
   * Returns the compatibility analyzer used to accumulate splitfile metadata.
   *
   * @return compatibility analyzer instance; may be {@code null} if not initialized.
   */
  FcpCompatibilityAnalysis getCompatibilityAnalyser() {
    return compatibilityAnalysis();
  }

  /**
   * Replaces the compatibility analyzer instance.
   *
   * @param compatMode analyzer instance to store; may be {@code null}.
   */
  void setCompatibilityAnalyser(FcpCompatibilityAnalysis compatMode) {
    this.compatMode = compatMode;
  }

  /** Ensures a compatibility analysis exists, creating one if missing. */
  void ensureCompatibilityMode() {
    compatibilityAnalysis();
  }

  /** Resets the compatibility analysis to a fresh, empty instance. */
  void resetCompatibilityMode() {
    compatMode = new FcpCompatibilityAnalysis();
  }

  /**
   * Returns the compatibility modes accumulated so far.
   *
   * @return array of compatibility modes; never {@code null}.
   */
  FcpCompatibilityMode[] getCompatibilityMode() {
    return compatibilityAnalysis().getModes();
  }

  /**
   * Indicates whether compression should be skipped for reinsertion.
   *
   * @return {@code true} when the payload is already compressed.
   */
  boolean getDontCompress() {
    return compatibilityAnalysis().dontCompress();
  }

  /**
   * Returns the optional crypto key inferred from splitfile metadata.
   *
   * @return crypto key bytes, or {@code null} when no override exists.
   */
  byte[] getOverriddenSplitfileCryptoKey() {
    return compatibilityAnalysis().getCryptoKey();
  }

  /**
   * Merges new compatibility hints and notifies caches if configured.
   *
   * <p>The method updates the compatibility analyzer, emits cache updates, and optionally enqueues
   * a {@link CompatibilityMode} message based on request verbosity.
   *
   * @param minCompatibilityMode minimum compatibility mode hint.
   * @param maxCompatibilityMode maximum compatibility mode hint.
   * @param splitfileCryptoKey optional crypto key override from metadata.
   * @param dontCompress true when the payload should not be recompressed.
   * @param bottomLayer true when hints apply to the bottom layer of the splitfile.
   */
  void mergeCompatibilityMode(
      FcpCompatibilityMode minCompatibilityMode,
      FcpCompatibilityMode maxCompatibilityMode,
      byte[] splitfileCryptoKey,
      boolean dontCompress,
      boolean bottomLayer) {
    ensureCompatibilityMode();
    FcpCompatibilityAnalysis compatibilityAnalysis = compatibilityAnalysis();
    compatibilityAnalysis.merge(
        minCompatibilityMode, maxCompatibilityMode, splitfileCryptoKey, dontCompress, bottomLayer);
    if (request.client != null) {
      RequestStatusCache cache = request.client.getRequestStatusCache();
      if (cache != null) {
        cache.updateDetectedCompatModes(
            request.identifier,
            compatibilityAnalysis.getModes(),
            compatibilityAnalysis.getCryptoKey(),
            compatibilityAnalysis.dontCompress());
      }
    }
    if ((request.verbosity & ClientGet.VERBOSITY_COMPATIBILITY_MODE) != 0) {
      request.queueProgressMessageInner(
          new CompatibilityMode(request.identifier, request.global, compatibilityAnalysis),
          ClientGet.VERBOSITY_COMPATIBILITY_MODE);
    }
  }

  private FcpCompatibilityAnalysis compatibilityAnalysis() {
    if (compatMode instanceof FcpCompatibilityAnalysis compatibilityAnalysis) {
      return compatibilityAnalysis;
    }
    if (compatMode == null) {
      FcpCompatibilityAnalysis compatibilityAnalysis = new FcpCompatibilityAnalysis();
      compatMode = compatibilityAnalysis;
      return compatibilityAnalysis;
    }
    if (isLegacyCompatibilityAnalyser(compatMode)) {
      FcpCompatibilityAnalysis compatibilityAnalysis =
          migrateLegacyCompatibilityAnalyser(compatMode);
      compatMode = compatibilityAnalysis;
      return compatibilityAnalysis;
    }
    throw new IllegalStateException(
        "Unsupported ClientGetState compatibility analysis type: "
            + compatMode.getClass().getName());
  }

  private static boolean isLegacyCompatibilityAnalyser(Object value) {
    return value.getClass().getName().equals(LEGACY_COMPATIBILITY_ANALYSER_CLASS);
  }

  private static FcpCompatibilityAnalysis migrateLegacyCompatibilityAnalyser(
      Object legacyCompatibilityAnalyser) {
    FcpCompatibilityAnalysis compatibilityAnalysis = new FcpCompatibilityAnalysis();
    compatibilityAnalysis.merge(
        detachedCompatibilityMode(invokeLegacyAnalyserMethod(legacyCompatibilityAnalyser, "min")),
        detachedCompatibilityMode(invokeLegacyAnalyserMethod(legacyCompatibilityAnalyser, "max")),
        copyCryptoKey(invokeLegacyAnalyserMethod(legacyCompatibilityAnalyser, "getCryptoKey")),
        (boolean) invokeLegacyAnalyserMethod(legacyCompatibilityAnalyser, "dontCompress"),
        (boolean) invokeLegacyAnalyserMethod(legacyCompatibilityAnalyser, "definitive"));
    return compatibilityAnalysis;
  }

  private static FcpCompatibilityMode detachedCompatibilityMode(Object legacyMode) {
    if (legacyMode instanceof Enum<?> enumValue) {
      return FcpCompatibilityMode.valueOf(enumValue.name());
    }
    throw new IllegalStateException(
        "Legacy compatibility mode is not an enum: "
            + (legacyMode == null ? "null" : legacyMode.getClass().getName()));
  }

  private static byte[] copyCryptoKey(Object legacyCryptoKey) {
    if (legacyCryptoKey == null) {
      return null;
    }
    if (legacyCryptoKey instanceof byte[] cryptoKey) {
      return Arrays.copyOf(cryptoKey, cryptoKey.length);
    }
    throw new IllegalStateException(
        "Legacy compatibility crypto key is not a byte array: "
            + legacyCryptoKey.getClass().getName());
  }

  private static Object invokeLegacyAnalyserMethod(
      Object legacyCompatibilityAnalyser, String method) {
    try {
      return legacyCompatibilityAnalyser
          .getClass()
          .getMethod(method)
          .invoke(legacyCompatibilityAnalyser);
    } catch (IllegalAccessException | NoSuchMethodException e) {
      throw new IllegalStateException(
          "Legacy compatibility analyser does not expose method " + method, e);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause() == null ? e : e.getCause();
      throw new IllegalStateException(
          "Legacy compatibility analyser method " + method + " failed", cause);
    }
  }

  /**
   * Returns the direct-delivery bucket if one is retained.
   *
   * @return bucket containing payload bytes, or {@code null} when not retained.
   */
  Bucket getReturnBucketDirect() {
    return returnBucketDirect;
  }

  /**
   * Stores the direct-delivery bucket for later replay.
   *
   * @param bucket payload bucket to retain, or {@code null} to clear.
   */
  void setReturnBucketDirect(Bucket bucket) {
    returnBucketDirect = bucket;
  }

  /**
   * Returns and clears the direct-delivery bucket.
   *
   * @return previously stored bucket, or {@code null} if none was stored.
   */
  Bucket takeReturnBucketDirect() {
    Bucket data = returnBucketDirect;
    returnBucketDirect = null;
    return data;
  }
}
