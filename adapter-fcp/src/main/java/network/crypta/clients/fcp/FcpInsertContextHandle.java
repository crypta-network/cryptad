package network.crypta.clients.fcp;

import java.io.Serializable;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.ClientEventProducer;

/**
 * Adapter-owned mutable handle for configuring a live insert context.
 *
 * <p>The adapter uses this interface instead of exposing the daemon's concrete {@code
 * InsertContext} type. Implementations may wrap a live runtime context or another bridge-owned
 * state holder, but callers only see the narrow insert surface needed by the FCP put path.
 *
 * <p>The contract intentionally mixes mutable request-specific knobs with read-only structural
 * limits. Callers are expected to copy a baseline handle from runtime defaults, apply the PUT
 * request's overrides through the setter methods, and then hand the handle back to bridge code when
 * an execution object or legacy serialization form is needed. The seam therefore documents the
 * remaining insert-context behavior that still belongs to the adapter without reintroducing the
 * daemon-owned type into adapter code.
 */
public interface FcpInsertContextHandle extends Serializable {
  /**
   * Sets whether this request should ask the runtime for CHK-only behavior.
   *
   * @param getCHKOnly {@code true} to request CHK-only handling; otherwise {@code false}
   */
  void setGetCHKOnly(boolean getCHKOnly);

  /**
   * Returns whether CHK-only behavior is currently enabled.
   *
   * @return {@code true} when CHK-only handling is enabled; otherwise {@code false}
   */
  boolean getCHKOnly();

  /**
   * Sets whether compression should be disabled for this request.
   *
   * @param dontCompress {@code true} to skip compression; otherwise {@code false}
   */
  void setDontCompress(boolean dontCompress);

  /**
   * Registers a listener on the handle's event producer.
   *
   * @param listener listener that should receive insert-related client events
   */
  void addEventListener(ClientEventListener listener);

  /**
   * Removes a previously registered listener from the handle's event producer.
   *
   * @param listener listener that should no longer receive client events
   * @return {@code true} if the listener was removed; otherwise {@code false}
   */
  @SuppressWarnings("UnusedReturnValue")
  boolean removeEventListener(ClientEventListener listener);

  /**
   * Returns the event producer backing this detached handle.
   *
   * @return event producer used for listener registration and event dispatch
   */
  ClientEventProducer eventProducer();

  /**
   * Sets the maximum insert retry count for this request.
   *
   * @param maxInsertRetries maximum retry count to apply
   */
  void setMaxInsertRetries(int maxInsertRetries);

  /**
   * Returns the configured maximum insert retry count.
   *
   * @return maximum retry count currently configured on the handle
   */
  int getMaxInsertRetries();

  /**
   * Returns the baseline count of consecutive RNFs that should count as success.
   *
   * @return consecutive RNF success threshold captured from the runtime defaults
   */
  int getConsecutiveRnfsCountAsSuccess();

  /**
   * Returns the baseline splitfile data-block limit per segment.
   *
   * @return maximum data blocks per splitfile segment
   */
  int getSplitfileSegmentDataBlocks();

  /**
   * Returns the baseline splitfile check-block limit per segment.
   *
   * @return maximum check blocks per splitfile segment
   */
  int getSplitfileSegmentCheckBlocks();

  /**
   * Sets whether the request may write into the client cache.
   *
   * @param canWriteClientCache {@code true} when client-cache writes are allowed
   */
  void setCanWriteClientCache(boolean canWriteClientCache);

  /**
   * Returns whether client-cache writes are currently allowed.
   *
   * @return {@code true} when client-cache writes are enabled; otherwise {@code false}
   */
  boolean canWriteClientCache();

  /**
   * Sets the compressor descriptor string for this request.
   *
   * @param compressorDescriptor compressor descriptor, or {@code null} for the default behavior
   */
  void setCompressorDescriptor(String compressorDescriptor);

  /**
   * Returns the configured compressor descriptor string.
   *
   * @return compressor descriptor, or {@code null} when the default runtime behavior is desired
   */
  String getCompressorDescriptor();

  /**
   * Sets whether cacheable inserts may fork additional work.
   *
   * @param forkOnCacheable {@code true} when cacheable inserts may fork; otherwise {@code false}
   */
  void setForkOnCacheable(boolean forkOnCacheable);

  /**
   * Returns whether cacheable inserts may fork additional work.
   *
   * @return {@code true} when fork-on-cacheable is enabled; otherwise {@code false}
   */
  boolean forkOnCacheable();

  /**
   * Sets the extra-insert count for single-block inserts.
   *
   * @param extraInsertsSingleBlock redundancy value for standalone single-block inserts
   */
  void setExtraInsertsSingleBlock(int extraInsertsSingleBlock);

  /**
   * Returns the extra-insert count for single-block inserts.
   *
   * @return redundancy value for standalone single-block inserts
   */
  int getExtraInsertsSingleBlock();

  /**
   * Sets the extra-insert count for splitfile header blocks.
   *
   * @param extraInsertsSplitfileHeaderBlock redundancy value for splitfile header blocks
   */
  void setExtraInsertsSplitfileHeaderBlock(int extraInsertsSplitfileHeaderBlock);

  /**
   * Returns the extra-insert count for splitfile header blocks.
   *
   * @return redundancy value for splitfile header blocks
   */
  int getExtraInsertsSplitfileHeaderBlock();

  /**
   * Sets the detached compatibility mode for this request.
   *
   * @param compatibilityMode compatibility mode to apply to the request
   */
  void setCompatibilityMode(FcpCompatibilityMode compatibilityMode);

  /**
   * Returns the detached compatibility mode currently configured on the handle.
   *
   * @return compatibility mode currently selected for the request
   */
  FcpCompatibilityMode getCompatibilityMode();

  /**
   * Sets whether the request is restricted to local handling only.
   *
   * @param localRequestOnly {@code true} to keep the request local; otherwise {@code false}
   */
  void setLocalRequestOnly(boolean localRequestOnly);

  /**
   * Returns whether the request is restricted to local handling only.
   *
   * @return {@code true} when the request is local-only; otherwise {@code false}
   */
  boolean localRequestOnly();

  /**
   * Sets whether early-encode behavior is enabled.
   *
   * @param earlyEncode {@code true} to enable early encoding; otherwise {@code false}
   */
  void setEarlyEncode(boolean earlyEncode);

  /**
   * Returns whether early-encode behavior is enabled.
   *
   * @return {@code true} when early encoding is enabled; otherwise {@code false}
   */
  boolean earlyEncode();

  /**
   * Sets whether USK datehints should be ignored.
   *
   * @param ignoreUSKDatehints {@code true} to ignore USK datehints; otherwise {@code false}
   */
  void setIgnoreUSKDatehints(boolean ignoreUSKDatehints);

  /**
   * Returns whether USK datehints are ignored.
   *
   * @return {@code true} when USK datehints are ignored; otherwise {@code false}
   */
  boolean ignoreUSKDatehints();

  /**
   * Returns whether compression is currently disabled.
   *
   * @return {@code true} when compression is disabled; otherwise {@code false}
   */
  boolean isDontCompress();
}
