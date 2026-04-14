package network.crypta.clients.fcp;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;
import network.crypta.client.InsertContext;

/**
 * Detached directory insert description consumed by the bridge runtime.
 *
 * <p>This specification captures the adapter-owned inputs that the bridge needs to create or
 * recreate a live manifest putter for a {@link ClientPutDir}. It deliberately keeps request
 * identity, insert policy, and manifest access together while leaving the concrete daemon-owned
 * execution types on the bridge side of the module boundary. Unlike the earlier refactor draft, it
 * does not clone the whole manifest tree; instead, it reads the request-owned manifest lazily
 * through the callback. That preserves persistent-request behavior without retaining duplicate
 * manifest copies for large site inserts.
 */
public final class ClientPutDirExecutionSpec implements Serializable {
  /** Serialization identifier preserved for persistent request compatibility. */
  @Serial private static final long serialVersionUID = 1L;

  /** The owning request that supplies callbacks, current priority, and the live manifest tree. */
  private final ClientPutDir callback;

  /** Request-scoped identity and persistence metadata captured when the execution is assembled. */
  private final ClientRequestParams requestParams;

  /** The insert policy snapshot that the bridge forwards into the manifest putter. */
  private final InsertContext insertContext;

  /** Preferred default document name for the inserted manifest, if any. */
  private final String defaultName;

  /** Optional splitfile crypto key override supplied by the client. */
  private final byte[] forceCryptoKey;

  /**
   * Creates a detached manifest-execution specification for one directory insert request.
   *
   * <p>The constructor stores the request callback and the stable insert parameters needed to build
   * a live manifest putter later. It does not touch the filesystem, allocate buckets, or copy the
   * request manifest tree. Bridge code can therefore keep this object alongside a persistent
   * request without introducing another full manifest clone in memory.
   *
   * @param callback owning directory insert request that provides callbacks and manifest access
   * @param requestParams detached request identity and persistence metadata for this insert
   * @param insertContext insert policy snapshot to apply when the bridge creates a manifest putter
   * @param defaultName preferred default document name for manifest fetches, or {@code null}
   * @param forceCryptoKey optional splitfile crypto key override, or {@code null}
   */
  public ClientPutDirExecutionSpec(
      ClientPutDir callback,
      ClientRequestParams requestParams,
      InsertContext insertContext,
      String defaultName,
      byte[] forceCryptoKey) {
    this.callback = callback;
    this.requestParams = requestParams;
    this.insertContext = insertContext;
    this.defaultName = defaultName;
    this.forceCryptoKey = forceCryptoKey;
  }

  /**
   * Returns the callback surface that should receive insert lifecycle notifications.
   *
   * <p>The bridge uses this callback when wiring a concrete manifest putter so that completion,
   * failure, and progress events flow back into the existing {@link ClientPutDir} request logic.
   *
   * @return owning request callback for the directory insert execution
   */
  public ClientPutBase callback() {
    return callback;
  }

  /**
   * Returns the detached request metadata associated with this manifest execution.
   *
   * <p>The returned value includes the target URI, identifier, persistence mode, and original
   * priority snapshot. Bridge code uses it for restart-time reconstruction and for settings that do
   * not need to track the later mutable request state.
   *
   * @return request-scoped metadata captured for this directory insert execution
   */
  public ClientRequestParams requestParams() {
    return requestParams;
  }

  /**
   * Returns the insert policy snapshot that governs manifest creation.
   *
   * <p>This context carries retry, compression, caching, and compatibility settings that should be
   * applied when the bridge creates a live manifest putter. The bridge treats it as the
   * request-specific insert policy for this execution.
   *
   * @return the insert policy snapshot to pass into the runtime-owned manifest putter
   */
  public InsertContext insertContext() {
    return insertContext;
  }

  /**
   * Returns the current priority class that should be used for a restart.
   *
   * <p>Persistent requests can be reprioritized after construction through {@code
   * ModifyPersistentRequest}. When the owning callback is available, this method reflects that
   * current request priority instead of the original snapshot in {@link #requestParams()}. The
   * fallback keeps recovery code safe if a callback is unavailable.
   *
   * @return current effective priority class for the directory insert execution
   */
  public short priorityClass() {
    return callback == null ? requestParams.priorityClass() : callback.priorityClass;
  }

  /**
   * Returns the preferred default document name for the manifest.
   *
   * <p>The bridge forwards this value to the concrete manifest putter so that directory fetches can
   * resolve an index document consistently with the original FCP request semantics.
   *
   * @return default document name for the manifest, or {@code null} if none was requested
   */
  public String defaultName() {
    return defaultName;
  }

  /**
   * Returns the explicit splitfile crypto key override if one was provided.
   *
   * <p>The bridge uses this key when reconstructing a manifest putter, so restart behavior remains
   * consistent with the original insert request.
   *
   * @return explicit splitfile crypto key override, or {@code null} when the runtime should choose
   *     its normal keying behavior
   */
  public byte[] forceCryptoKey() {
    return forceCryptoKey;
  }

  /**
   * Returns the request-owned manifest tree for this execution.
   *
   * <p>The manifest is resolved lazily from the owning {@link ClientPutDir} rather than being
   * duplicated inside the spec. That keeps the bridge supplied with the authoritative manifest
   * structure while avoiding a second in-memory tree for large persistent directory inserts.
   *
   * @return live request-owned manifest tree used to assemble the manifest putter
   */
  public Map<String, Object> manifestElements() {
    return callback.manifestElementsForExecution();
  }
}
