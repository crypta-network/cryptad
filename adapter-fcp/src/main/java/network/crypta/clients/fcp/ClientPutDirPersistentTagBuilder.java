package network.crypta.clients.fcp;

import java.io.InvalidObjectException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds replayable {@link PersistentPutDir} messages from the mutable state held by {@link
 * ClientPutDir}.
 *
 * <p>The surrounding request tracks live execution state, legacy persistence metadata, and the
 * manifest tree that may survive node restarts. This helper turns that mix of state back into the
 * detached FCP wire message used for reconnection replies, persistent-request listings, and other
 * replay-style responses. The class deliberately keeps that snapshot assembly out of the request
 * shell so the request can focus on lifecycle transitions rather than on serializing itself back
 * into FCP-visible DTOs.
 *
 * <p>Its most important behavior is the fallback path. When a live {@link ClientPutDirExecution}
 * wrapper is available, the builder prefers the bridge-owned detached manifest snapshots from that
 * execution. When the wrapper is missing but the persisted manifest tree is still present, the
 * builder asks the legacy bridge to snapshot that stored tree instead. That preserves the existing
 * replay semantics for durable directory inserts instead of silently reporting an empty manifest.
 *
 * <ul>
 *   <li>Builds the stable {@code PersistentPutDir} wire representation for one request.
 *   <li>Prefers live-detached entry snapshots when an execution wrapper is available.
 *   <li>Falls back to the restored manifest tree when replaying partially rehydrated requests.
 * </ul>
 */
final class ClientPutDirPersistentTagBuilder {
  /** Logger used for replay-path diagnostics when a persistent state is only partially attached. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutDirPersistentTagBuilder.class);

  /** Request whose mutable and restored state will be translated into a detached FCP reply. */
  private final ClientPutDir request;

  /**
   * Creates a builder bound to one directory insert request.
   *
   * @param request request whose current and restored state should be serialized back into FCP
   */
  ClientPutDirPersistentTagBuilder(ClientPutDir request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Builds the persistent-tag reply that mirrors the current request state.
   *
   * <p>The returned message includes the request identifiers, insert settings, compatibility hints,
   * optional splitfile crypto key, and the best available detached manifest snapshot. Missing live
   * runtime collaborators are tolerated because persistent requests may be replayed while they are
   * only partially reattached after deserialization. In that case the builder logs the gap and
   * falls back to the persisted manifest tree when possible.
   *
   * @return detached {@link PersistentPutDir} message ready for FCP replay
   */
  FCPMessage persistentTagMessage() {
    ClientPutDirExecution execution = request.persistentTagExecution();
    if (request.lowLevelClient == null) {
      LOG.warn("Persistent snapshot missing low-level client");
    }
    if (execution == null) {
      LOG.warn("Persistent snapshot missing putter");
    }

    List<PersistentPutDirEntrySnapshot> manifestSnapshot = manifestSnapshot(execution);
    ClientRequestParams requestParams =
        new ClientRequestParams(
            request.publicURI,
            request.identifier,
            request.verbosity,
            request.priorityClass,
            request.persistence,
            realTimeFlag(),
            request.clientToken,
            request.global);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            request.uri,
            request.started,
            request.ctx.getMaxInsertRetries(),
            request.ctx.getCompatibilityMode(),
            request.ctx.isDontCompress(),
            request.ctx.getCompressorDescriptor(),
            execution != null ? execution.getSplitfileCryptoKey() : null);
    return new PersistentPutDir(
        requestParams,
        metadata,
        request.persistentTagDefaultName(),
        manifestSnapshot,
        request.persistentTagWasDiskPut());
  }

  /**
   * Selects the manifest snapshot source for persistent-tag serialization.
   *
   * <p>Live executions already expose bridge-owned {@link PersistentPutDirEntrySnapshot} values and
   * therefore remain the preferred source. When the execution wrapper is missing, the method
   * attempts to rebuild the same detached entry list from the restored manifest tree through the
   * legacy bridge. If no manifest is available, or the bridge cannot be resolved, the builder
   * degrades to an empty snapshot rather than failing the reply path.
   *
   * @param execution live execution wrapper, or {@code null} during replay-only fallback paths
   * @return detached manifest entry snapshots in the order expected by {@code PersistentPutDir}
   */
  private List<PersistentPutDirEntrySnapshot> manifestSnapshot(ClientPutDirExecution execution) {
    if (execution != null) {
      return execution.persistentPutDirEntries();
    }
    Map<String, Object> manifestElements = request.persistentTagManifestElements();
    if (manifestElements == null) {
      return List.of();
    }
    try {
      return LegacyInsertExecutionBridgeLoader.load()
          .snapshotPersistentPutDirEntries(manifestElements);
    } catch (InvalidObjectException e) {
      LOG.warn("Persistent snapshot manifest fallback unavailable", e);
      return List.of();
    }
  }

  /**
   * Returns the real-time scheduling flag for the replayed request.
   *
   * <p>Older or partially corrupted persistent requests may be missing the low-level request
   * client. In that case the builder preserves the historical defensive behavior and reports {@code
   * false} rather than throwing while generating the persistent-tag reply.
   *
   * @return current real-time flag, or {@code false} when the low-level client is unavailable
   */
  private boolean realTimeFlag() {
    if (request.lowLevelClient == null) {
      return false;
    }
    return request.lowLevelClient.realTimeFlag();
  }
}
