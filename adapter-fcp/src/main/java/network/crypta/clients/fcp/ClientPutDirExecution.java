package network.crypta.clients.fcp;

import java.util.List;
import java.util.Map;
import network.crypta.support.io.ResumeFailedException;

/**
 * Opaque adapter-owned handle for one live directory/manifest insert execution.
 *
 * <p>The bridge owns the concrete manifest putter, while the adapter keeps only the request-scoped
 * lifecycle contract and the minimal resume hook used by persistent manifests. Callers treat an
 * instance of this interface as the live execution state for a single directory insert attempt:
 * they can inspect the file count and aggregate size that were computed when the manifest was
 * prepared, start or restart the transfer through the inherited methods, and reattach transient
 * metadata when a persistent request is resumed after a restart.
 *
 * <p>The handle is intentionally narrow. It does not expose the runtime-owned manifest putter type,
 * container builder state, or scheduler internals. That keeps the insert-specific boundary aligned
 * with the Phase 2 split: {@code :adapter-fcp} owns request lifecycle and protocol reporting, while
 * {@code :bridge-fcp-runtime} owns the daemon-core wiring and the concrete insert engine.
 */
public interface ClientPutDirExecution extends ClientPutExecution {

  /**
   * Returns the number of files counted for the current manifest execution.
   *
   * <p>The value reflects the manifest tree handed to the bridge when the execution was
   * constructed. It is primarily used to populate FCP status messages and persistent tags so
   * clients can display deterministic progress information before the transfer starts.
   *
   * @return non-negative count of file entries represented by this manifest execution
   */
  int countFiles();

  /**
   * Returns the aggregate byte size tracked for the current manifest execution.
   *
   * <p>This is the total raw content size derived from the manifest elements, not a measure of
   * protocol overhead or encoded container size. The adapter uses it for user-visible progress
   * reporting and persistence snapshots.
   *
   * @return total number of payload bytes represented by this manifest execution
   */
  long totalSize();

  /**
   * Returns a detached snapshot of the manifest entries for persistent-tag serialization.
   *
   * <p>The bridge/runtime side owns manifest flattening and upload-source classification. The
   * adapter consumes only the resulting detached entry descriptors when rebuilding a {@link
   * PersistentPutDir} message.
   *
   * @return detached manifest entry snapshots in the wire order expected by {@code Files.N}
   */
  List<PersistentPutDirEntrySnapshot> persistentPutDirEntries();

  /**
   * Rehydrates transient manifest metadata after a persistent request resumes.
   *
   * <p>Persistent directory inserts can survive JVM restarts, but nested manifest elements may need
   * to reopen buckets or rebuild runtime-owned metadata before insertion can continue. The adapter
   * calls this hook during request resume, passing the request-owned manifest tree and the current
   * client context so the bridge can restore that transient state without leaking runtime types
   * back into the adapter layer.
   *
   * @param manifestElements request-owned manifest tree whose elements should be reattached to live
   *     runtime state
   * @param context live client context that provides resume-time factories and services
   * @throws ResumeFailedException if any manifest element cannot restore the required transient
   *     runtime state
   */
  void resumeMetadata(
      Map<String, Object> manifestElements, network.crypta.client.async.ClientContext context)
      throws ResumeFailedException;
}
