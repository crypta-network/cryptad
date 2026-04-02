package network.crypta.client.async;

import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.crypt.ChecksumChecker;

/**
 * Callback contract for persistent client requests that must be recoverable across restarts.
 *
 * <p>Persistent fetches and inserts need to serialize a high‑level description of the request so it
 * can be restored even when full object serialization is unavailable or fails. Implementations use
 * {@link #getClientDetail(DataOutputStream, ChecksumChecker)} to emit a compact representation that
 * captures both how to restart the request from scratch and, when applicable, a summary of the
 * final outcome. The data can be stored alongside artifacts such as splitfile downloads so recovery
 * does not depend solely on database state.
 *
 * <p>Typical usage includes two scenarios. First, during checkpointing the node writes this summary
 * so a request can be recovered even if serializer state is inconsistent at that moment. Second,
 * when creating a splitfile, the summary is stored with the file so the request can be restarted
 * using only the splitfile. Because the summary is not incrementally updated, values that users can
 * change after start (for example, priority or client token) may be stale when restored.
 *
 * <ul>
 *   <li>Encodes sufficient information to restart the request from scratch.
 *   <li>When complete, may include outcome details (e.g., MIME type, final storage location).
 *   <li>For simple final states (e.g., splitfile downloads), includes resume information such as a
 *       filename and basic metadata.
 * </ul>
 *
 * @see ClientBaseCallback
 * @see ChecksumChecker
 */
public interface PersistentClientCallback extends ClientBaseCallback {

  /**
   * Writes a high‑level representation of the request for recovery.
   *
   * <p>The serialized form should include:
   *
   * <ul>
   *   <li>Enough information to restart the request from scratch, including values that users may
   *       change manually after start (for example, priority and client token).
   *   <li>If the request has completed, details describing the outcome such as MIME type and final
   *       storage location.
   *   <li>For <em>simple</em> final states (e.g., splitfile downloads), sufficient data to resume
   *       the request later—typically the splitfile filename plus metadata not carried by the
   *       splitfile (e.g., MIME type). Single‑block fetches, multi‑level metadata fetches, and
   *       container fetches are out of scope for this shortcut.
   * </ul>
   *
   * <p>Called when checkpointing and when creating a splitfile. The written summary is not updated
   * after initial emission; when restored, fields such as priority or client token might therefore
   * be stale relative to the latest in‑memory state.
   *
   * @param dos destination stream to receive the recovery summary; must be open and writable for
   *     the duration of the call; callers manage its lifecycle including closing and flushing.
   * @param checker checksum helper to accompany the emitted data; implementations may consult it to
   *     compute or append checksums that protect the summary against corruption during storage.
   * @throws IOException if writing to {@code dos} fails or the summary cannot be produced due to an
   *     underlying I/O error.
   */
  void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException;
}
