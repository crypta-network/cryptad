package network.crypta.clients.fcp;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.InsertException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;

/**
 * Adapter-owned callback contract for live insert lifecycle events.
 *
 * <p>This interface is the adapter-side replacement for the runtime {@code ClientPutCallback}. The
 * bridge runtime owns the concrete daemon inserter and adapts that inserter back to this detached
 * surface, which lets {@code :adapter-fcp} react to insert progress without importing the
 * runtime-owned callback or putter classes directly. In practice, implementations are long-lived
 * request objects such as {@link ClientPutBase} descendants that need to survive reconnections,
 * Java serialization, and persistent-request resume.
 *
 * <p>The contract deliberately mixes two kinds of responsibilities. First, it carries the
 * user-visible lifecycle events that the FCP layer exposes, such as generated URIs, metadata-only
 * completion, fetchable hints, terminal success, and terminal failure. Second, because persistent
 * requests still serialize a higher-level client description, it also exposes the small recovery
 * hooks needed to resume and identify the owning request across restarts. That combination keeps
 * the seam narrow while preserving the historical persistent-request behavior.
 *
 * <p>Implementations should treat the callback as request-scoped rather than reusable. The bridge
 * may call these methods on runtime worker threads, so implementors should avoid long blocking work
 * and should treat the supplied {@link FcpInsertCallbackState} as a transient, read-only snapshot
 * of the current live putter.
 *
 * <ul>
 *   <li>Receives user-visible insert lifecycle notifications from the bridge runtime.
 *   <li>Provides persistent-request resume and serialization hooks for the owning request.
 *   <li>Hides the concrete runtime {@code ClientPutCallback} and putter types from the adapter.
 * </ul>
 */
public interface FcpInsertCallback extends Serializable {

  /**
   * Stable serialization version for callback implementations that survive persistent-request
   * snapshots.
   */
  @Serial long serialVersionUID = 1L;

  /**
   * Reattaches transient runtime collaborators after persistent-request resume.
   *
   * <p>Persistent FCP requests are Java-serialized and later rebound to a fresh daemon runtime. The
   * bridge invokes this hook during that resume flow, so the owning request can recreate any
   * transient state that depends on the detached request runtime context, such as
   * persistent-request coordinator handles, bucket factories, or scheduler-facing state.
   *
   * @param context detached request runtime context supplied during resume; it carries the runtime
   *     services needed to reattach the owning request safely
   * @throws ResumeFailedException if the request cannot rebind its transient collaborators and
   *     should therefore fail, resume rather than continue in a partially attached state
   */
  void onResume(FcpRequestRuntimeContext context) throws ResumeFailedException;

  /**
   * Returns the low-level request client associated with the owning request.
   *
   * <p>The bridge forwards this identity into the runtime inserter, so scheduling and persistence
   * continue to attribute work to the same logical FCP client. Implementations should therefore
   * return the stable request-scoped {@link RequestClient}, not an ephemeral wrapper created for a
   * single callback invocation.
   *
   * @return low-level request client for the owning request; callers expect the same logical
   *     identity across the lifetime of a persistent request
   */
  RequestClient getRequestClient();

  /**
   * Writes compact client detail used by persistent request serialization.
   *
   * <p>The runtime requester still persists a higher-level summary of the owning request so it can
   * be reconstructed even when a full Java object graph cannot be trusted. This hook lets the
   * adapter-owned request encode that compact description while the bridge continues to own the
   * live inserter and callback adaptation.
   *
   * @param dos destination stream for the client detail payload; implementations should append only
   *     the request-owned recovery detail and leave stream lifecycle management to the caller
   * @param checker checksum helper used during serialization to protect the emitted recovery data
   * @throws IOException if writing the persistent client detail fails
   */
  void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException;

  /**
   * Reports successful insert completion.
   *
   * <p>This is the terminal success signal for the current insert attempt. The supplied state may
   * expose a final URI fallback when the owning request has not yet cached one, but callers should
   * treat it as a best-effort runtime state rather than a durable object they can retain.
   *
   * @param state minimal bridge-owned state view for the live putter, or {@code null} when the
   *     runtime completed without a state object that can be surfaced through the detached seam
   */
  void onSuccess(FcpInsertCallbackState state);

  /**
   * Reports insert failure.
   *
   * <p>This is the terminal failure signal for the current insert attempt. The exception describes
   * the runtime failure mode, while the optional state can still provide a best-known URI or debug
   * identity that helps the owning request reconcile partially completed work.
   *
   * @param exception failure reported by the runtime insert path; implementations typically convert
   *     it into FCP-facing failure messages or cached status
   * @param state minimal bridge-owned state view for the live putter, or {@code null} when no
   *     detached state snapshot is available
   */
  void onFailure(InsertException exception, FcpInsertCallbackState state);

  /**
   * Reports the final generated URI for the insert.
   *
   * <p>The bridge issues this callback as soon as the runtime can expose the stable final URI for
   * the insert. The owning request can cache the URI immediately and publish it to reconnecting FCP
   * clients even before the overall insert reports terminal success.
   *
   * @param uri generated URI supplied by the runtime insert path; implementations should treat it
   *     as immutable request output
   * @param state minimal bridge-owned state view for the live putter, or {@code null} when only the
   *     generated URI itself is available
   */
  void onGeneratedURI(FreenetURI uri, FcpInsertCallbackState state);

  /**
   * Reports generated metadata produced instead of a final URI.
   *
   * <p>Some insert flows return metadata instead of a final URI, for example, when the metadata
   * falls below the configured threshold. Ownership of the supplied bucket follows the historical
   * runtime callback behavior: the receiver is responsible for deciding whether to retain, forward,
   * or free it.
   *
   * @param metadata metadata bucket produced by the runtime insert path; implementations should
   *     treat it as owned by the callback receiver once delivered
   * @param state minimal bridge-owned state view for the live putter, or {@code null} when no
   *     detached runtime state snapshot accompanies the metadata
   */
  void onGeneratedMetadata(Bucket metadata, FcpInsertCallbackState state);

  /**
   * Reports that the insert has become fetchable before final completion.
   *
   * <p>This is an advisory callback rather than a terminal outcome. It tells the owning request
   * that the runtime considers the inserted content fetchable already, which is useful for
   * progress-oriented FCP messages and status pages that want to surface early availability.
   *
   * @param state minimal bridge-owned state view for the live putter, or {@code null} when the
   *     bridge can report fetchability without an accompanying detached state snapshot
   */
  void onFetchable(FcpInsertCallbackState state);
}
