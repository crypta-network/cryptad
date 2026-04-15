package network.crypta.clients.fcp;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.support.io.ResumeFailedException;

/**
 * Adapter-owned control surface for one live runtime requester.
 *
 * <p>This interface is the detached requester seam between {@code :adapter-fcp} and the
 * bridge-owned runtime bindings. The FCP adapter still owns a handful of cross-cutting operations
 * that apply to both GET and PUT request lifecycles, such as cancellation, priority changes,
 * diagnostics tagging, persistent-request resume, and orderly shutdown. Rather than exposing the
 * concrete daemon {@code ClientRequester} type directly, the bridge wraps that runtime object in an
 * implementation of this interface and hands the adapter only this narrow control handle.
 *
 * <p>The handle is request-scoped and serializable because persistent FCP requests may retain an
 * execution object across Java serialization and later rebind it to a fresh daemon runtime. The
 * interface therefore avoids broad inspection methods and focuses on the specific operations the
 * adapter still needs to perform during request orchestration. Callers should treat implementations
 * as opaque bridge-owned objects and should not rely on any concrete type, identity, or
 * thread-affinity beyond the declared methods.
 *
 * <ul>
 *   <li>Lets the adapter cancel or reprioritize an in-flight runtime requester.
 *   <li>Preserves resume and shutdown hooks for persistent-request lifecycle management.
 *   <li>Keeps the concrete runtime requester type out of the adapter module's API surface.
 * </ul>
 */
public interface FcpRequesterHandle extends Serializable {

  /** Stable serialization version for bridge-owned requester-handle implementations. */
  @Serial long serialVersionUID = 1L;

  /**
   * Requests cancellation of the underlying runtime work.
   *
   * <p>This is the detached equivalent of invoking cancellation on the runtime requester directly.
   * The supplied {@link ClientContext} provides the live runtime services needed to stop work and
   * release any request-owned state cleanly.
   *
   * @param context live client context used by the runtime requester when performing cancellation
   */
  void cancel(ClientContext context);

  /**
   * Updates the scheduling priority class on the underlying runtime requester.
   *
   * <p>FCP clients can mutate request priority after a request has been accepted. This hook lets
   * the adapter forward that change through the bridge without learning about the concrete runtime
   * requester implementation.
   *
   * @param priorityClass new priority class to apply to the underlying runtime requester
   * @param context live client context used by the runtime requester while applying the new
   *     scheduling priority
   */
  void setPriorityClass(short priorityClass, ClientContext context);

  /**
   * Assigns an external diagnostics identifier to the underlying runtime requester.
   *
   * <p>The adapter uses this for FCP-visible identifiers and logging correlation. Implementations
   * should forward the value directly to the runtime requester and tolerate {@code null} when the
   * caller wants to clear the diagnostic tag.
   *
   * @param externalRequestIdentifier diagnostics identifier, or {@code null} when no external tag
   *     should remain on the runtime requester
   */
  void setExternalRequestIdentifier(String externalRequestIdentifier);

  /**
   * Rebinds transient runtime collaborators after deserialization.
   *
   * <p>Persistent FCP requests may deserialize with an execution object that still needs to
   * reconnect to a fresh daemon runtime. The adapter invokes this hook during request resume so the
   * bridge can reattach any transient runtime collaborators behind the detached requester seam.
   *
   * @param context live client context supplied during persistent-request resume; it carries the
   *     runtime services needed to rebind the underlying requester
   * @throws ResumeFailedException if the runtime requester cannot be reattached safely during
   *     persistent-request resume
   */
  void onResume(ClientContext context) throws ResumeFailedException;

  /**
   * Invokes the runtime requester's shutdown hook.
   *
   * <p>This is used during node or request shutdown flows to give the runtime requester a final
   * chance to flush, detach, or release transient state that depends on the live {@link
   * ClientContext}. Implementations should treat the call as best-effort cleanup rather than as a
   * normal lifecycle transition.
   *
   * @param context live client context supplied during shutdown
   */
  void onShutdown(ClientContext context);
}
