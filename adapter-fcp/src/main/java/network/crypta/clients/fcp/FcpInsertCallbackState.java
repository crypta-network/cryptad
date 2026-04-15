package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;

/**
 * Minimal adapter-owned view of the live insert state that goes with callback events.
 *
 * <p>The bridge uses this interface to expose only the tiny subset of runtime putter state that the
 * adapter still needs after requester and callback detachment. Today that subset is intentionally
 * small: the owning request may need a best-known URI fallback before it has cached one locally,
 * and it may want the wrapped object's diagnostic {@link Object#toString()} representation for
 * logs. Everything else about the live runtime putter stays hidden behind the bridge boundary.
 *
 * <p>Implementations should treat this view as ephemeral and observational. Callers should not
 * cache it as a durable request state, assume it exposes a stable concrete type, or attempt to
 * mutate the underlying runtime insert machinery through it.
 *
 * <ul>
 *   <li>Supplies the current URI fallback visible from the live runtime putter.
 *   <li>Leaves debug rendering to the implementation's own {@code toString()}.
 *   <li>Intentionally omits a broader runtime state to keep the adapter/runtime seam narrow.
 * </ul>
 */
public interface FcpInsertCallbackState {

  /**
   * Returns the best-known URI currently exposed by the live insert state.
   *
   * <p>This is primarily a fallback for request objects that need to publish a URI during success
   * handling before their own cached generated URI has been populated. The value is advisory and
   * may still be {@code null} when the runtime has not yet produced a stable URI.
   *
   * @return current URI, or {@code null} when the live insert state does not yet expose one
   */
  FreenetURI getURI();
}
