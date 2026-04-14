package network.crypta.clients.fcp;

import java.io.Serializable;

/**
 * Opaque adapter-owned handle for one live USK subscription.
 *
 * <p>The adapter stores this handle as the minimal representation of an active runtime-backed USK
 * subscription. The concrete subscription wiring remains in {@code :bridge-fcp-runtime}; the
 * adapter uses the handle only to end that live subscription when the client disconnects,
 * unsubscribes, or otherwise stops caring about updates.
 *
 * <p>Implementations are expected to be idempotent with respect to unsubscription. Callers should
 * not assume anything about the underlying runtime callback object or USK manager token beyond the
 * fact that invoking {@link #unsubscribe()} severs the live subscription.
 */
public interface UskSubscriptionHandle extends Serializable {

  /**
   * Unsubscribes the live USK callback from the runtime manager.
   *
   * <p>This releases the concrete runtime-owned subscription that the bridge created on behalf of
   * the FCP adapter. After this call returns, the owning client should no longer receive USK update
   * callbacks for the associated subscription.
   */
  void unsubscribe();
}
