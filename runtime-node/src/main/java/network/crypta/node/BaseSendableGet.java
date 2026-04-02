package network.crypta.node;

import java.io.Serial;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.Key;

/**
 * Abstract base for "get" requests that can be scheduled and sent by the client.
 *
 * <p>Instances participate in the client request scheduling flow via {@link SendableRequest}. Some
 * subclasses may be persisted; when persistence applies, changing non-transient fields can
 * invalidate on-disk state and cause downloads to restart or uploads to be lost.
 *
 * <p>This type defines the minimal contract common to get-style requests: mapping a scheduler token
 * to a {@link network.crypta.keys.Key} and an optional pre-registration hook that may cancel
 * sending or emit side effects before network transmission.
 *
 * @author toad
 */
public abstract class BaseSendableGet extends SendableRequest {

  @Serial private static final long serialVersionUID = 1L;

  protected BaseSendableGet(boolean persistent, boolean realTimeFlag) {
    super(persistent, realTimeFlag);
  }

  /**
   * Returns the key associated with the provided scheduler token.
   *
   * <p>The token is typically obtained from {@link SendableRequest#chooseKey} and identifies a
   * specific unit of work. Implementations should provide a stable mapping for the lifetime of the
   * token.
   *
   * @param token scheduler token identifying the item to fetch
   * @return the key to request from the network
   */
  public abstract Key getNodeKey(SendableRequestItem token);

  /**
   * Hook invoked after local datastore checks and before registering the request for sending.
   *
   * <p>Implementations may cancel further processing or emit side effects (for example, notifying
   * client listeners) prior to network transmission.
   *
   * @param context client execution context
   * @param toNetwork {@code true} when the scheduler intends to send network requests (unless this
   *     method cancels); {@code false} when the assigned work has completed locally
   * @return {@code true} to cancel at this stage and not go to the network; in that case the
   *     implementation must handle the failure/notification itself
   */
  public abstract boolean preRegister(ClientContext context, boolean toNetwork);
}
