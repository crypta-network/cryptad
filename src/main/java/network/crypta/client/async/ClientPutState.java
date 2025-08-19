package network.crypta.client.async;

import network.crypta.client.InsertException;
import network.crypta.support.io.ResumeFailedException;

/**
 * ClientPutState
 *
 * <p>Represents a state in the insert process.
 */
public interface ClientPutState {

  /** Get the BaseClientPutter responsible for this request state. */
  BaseClientPutter getParent();

  /** Cancel the request. */
  void cancel(ClientContext context);

  /** Schedule the request. */
  void schedule(ClientContext context) throws InsertException;

  /** Get the token, an object which is passed around with the insert and may be used by callers. */
  Object getToken();

  /**
   * Called on restarting the node for a persistent request. The request must re-schedule itself.
   * Caller must ensure that it is safe to call this method more than once, as we recurse through
   * the graph of dependencies.
   *
   * @throws InsertException
   * @throws ResumeFailedException
   */
  void onResume(ClientContext context) throws InsertException, ResumeFailedException;

  /**
   * Called just before the final write of client.dat before the node shuts down. Should write any
   * dirty data to disk etc.
   */
  void onShutdown(ClientContext context);
}
