package network.crypta.io.comm;

/**
 * Callback for handling unmatched messages.
 *
 * <p>The messaging core invokes this interface when an incoming {@link Message} did not match any
 * registered {@link MessageFilter}. Implementations may inspect the message and either consume it
 * (returning {@code true}) or decline it (returning {@code false}). When {@code false} is returned,
 * the message is treated as unhandled and may be retained for later matching according to the
 * policy in {@link MessageCore}.
 *
 * <p>Threading: {@link MessageCore} may call this method from an I/O or worker thread. Implementers
 * should avoid long blocking operations and offload heavy work to executors as appropriate.
 */
public interface Dispatcher {

  /**
   * Attempts to handle a message that no filter claimed.
   *
   * @param m the message to process; never {@code null}.
   * @return {@code true} if the message is fully handled and requires no further processing; {@code
   *     false} to leave it unhandled so the core can apply its unmatched-message policy.
   */
  boolean handleMessage(Message m);
}
