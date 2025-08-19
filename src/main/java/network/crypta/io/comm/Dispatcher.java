package network.crypta.io.comm;

public interface Dispatcher {

  /**
   * Handle a message.
   *
   * @param m
   * @return false if we did not handle the message and want it to be passed on to the next filter.
   */
  boolean handleMessage(Message m);
}
