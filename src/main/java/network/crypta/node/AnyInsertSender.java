package network.crypta.node;

public interface AnyInsertSender {

  int getStatus();

  short getHTL();

  /**
   * @return The current status as a string
   */
  String getStatusString();

  boolean sentRequest();

  long getUID();
}
