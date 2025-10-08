package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Message that disconnects a client.
 *
 * @author <a href="mailto:bombe@freenetproject.org">David ‘Bombe’ Roden</a>
 */
public class DisconnectMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(DisconnectMessage.class);

  /** The name of this message. */
  public static final String NAME = "Disconnect";

  /**
   * Creates a new disconnect message.
   *
   * @param simpleFieldSet The field set to create the message from
   */
  public DisconnectMessage(SimpleFieldSet simpleFieldSet) {
    /* do nothing. */
  }

  /**
   * {@inheritDoc}
   *
   * @see FCPMessage#getFieldSet()
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * {@inheritDoc}
   *
   * @see FCPMessage#getName()
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * {@inheritDoc}
   *
   * @see FCPMessage#run(FCPConnectionHandler, Node)
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    handler.close();
  }
}
