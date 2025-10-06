package network.crypta.client.events;

import network.crypta.client.async.ClientContext;
import network.crypta.support.Logger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Event handeling for clients.
 *
 * @author oskar
 */
public class EventLogger implements ClientEventListener {
  private static final Logger LOG = LoggerFactory.getLogger(EventLogger.class);

  final LogLevel logPrio;
  final boolean removeWithProducer;

  public EventLogger(LogLevel prio, boolean removeWithProducer) {
    logPrio = prio;
    this.removeWithProducer = removeWithProducer;
  }

  /**
   * Logs an event
   *
   * @param ce The event that occured
   */
  @Override
  public void receive(ClientEvent ce, ClientContext context) {
    // Map legacy Logger.LogLevel to SLF4J levels
    switch (logPrio) {
      case MINOR:
      case DEBUG:
        if (LOG.isDebugEnabled()) LOG.debug("{}", ce.getDescription());
        break;
      case NORMAL:
        LOG.info("{}", ce.getDescription());
        break;
      case WARNING:
        LOG.warn("{}", ce.getDescription());
        break;
      case ERROR:
        LOG.error("{}", ce.getDescription());
        break;
      default:
        LOG.info("{}", ce.getDescription());
    }
  }
}
