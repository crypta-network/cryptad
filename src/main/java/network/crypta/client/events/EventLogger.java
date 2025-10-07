package network.crypta.client.events;

import network.crypta.client.async.ClientContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Event handeling for clients.
 *
 * @author oskar
 */
public class EventLogger implements ClientEventListener {
  private static final Logger LOG = LoggerFactory.getLogger(EventLogger.class);

  final Level slf4jLevel;
  final boolean removeWithProducer;

  /** New overload that accepts SLF4J level directly (preferred). */
  public EventLogger(Level level, boolean removeWithProducer) {
    this.slf4jLevel = level == null ? Level.INFO : level;
    this.removeWithProducer = removeWithProducer;
  }

  /**
   * Logs an event
   *
   * @param ce The event that occured
   */
  @Override
  public void receive(ClientEvent ce, ClientContext context) {
    switch (slf4jLevel) {
      case ERROR:
        LOG.error("{}", ce.getDescription());
        break;
      case WARN:
        LOG.warn("{}", ce.getDescription());
        break;
      case INFO:
        LOG.info("{}", ce.getDescription());
        break;
      case DEBUG:
        if (LOG.isDebugEnabled()) LOG.debug("{}", ce.getDescription());
        break;
      case TRACE:
      default:
        if (LOG.isTraceEnabled()) LOG.trace("{}", ce.getDescription());
        else if (LOG.isDebugEnabled()) LOG.debug("{}", ce.getDescription());
        else LOG.info("{}", ce.getDescription());
    }
  }

  // No legacy Logger.LogLevel constructor; SLF4J Level is used directly.
}
