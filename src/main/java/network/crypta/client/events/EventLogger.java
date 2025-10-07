package network.crypta.client.events;

import network.crypta.client.async.ClientContext;
import network.crypta.support.Logger.LogLevel;
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

  public EventLogger(LogLevel prio, boolean removeWithProducer) {
    this.slf4jLevel = mapLegacy(prio);
    this.removeWithProducer = removeWithProducer;
  }

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

  private static Level mapLegacy(LogLevel prio) {
    if (prio == null) return Level.INFO;
    switch (prio) {
      case ERROR:
        return Level.ERROR;
      case WARNING:
        return Level.WARN;
      case NORMAL:
        return Level.INFO;
      case MINOR:
      case DEBUG:
        return Level.DEBUG;
      case MINIMAL:
        return Level.TRACE;
      case NONE:
      default:
        return Level.INFO;
    }
  }
}
