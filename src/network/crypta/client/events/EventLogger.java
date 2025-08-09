package network.crypta.client.events;

import network.crypta.client.async.ClientContext;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

/**
 * Event handeling for clients.
 *
 * @author oskar
 */
public class EventLogger implements ClientEventListener {

	final LogLevel logPrio;
	final boolean removeWithProducer;
	
	public EventLogger(LogLevel prio, boolean removeWithProducer) {
		logPrio = prio;
		this.removeWithProducer = removeWithProducer;
	}
	
    /**
     * Logs an event
     * 
     * @param ce
     *            The event that occured
     */
	@Override
    public void receive(ClientEvent ce, ClientContext context) {
    	Logger.logStatic(ce, ce.getDescription(), logPrio);
    }
}
