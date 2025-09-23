package network.crypta.client.events;

import network.crypta.client.async.ClientContext;

/**
 * Event handling for clients.
 *
 * @author oskar
 */
public interface ClientEventListener {

  /**
   * Hears an event.
   *
   * @param ce ClientEvent
   * @param context The database context the event was generated in. NOTE THAT IT MAY NOT HAVE BEEN
   *     GENERATED IN A DATABASE CONTEXT AT ALL: In this case, container will be null, and you
   *     should use context to schedule a DBJob.
   */
  void receive(ClientEvent ce, ClientContext context);
}
