package network.crypta.client.events;

/**
 * Event handling for clients.
 *
 * @author oskar
 */
public interface ClientEvent {

  /** Returns a string describing the event. */
  String getDescription();

  /** Returns a unique code for this event. */
  int getCode();
}
