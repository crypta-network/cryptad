package network.crypta.client.events;

import java.io.IOException;
import java.io.Writer;
import network.crypta.client.async.ClientContext;

public class EventDumper implements ClientEventListener {

  final Writer w;
  final boolean removeWithProducer;

  public EventDumper(Writer writer, boolean removeWithProducer) {
    this.w = writer;
    this.removeWithProducer = removeWithProducer;
  }

  @Override
  public void receive(ClientEvent ce, ClientContext context) {
    try {
      w.write(ce.getDescription() + "\n");
    } catch (IOException e) {
      // Ignore.
    }
  }
}
