package network.crypta.clients.fcp;

import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;

/** Creates {@link ClientPutter} instances for single-file inserts. */
final class ClientPutPutterFactory {
  private ClientPutPutterFactory() {}

  static ClientPutter create(ClientPutterRequest request, ClientPutterOptions options) {
    return new ClientPutter(request, options);
  }
}
