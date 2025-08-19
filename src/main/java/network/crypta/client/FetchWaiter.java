package network.crypta.client;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.node.RequestClient;

/**
 * Provides a blocking wrapper for a fetch. Used for simple blocking APIs such as
 * HighLevelSimpleClient.
 */
public class FetchWaiter implements ClientGetCallback {

  private FetchResult result;
  private FetchException error;
  private boolean finished;
  private final RequestClient client;

  public FetchWaiter(RequestClient client) {
    this.client = client;
  }

  @Override
  public synchronized void onSuccess(FetchResult result, ClientGetter state) {
    if (finished) return;
    this.result = result;
    finished = true;
    notifyAll();
  }

  @Override
  public synchronized void onFailure(FetchException e, ClientGetter state) {
    if (finished) return;
    this.error = e;
    finished = true;
    notifyAll();
  }

  /** Wait for the request to complete, return the results, throw if it failed. */
  public synchronized FetchResult waitForCompletion() throws FetchException {
    while (!finished) {
      try {
        wait();
      } catch (InterruptedException e) {
        // Ignore
      }
    }

    if (error != null) throw error;
    return result;
  }

  @Override
  public void onResume(ClientContext context) {
    throw new UnsupportedOperationException();
    // Not persistent.
  }

  @Override
  public RequestClient getRequestClient() {
    return client;
  }
}
