package network.crypta.clients.fcp;

public interface RequestCompletionCallback {

  /** Callback called when a request succeeds. */
  void notifySuccess(ClientRequest req);

  /** Callback called when a request fails */
  void notifyFailure(ClientRequest req);

  /** Callback when a request is removed */
  void onRemove(ClientRequest req);
}
