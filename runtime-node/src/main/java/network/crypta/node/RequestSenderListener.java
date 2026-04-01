package network.crypta.node;

/**
 * Listener for asynchronous events emitted by {@link RequestSender} during request processing.
 *
 * <p>All callbacks must return quickly. The caller may invoke them on I/O or scheduler threads;
 * offload any blocking or lengthy work to your own threads or an executor to avoid stalling
 * networking and scheduling.
 */
public interface RequestSenderListener {
  /**
   * Notified when a reject-overload condition is received for the request.
   *
   * <p>Return immediately; perform any retry or backoff logic outside of this callback.
   */
  void onReceivedRejectOverload();

  /**
   * Notified when a CHK (content-hash key) transfer for the request begins.
   *
   * <p>Use this to initialize progress tracking or UI hooks. Must return quickly.
   */
  void onCHKTransferBegins();

  /**
   * Notified when the sender finishes processing the request (success, failure, or cancellation).
   *
   * @param status implementation-defined completion status code; see {@link RequestSender}.
   * @param fromOfferedKey indicates how completion was achieved as defined by {@link
   *     RequestSender}. The specific meaning of an "offered key" is implementation-dependent.
   * @param rs the sender instance associated with this callback.
   */
  void onRequestSenderFinished(int status, boolean fromOfferedKey, RequestSender rs);

  /**
   * Called when a request is not started because it was restricted to a local-only lookup and the
   * data was not present in the store.
   *
   * <p>Not invoked by {@link RequestSender}.
   *
   * @param internalError {@code true} if the condition is due to an internal error rather than the
   *     absence of data.
   */
  void onNotStarted(boolean internalError);

  /**
   * Called when the requested data is found locally and no remote request is started.
   *
   * <p>Not invoked by {@link RequestSender}. The pending-key trip (if applicable) has already
   * occurred before this callback.
   */
  void onDataFoundLocally();
}
