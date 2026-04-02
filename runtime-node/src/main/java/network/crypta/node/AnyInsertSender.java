package network.crypta.node;

/**
 * Describes a component capable of sending an "insert" request and exposing lightweight status for
 * monitoring and routing.
 *
 * <p>The interface provides accessors for a status code and a human-readable status string, the
 * current HTL (Hops-To-Live) value, whether a request has been dispatched, and an identifier that
 * can be used for correlation across logs or subsystems. See {@link HighHtlAware} for related
 * concepts around high HTL.
 *
 * <p>Thread-safety: Concurrency guarantees are implementation-defined.
 */
public interface AnyInsertSender {

  /**
   * Returns an implementation-defined status code reflecting the sender's current state.
   *
   * <p>Use together with {@link #getStatusString()} for a human-readable description.
   *
   * @return the current status code.
   */
  int getStatus();

  /**
   * Returns the current Hops-To-Live (HTL) value for the associated request.
   *
   * <p>HTL is the hop budget used during routing. Higher values indicate that the request is still
   * near its origin; lower values indicate it has traversed more of the network.
   *
   * @return the current HTL, expressed in hops.
   */
  short getHTL();

  /**
   * Returns a human-readable description of the current status.
   *
   * <p>The returned string should correspond to the code from {@link #getStatus()} and be suitable
   * for logs, metrics, or UI surfaces.
   *
   * @return the current status as text.
   */
  String getStatusString();

  /**
   * Indicates whether an insert request has been dispatched by this sender.
   *
   * <p>This method reports state only; it does not perform any network operation.
   *
   * @return {@code true} if a request has been sent; {@code false} otherwise.
   */
  boolean sentRequest();

  /**
   * Returns an identifier associated with this sender or its request.
   *
   * <p>The identifier is intended for correlation across components. Its uniqueness scope is
   * implementation-defined.
   *
   * @return an identifier suitable for correlation.
   */
  long getUID();
}
