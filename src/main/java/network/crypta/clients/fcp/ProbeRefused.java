package network.crypta.clients.fcp;

/**
 * FCP response emitted when a probed endpoint explicitly declines to answer the request.
 *
 * <p>This message represents a deliberate refusal by the target node to service the probe, which
 * prevents clients from confusing silent drops with intentional policy decisions. Typical producers
 * are routing layers that keep statistics about how peers handle anonymous probes. Clients receive
 * the message asynchronously and should treat it as definitive feedback that the specific probe
 * will not progress further in the network. Because the class inherits the mutable {@link
 * FCPResponse#fs} field set, callers may enrich the payload after construction, but instances are
 * expected to remain request-scoped and single-threaded just like other responses.
 *
 * <p>The type is lightweight and intentionally immutable after population apart from the exposed
 * field set. It does not perform retries or automatic requeueing; higher layers decide whether to
 * issue follow-up probes. No synchronization is provided, so writers should avoid cross-thread
 * sharing unless guarded externally.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> label the refusal event and propagate the FCP
 *       identifier, enabling clients to reconcile probes with outcomes.
 *   <li><strong>Notable behavior:</strong> {@link
 *       FCPResponse#run(network.crypta.clients.fcp.FCPConnectionHandler)} remains the inherited
 *       guard that always raises {@link MessageInvalidException} if a client attempts to send this
 *       response upstream.
 * </ul>
 *
 * @see FCPResponse
 * @see FCPMessage
 */
public class ProbeRefused extends FCPResponse {

  /**
   * Creates a refusal response bound to the supplied FCP identifier.
   *
   * <p>The constructor immediately allocates the underlying {@link
   * network.crypta.support.SimpleFieldSet} via the {@link FCPResponse} superclass and stores the
   * identifier verbatim, allowing downstream code to add probe-specific metadata before
   * serialization. Passing {@code null} creates a refusal that cannot be correlated to a
   * client-supplied token, which can be useful for legacy fire-and-forget probes yet requires the
   * receiver to inspect contextual routing details to determine origin. No validation is performed
   * here; invariants—including identifier uniqueness—are enforced elsewhere in the probing
   * subsystem.
   *
   * <pre>{@code
   * // Example: propagate a refusal when a peer policy blocks the probe
   * var response = new ProbeRefused(identifier);
   * connection.send(response);
   * }</pre>
   *
   * @param fcpIdentifier identifier that the client attached to the probe; {@code null} omits the
   *     {@code Identifier} field entirely, mirroring legacy protocol semantics.
   */
  public ProbeRefused(String fcpIdentifier) {
    super(fcpIdentifier);
  }

  /**
   * Returns the protocol-level name announcing this refusal response to clients.
   *
   * <p>The method always returns the literal {@code "ProbeRefused"} string so that routing tables,
   * loggers, and serialization helpers can rely on a stable identifier. Implementations
   * intentionally avoid dynamic computation, ensuring minimal overhead during message emission and
   * preventing mismatches with the canonical wire format.
   *
   * @return constant {@code "ProbeRefused"} so receivers can differentiate refusals from other
   *     probe outcomes without additional metadata lookups.
   */
  @Override
  public String getName() {
    return "ProbeRefused";
  }
}
