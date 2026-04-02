package network.crypta.clients.fcp;

/**
 * Reports the outcome of an identifier probe, pairing a remote endpoint token with recent uptime
 * statistics for consumption by FCP clients.
 *
 * <p>{@code ProbeIdentifier} travels from the node to the client whenever the node refreshes its
 * knowledge of a peer's identifier and rolling availability. The class is intentionally lightweight
 * so request handlers can instantiate it inline, populate two numeric fields, and serialize it to
 * the connected socket without extra buffering or defensive copies. Callers typically build an
 * instance immediately before streaming and then discard it, mirroring the short-lived lifecycle of
 * other {@link FCPResponse}-derived payloads.
 *
 * <p>Although the accessor state is immutable, the underlying {@link
 * network.crypta.support.SimpleFieldSet} inherited from the superclass remains mutable until the
 * response is fully assembled. Authors may attach additional keys before emitting the message if
 * future protocol revisions require more context, but the instance must not be shared across
 * threads. Once written to the network, the object should be considered spent and left for garbage
 * collection.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> capture the identifier token, record the rolling uptime
 *       percentage, and surface the canonical message name.
 *   <li><strong>Thread-safety:</strong> callers must keep each instance private to the constructing
 *       thread until serialization completes.
 * </ul>
 *
 * @see FCPResponse
 */
public class ProbeIdentifier extends FCPResponse {
  /**
   * Creates a response that carries the provided identifier token alongside the measured uptime
   * percentage gathered during the most recent probe cycle.
   *
   * <p>The constructor applies the standard {@link FCPResponse} identifier semantics (null values
   * omit the {@code Identifier} key) and records both numeric metrics as decimal strings to
   * preserve wire compatibility. Callers should perform any validation before invoking this
   * constructor; the type assumes the supplied values already reflect sanitized probe output.
   * Typical usage is to instantiate the message, stream it immediately to the client, and then drop
   * the reference.
   *
   * <pre>{@code
   * ProbeIdentifier payload = new ProbeIdentifier(reqId, endpointId, uptimeRollingPercent);
   * connection.write(payload.getName(), payload.getFieldSet());
   * }</pre>
   *
   * @param fcpIdentifier Optional correlation token supplied by the probing request; pass {@code
   *     null} when broadcasting unsolicited updates.
   * @param probeIdentifier Stable endpoint identifier returned by the probe routine, typically a
   *     node-generated numeric handle.
   * @param uptimePercentage Rolling seven-day uptime reported in hundredths of a percent (e.g.,
   *     {@code 9950} equals 99.50%).
   */
  public ProbeIdentifier(String fcpIdentifier, long probeIdentifier, long uptimePercentage) {
    super(fcpIdentifier);
    fs.put(PROBE_IDENTIFIER, probeIdentifier);
    fs.put(UPTIME_PERCENT, uptimePercentage);
  }

  @Override
  public String getName() {
    return "ProbeIdentifier";
  }
}
