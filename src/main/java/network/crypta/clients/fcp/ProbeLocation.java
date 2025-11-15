package network.crypta.clients.fcp;

/**
 * FCP response conveying the routing-location measurement observed by a client endpoint.
 *
 * <p>This message is emitted by the node whenever it needs to inform an FCP client about the
 * current estimated location of a remote endpoint, typically after a probe that measures network
 * coordinates finishes. Instances encapsulate the identifier supplied by the client so observers
 * can correlate asynchronous replies with their originating probe requests. The underlying {@link
 * network.crypta.support.SimpleFieldSet} is intentionally mutable in {@link FCPResponse}, but
 * callers treat {@code ProbeLocation} as write-once: populate it immediately and hand it off to the
 * connection layer. Because the message simply mirrors measurements with no cached state, it is
 * safe to create anew for each outbound notification and to drop once serialized.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> bridge between internal probe metrics and the wire-level
 *       {@code Location} field, and preserve request identifiers for bookkeeping.
 *   <li><strong>Thread-safety:</strong> not synchronized; build and serialize on one thread only to
 *       avoid field-set races.
 * </ul>
 *
 * @see ProbeRequest
 * @see FCPResponse
 */
public class ProbeLocation extends FCPResponse {

  /**
   * Creates a response wrapper containing an optional identifier and a concrete location value.
   *
   * <p>The constructor immediately stores both fields inside the backing {@link
   * network.crypta.support.SimpleFieldSet} so downstream serialization can stream the response
   * without further mutation. Passing a {@code null} identifier mirrors legacy FCP behavior where
   * best-effort notifications do not always include correlation tokens, while the {@code location}
   * argument is encoded verbatim using {@link Double#toString(double)}. Callers should avoid
   * reusing the same instance across probe events because the class performs no defensive copying
   * or thread coordination.
   *
   * <pre>{@code
   * // Example: wrap a freshly computed endpoint location
   * var response = new ProbeLocation(requestId, endpointLocation);
   * handler.send(response);
   * }</pre>
   *
   * @param fcpIdentifier identifier string supplied by the requesting client; {@code null} omits
   *     the {@code Identifier} field when the probe is fire-and-forget.
   * @param location normalized routing-location value, typically a double between 0.0 and 1.0 as
   *     reported by the probing logic.
   */
  public ProbeLocation(String fcpIdentifier, double location) {
    super(fcpIdentifier);
    fs.put(LOCATION, location);
  }

  /**
   * Returns the static protocol label used to announce this response on the wire.
   *
   * <p>The method always yields {@code "ProbeLocation"}, enabling downstream code to perform type
   * comparisons or log statements without inspecting field-set contents. Because the value is
   * constant, the call is side effect free and safe to repeat whenever diagnostics require the
   * human-readable name.
   *
   * @return immutable {@code String} literal {@code "ProbeLocation"} representing this response
   *     family within FCP traffic.
   */
  @Override
  public String getName() {
    return "ProbeLocation";
  }
}
