package network.crypta.clients.fcp;

/**
 * Conveys the node's most recent understanding of the client's permissible outbound bandwidth as a
 * lightweight FCP response.
 *
 * <p>{@code ProbeBandwidth} is emitted whenever the node probes the remote peer and receives a
 * definitive limit for outbound transfer capacity expressed in kibibytes per second. The class is
 * intentionally tiny—essentially a thin wrapper around {@link FCPResponse}—so it can be created in
 * latency-sensitive paths immediately before serialization. Instances are ephemeral, short-lived
 * holders for fields written directly to the {@link network.crypta.support.SimpleFieldSet}
 * inherited from the superclass.
 *
 * <p>Consumers typically construct the response, write both the identifier and the reported value,
 * and immediately stream the resulting payload to the connected client. Because the object lives on
 * a single thread for just long enough to reach the socket, it performs no defensive copies and
 * should not be reused beyond the originating write. While the type itself is immutable from an API
 * standpoint, the underlying field set remains mutable until the caller finishes populating it;
 * additional keys may be appended if future protocol revisions demand more context.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> capture the FCP identifier, expose the measured outbound
 *       bandwidth, and advertise the well-known message name.
 *   <li><strong>Thread-safety:</strong> callers must confine each instance to a single thread and
 *       serialize the response immediately after construction.
 * </ul>
 *
 * @see FCPResponse
 */
public class ProbeBandwidth extends FCPResponse {
  /**
   * Creates a response that embeds the supplied identifier and the probed outbound bandwidth
   * constraint, leaving the rest of the field set available for subsequent protocol extensions.
   *
   * <p>The constructor eagerly stores the identifier using {@link FCPResponse}'s semantics (null
   * identifiers are omitted) and records the bandwidth as a floating-point number in kibibytes per
   * second. Callers are expected to allocate and send the message immediately after construction to
   * avoid mutating the backing {@link network.crypta.support.SimpleFieldSet} from multiple threads.
   * Typical usage is restricted to node internals that monitor endpoint throttling behavior.
   *
   * <pre>{@code
   * ProbeBandwidth payload = new ProbeBandwidth(requestId, measuredLimitKib);
   * connection.write(payload.getName(), payload.getFieldSet());
   * }</pre>
   *
   * @param fcpIdentifier String token used to correlate this response with the originating probe;
   *     may be {@code null} for fire-and-forget events.
   * @param outputBandwidth Upper bound reported by the client in kibibytes per second; must be a
   *     finite {@code float} representing the instantaneous rate limit.
   */
  public ProbeBandwidth(String fcpIdentifier, float outputBandwidth) {
    super(fcpIdentifier);
    fs.put(OUTPUT_BANDWIDTH, outputBandwidth);
  }

  @Override
  public String getName() {
    return "ProbeBandwidth";
  }
}
