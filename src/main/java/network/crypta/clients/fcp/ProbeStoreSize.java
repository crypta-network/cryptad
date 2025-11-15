package network.crypta.clients.fcp;

/**
 * Node-originated response conveying the datastore size measured for a remote endpoint.
 *
 * <p>{@code ProbeStoreSize} is emitted after a probe handler samples the remote node and applies
 * the randomized Gaussian noise mandated by the Freenet/Crypta protocol to avoid leaking exact
 * capacity information. Client applications typically instantiate {@link ProbeRequest} messages and
 * then listen for this response to display approximate datastore recommendations, tune caching
 * thresholds, or log long-term sizing trends. Instances are inherently short-lived: the node
 * constructs the response, serializes its {@link network.crypta.support.SimpleFieldSet}, and
 * immediately discards it once the bytes are flushed to the FCP socket.
 *
 * <p>The response body remains immutable after construction—callers should treat the contained
 * field set as write-once by the server side and read-only for receivers. No synchronization is
 * provided, so concurrent threads must guard access externally if they reuse the same instance for
 * any reason. Protocol semantics guarantee that one response instance mirrors exactly one probe.
 *
 * <ul>
 *   <li><strong>Primary responsibility:</strong> publish the noisy datastore size via {@code
 *       StoreSize} alongside the user-supplied identifier.
 *   <li><strong>Notable behavior:</strong> omits {@code Identifier} entirely when the sender passes
 *       {@code null}, honoring legacy fire-and-forget consumers.
 *   <li><strong>Related types:</strong> {@link ProbeRequest} initiates the exchange, while other
 *       responses such as {@link ProbeBuild} expose complementary probe statistics.
 * </ul>
 */
public class ProbeStoreSize extends FCPResponse {
  /**
   * Creates a response that reports the noisy datastore size observed for the associated probe.
   *
   * <p>The constructor immediately records the identifier (when non-null) and the supplied size
   * inside the backing {@link network.crypta.support.SimpleFieldSet}. The {@code storeSize}
   * argument should already include any masking noise or normalization performed by the node's
   * metrics layer. Instances are ready for serialization as soon as construction finishes and are
   * safe to pass directly to the FCP writer without further mutation.
   *
   * @param fcpIdentifier FCP-level correlation token supplied by the client; {@code null} omits the
   *     {@code Identifier} key entirely for broadcast-style probes.
   * @param storeSize Endpoint datastore size in GiB as a floating-point number that already
   *     includes protocol-mandated Gaussian noise and any rounding applied by the caller.
   */
  public ProbeStoreSize(String fcpIdentifier, float storeSize) {
    super(fcpIdentifier);
    fs.put(STORE_SIZE, storeSize);
  }

  /**
   * Reports the stable message name used on the FCP wire protocol for this response.
   *
   * <p>The value never changes at runtime and enables downstream code to match the serialized
   * header emitted by {@link #getFieldSet()} with handler registrations. Overriding this method is
   * required by {@link FCPResponse}; this implementation always returns the literal {@code
   * "ProbeStoreSize"} defined by the FCP specification.
   *
   * @return Constant string {@code "ProbeStoreSize"} understood by clients and logging systems.
   */
  @Override
  public String getName() {
    return "ProbeStoreSize";
  }
}
