package network.crypta.clients.fcp;

/**
 * Response envelope that streams the link-length vector produced by a probe back to an FCP client.
 *
 * <p>The node emits this message whenever an administrative or diagnostic client asks for insight
 * into its routing topology. Each instance captures a snapshot of the most recent probe run by
 * copying the floating-point samples into the inherited field set obtained through {@link
 * FCPResponse#getFieldSet()} so the response can be serialized to the socket without extra
 * buffering. The class itself remains deliberately thin: it carries no parsing or business logic
 * because the node already normalized the values before instantiation, allowing the transport layer
 * to forward the distribution as-is.
 *
 * <p>The object is short-lived and not thread-safe; callers should create it, populate the outbound
 * stream, and drop the reference. Subsequent mutations to the provided array are not reflected, so
 * producers should prepare a finalized slice beforehand. Clients typically receive the message in
 * asynchronous status feeds and render the provided floats as length histograms or path statistics.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> bridge node metrics to FCP wire encoding, associate the
 *       payload with an optional identifier, and advertise a stable name for logging/routing.
 *   <li><strong>Notable behavior:</strong> refuses inbound execution via {@link #run} because it is
 *       a node-to-client response only.
 * </ul>
 *
 * @see FCPResponse
 * @see FCPMessage#LINK_LENGTHS
 */
public class ProbeLinkLengths extends FCPResponse {

  /**
   * Builds a response that carries the supplied link-length distribution values.
   *
   * <p>The constructor records the identifier, when present, and writes the raw floating-point
   * samples into the {@link network.crypta.support.SimpleFieldSet} inherited from {@link
   * FCPResponse}. The array reference itself is not retained afterward; values are copied as
   * delimited strings suitable for FCP transmission. Callers should supply a finalized snapshot
   * because any later modifications to the passed array do not flow back into the response.
   *
   * @param fcpIdentifier optional identifier correlating the probe reply to a preceding client
   *     request; pass {@code null} when no correlation is needed or when broadcasting events.
   * @param linkLengths ordered, non-null list of link-length samples (typically normalized floats)
   *     that the node wants to expose; empty arrays result in the field being omitted entirely.
   */
  public ProbeLinkLengths(String fcpIdentifier, float[] linkLengths) {
    super(fcpIdentifier);
    fs.put(LINK_LENGTHS, linkLengths);
  }

  /**
   * Reports the symbolic response name that appears on the FCP wire.
   *
   * <p>The method always returns the literal {@code "ProbeLinkLengths"} so that downstream routing,
   * logging, and client code can rely on a stable discriminator. Because the response is produced
   * exclusively by the node, the name never varies with runtime state or identifier values.
   *
   * @return constant literal identifying this response type throughout the FCP implementation.
   */
  @Override
  public String getName() {
    return "ProbeLinkLengths";
  }
}
