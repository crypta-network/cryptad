package network.crypta.clients.fcp;

/**
 * Conveys the per-bucket reject counters gathered during a probe run back to an FCP client.
 *
 * <p>This response is emitted immediately after the node finishes measuring how many bulk CHK and
 * SSK operations it denied during a probe sweep. Client tooling consumes the synthetic statistics
 * to judge saturation, detect throttling policies, or surface overload warnings in dashboards.
 * Instances are short-lived and flow from the server to the requesting socket in a single pass; no
 * attempt is made to cache results or reuse the field set across probes. The class keeps the
 * payload intentionally narrow—just four counters—so callers can trivially serialize the data into
 * their own telemetry streams without decoding large objects.
 *
 * <p><strong>Usage considerations:</strong>
 *
 * <ul>
 *   <li>The underlying {@link network.crypta.support.SimpleFieldSet} is mutable until the response
 *       is written, so avoid sharing an instance across threads.
 *   <li>All counters use signed 32-bit integers and therefore reflect the two's-complement view of
 *       the originating bytes; consumers should treat unexpected negative values as protocol data
 *       rather than applying unsigned conversion.
 *   <li>Each {@link ProbeRequest} normally yields at most one {@code ProbeRejectStats} message,
 *       keeping the identifier unique for log correlation.
 * </ul>
 *
 * @see ProbeRequest
 * @see FCPResponse
 */
public class ProbeRejectStats extends FCPResponse {

  /**
   * Builds a response that mirrors four probe reject counters into the FCP field set.
   *
   * <p>The constructor copies the provided bytes directly into integer fields in the inherited
   * {@link network.crypta.support.SimpleFieldSet}, where each position corresponds to a bulk
   * request or insert family for CHK and SSK traffic. Callers must supply an array whose first four
   * elements are meaningful; the method neither clones nor validates the length, so shorter input
   * will surface as an {@link ArrayIndexOutOfBoundsException}. Identifiers are optional, but when
   * provided they allow the client to correlate this response with the originating probe
   * submission.
   *
   * <pre>{@code
   * var stats = collector.recentRejectSnapshot();
   * handler.send(new ProbeRejectStats(request.getIdentifier(), stats));
   * }</pre>
   *
   * @param identifier optional token mirroring the probe request so clients can correlate
   *     asynchronous responses even when multiple probes overlap; {@code null} omits the field.
   * @param stats byte array containing at least four entries in the order CHK request, SSK request,
   *     CHK insert, and SSK insert; data is consumed immediately without copying.
   */
  public ProbeRejectStats(String identifier, byte[] stats) {
    super(identifier);
    fs.put(BULK_CHK_REQUEST_REJECTS, (int) stats[0]);
    fs.put(BULK_SSK_REQUEST_REJECTS, (int) stats[1]);
    fs.put(BULK_CHK_INSERT_REJECTS, (int) stats[2]);
    fs.put(BULK_SSK_INSERT_REJECTS, (int) stats[3]);
  }

  /**
   * Returns the static protocol message identifier recognized by FCP peers.
   *
   * <p>The value never changes between instances because {@code ProbeRejectStats} represents a
   * single, well-defined response type. Downstream encoders rely on this constant to emit the
   * correct message header prior to serializing the {@link network.crypta.support.SimpleFieldSet}.
   * The fixed string also simplifies logging and switch statements that route incoming responses
   * through typed handlers.
   *
   * @return constant {@code "ProbeRejectStats"} for downstream routing and diagnostics.
   */
  @Override
  public String getName() {
    return "ProbeRejectStats";
  }
}
