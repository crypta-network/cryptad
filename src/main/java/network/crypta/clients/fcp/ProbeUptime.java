package network.crypta.clients.fcp;

/**
 * Response emitted by the node when an upstream probe collected the remote endpoint's uptime
 * percentage over a configured observation window.
 *
 * <p>{@code ProbeUptime} is a lightweight envelope that rides on the {@link FCPResponse} base
 * class, meaning it carries the caller-provided FCP identifier as well as the probe metric encoded
 * within the shared {@link network.crypta.support.SimpleFieldSet}. External clients typically
 * receive this message shortly after issuing a probe over the Freenet Client Protocol and use it to
 * display availability diagnostics or feed local heuristics that rank potential peers.
 *
 * <p>The message is immutable after construction: callers set the identifier and uptime metric once
 * and then write the response to the socket without subsequent mutation. No synchronization is
 * performed internally because the instances are expected to stay confined to the I/O thread that
 * generated them. The measured uptime is expressed as a percentage, with callers choosing whether a
 * 48-hour or 7-day window best suits their workflow.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> bridge probe results to the wire protocol by storing the
 *       identifier and uptime percentage in a field set.
 *   <li><strong>Usage:</strong> instantiate, optionally inspect {@link #getFieldSet()}, then stream
 *       via {@link #send(java.io.OutputStream)} inherited from {@link FCPMessage}.
 * </ul>
 *
 * @see FCPResponse
 * @see FCPMessage
 */
public class ProbeUptime extends FCPResponse {
  /**
   * Creates a response that reports the measured uptime percentage observed for the previously
   * requested probe.
   *
   * <p>The constructor immediately writes the provided identifier and {@code uptimePercent} into
   * the backing field set so the message can be serialized without additional mutation. Callers may
   * pass {@code null} when the probe was fire-and-forget; in that case the identifier field is
   * omitted, mirroring the behavior defined in {@link FCPResponse}. The {@code uptimePercent}
   * should already be normalized to a 0–100 range and typically represents either a 48-hour or
   * 7-day moving window depending on the upstream measurement request.
   *
   * <pre>{@code
   * var response = new ProbeUptime("probe-123", 99.2d);
   * output.write(response.getFieldSet().toString().getBytes(StandardCharsets.UTF_8));
   * }</pre>
   *
   * @param fcpIdentifier token that pairs this response with a prior request; may be {@code null}
   *     for unsolicited notifications but must otherwise match the caller's identifier verbatim.
   * @param uptimePercent percentage value already expressed as 0–100 using the observation window
   *     negotiated by the probe request; NaN and infinities should be filtered before calling.
   */
  public ProbeUptime(String fcpIdentifier, double uptimePercent) {
    super(fcpIdentifier);
    fs.put(UPTIME_PERCENT, uptimePercent);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The string is constant and can be used for routing or logging comparisons without repeated
   * allocation or synchronization.
   *
   * @return immutable literal {@code "ProbeUptime"} understood by the FCP framing layer.
   */
  public String getName() {
    return "ProbeUptime";
  }
}
