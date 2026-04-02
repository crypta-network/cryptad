package network.crypta.clients.fcp;

/**
 * Node-to-client response that reports the node's current build identifier via the Freenet Client
 * Protocol (FCP).
 *
 * <p>The message is emitted by diagnostic and probing routines whenever a remote endpoint needs to
 * confirm the build or protocol revision that the node is running. It wraps the {@code Build} field
 * inside the {@link #fs} structure inherited from {@link FCPResponse}, so callers can route it
 * through the standard serialization pipeline without custom handling. Consumers typically map the
 * value to UI readouts or compatibility gates before taking further action.
 *
 * <p>The class is intentionally minimal: once instantiated it acts as a read-only container whose
 * lifecycle is confined to the emitting thread. Downstream code should treat instances as
 * short-lived snapshots and avoid retaining references after the field set has been written to the
 * socket. Thread safety follows {@link FCPResponse}: mutation is confined to construction and
 * therefore safe under the single-threaded usage model encouraged by the FCP server.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> capture the caller-supplied identifier and build number,
 *       and present them through {@link #getFieldSet()} for serialization.
 *   <li><strong>Typical flow:</strong> request handler instantiates {@code ProbeBuild}, sends it
 *       via the connection handler, and immediately discards the instance after the writing
 *       completes.
 * </ul>
 *
 * @see FCPResponse
 * @see network.crypta.support.SimpleFieldSet
 */
public class ProbeBuild extends FCPResponse {
  /**
   * Creates a response that echoes the supplied build number and optional identifier back to the
   * client.
   *
   * <p>The constructor stores the identifier directly within the backing {@link
   * network.crypta.support.SimpleFieldSet SimpleFieldSet}, mirroring every other {@link
   * FCPResponse}. When {@code fcpIdentifier} is {@code null} the identifier key is omitted,
   * preserving FCP semantics for broadcast notifications. The {@code build} argument is recorded as
   * a decimal integer so consuming clients can compare it against compatibility thresholds or
   * display it verbatim in monitoring UIs.
   *
   * <pre>{@code
   * // Example: send a probe response after verifying a client session.
   * connection.send(new ProbeBuild("session-42", nodeState.getBuild()));
   * }</pre>
   *
   * @param fcpIdentifier unique token linking this reply to a prior request; may be {@code null}
   *     when the originating probe did not provide correlation metadata.
   * @param build numeric build identifier produced by the node's versioning subsystem; non-negative
   *     values are expected so clients can match release notes.
   */
  public ProbeBuild(String fcpIdentifier, int build) {
    super(fcpIdentifier);
    fs.put(BUILD, build);
  }

  @Override
  public String getName() {
    return "ProbeBuild";
  }
}
