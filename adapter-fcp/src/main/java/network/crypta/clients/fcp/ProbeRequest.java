package network.crypta.clients.fcp;

import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents an inbound FCP request that initiates a network probe and delivers results back to the
 * client.
 *
 * <p>This message is created from a parsed {@link SimpleFieldSet} and validates the probe type and
 * optional hop budget before execution. Callers typically get it through the FCP dispatch layer and
 * then invoke {@link #run(FCPConnectionHandler)} to start the probe asynchronously. The request
 * retains the identifier, type, and hop budget as an immutable state; it is not intended to be
 * reused across unrelated client sessions. A {@code null} identifier is supported and results in
 * response messages that omit the {@code Identifier} field.
 *
 * <p>Execution requires full-access credentials. When authorized, {@link
 * #run(FCPConnectionHandler)} constructs a {@link FcpProbeListener} that adapts probe callbacks
 * into concrete {@link FCPMessage} responses, gets a secure probe UID from the handler's server
 * runtime, and delegates to the message-runtime seam. The method does not block for completion;
 * responses arrive asynchronously via the handler.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> validate fields, enforce access, and bridge callbacks.
 *   <li><strong>Notable behaviors:</strong> defaults {@code HopsToLive} to {@link
 *       FcpProbeDefaults#MAX_HTL} and rejects negative values.
 *   <li><strong>Thread-safety:</strong> immutable after construction; no internal synchronization.
 * </ul>
 *
 * @see FcpProbeType
 * @see FcpProbeListener
 * @see FCPConnectionHandler
 */
public final class ProbeRequest extends FCPMessage {

  /**
   * Wire-level message name used for serialization and protocol dispatch.
   *
   * <p>The value is a stable, human-readable token that must stay consistent with the FCP protocol
   * identifier clients send on the wire. Keeping it constant preserves interoperability and ensures
   * the {@link FCPMessage} factory can resolve this request type reliably.
   */
  public static final String NAME = "ProbeRequest";

  private final String requestIdentifier;
  private final FcpProbeType probeType;
  private final byte hopsToLive;

  /**
   * Parses a probe request from the provided field set and validates required fields.
   *
   * <p>The constructor reads the optional {@code Identifier}, the mandatory {@code Type}, and an
   * optional {@code HopsToLive} value. When the hop budget is missing, it defaults to {@link
   * FcpProbeDefaults#MAX_HTL}; negative values are rejected. Any parsing or validation failure
   * results in a {@link MessageInvalidException} with {@link ProtocolErrorMessage#INVALID_MESSAGE},
   * which the caller should translate into an FCP protocol error response.
   *
   * <pre>{@code
   * SimpleFieldSet fields = ...;
   * ProbeRequest request = new ProbeRequest(fields);
   * }</pre>
   *
   * @param fs parsed field set containing Identifier, Type, and optional HopsToLive.
   * @throws MessageInvalidException if the type is invalid or hopsToLive cannot be parsed.
   */
  public ProbeRequest(SimpleFieldSet fs) throws MessageInvalidException {
    /* If not defined in the field set, Identifier will be null. As adding a null value to the field set does
     * not add something under the key, it will also be omitted in the response messages.
     */
    this.requestIdentifier = fs.get(IDENTIFIER);

    try {
      this.probeType = FcpProbeType.fromFieldValue(fs.get(TYPE));

      // If HTL is not specified default to MAX_HTL.
      this.hopsToLive = fs.get(HTL) == null ? FcpProbeDefaults.MAX_HTL : fs.getByte(HTL);

      if (this.hopsToLive < 0) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_MESSAGE, "hopsToLive cannot be negative.", null, false);
      }

    } catch (IllegalArgumentException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_MESSAGE,
          "Unrecognized parse probe type \"" + fs.get(TYPE) + "\": " + e,
          null,
          false);
    } catch (FSParseException e) {
      // Getting a String from a SimpleFieldSet does not throw - it can, at worst, return null.
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_MESSAGE,
          "Unable to parse hopsToLive \"" + fs.get(HTL) + "\": " + e,
          null,
          false);
    }
  }

  /**
   * Returns an empty field set for outbound serialization of this request.
   *
   * <p>Probe requests are primarily consumed inbound, and this implementation does not serialize
   * the parsed fields back onto the wire. Each invocation allocates a new {@link SimpleFieldSet}
   * marked short-lived, leaving the caller free to mutate it if required by higher-level framing.
   * The returned instance intentionally omits the identifier, type, and hop budget captured at
   * construction time.
   *
   * @return new empty, mutable field set owned by the caller.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Returns the protocol name token that identifies this request on the wire.
   *
   * <p>The name is constant and matches the identifier expected by FCP clients. It is used when
   * serializing outbound messages and when routing inbound messages to this implementation. The
   * method is side-effect-free and performs no allocation beyond returning the constant string.
   *
   * @return stable protocol name token, never null, matching {@link #NAME}.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Starts the probe execution and forwards results to the provided handler.
   *
   * <p>The handler must have full access; otherwise a {@link MessageInvalidException} with {@link
   * ProtocolErrorMessage#ACCESS_DENIED} is thrown and no probe is started. When authorized, this
   * method builds a {@link FcpProbeListener} that maps each callback to the corresponding {@link
   * FCPResponse} message and then delegates to the message-runtime seam using the stored hop budget
   * and a fresh secure random UID from the server runtime. The call is non-blocking and returns
   * immediately while responses are emitted asynchronously via {@link
   * FCPConnectionHandler#send(FCPMessage)}.
   *
   * @param handler connection handler used to authorize and send probe responses.
   * @throws MessageInvalidException if the caller lacks full access for probe execution.
   */
  @Override
  public void run(final FCPConnectionHandler handler) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "Probe requires full access.",
          requestIdentifier,
          false);
    }

    FcpProbeListener listener =
        new FcpProbeListener() {
          @Override
          public void onError(FcpProbeError error, Byte code, boolean local) {
            handler.send(new ProbeError(requestIdentifier, error, code, local));
          }

          @Override
          public void onRefused() {
            handler.send(new ProbeRefused(requestIdentifier));
          }

          @Override
          public void onOutputBandwidth(float outputBandwidth) {
            handler.send(new ProbeBandwidth(requestIdentifier, outputBandwidth));
          }

          @Override
          public void onBuild(int build) {
            handler.send(new ProbeBuild(requestIdentifier, build));
          }

          @Override
          public void onIdentifier(long probeIdentifier, byte percentageUptime) {
            handler.send(new ProbeIdentifier(requestIdentifier, probeIdentifier, percentageUptime));
          }

          @Override
          public void onLinkLengths(float[] linkLengths) {
            handler.send(new ProbeLinkLengths(requestIdentifier, linkLengths));
          }

          @Override
          public void onLocation(float location) {
            handler.send(new ProbeLocation(requestIdentifier, location));
          }

          @Override
          public void onStoreSize(float storeSize) {
            handler.send(new ProbeStoreSize(requestIdentifier, storeSize));
          }

          @Override
          public void onUptime(float uptimePercent) {
            handler.send(new ProbeUptime(requestIdentifier, uptimePercent));
          }

          @Override
          public void onRejectStats(byte[] stats) {
            handler.send(new ProbeRejectStats(requestIdentifier, stats));
          }

          @Override
          public void onOverallBulkOutputCapacity(
              byte bandwidthClassForCapacityUsage, float capacityUsage) {
            handler.send(
                new ProbeOverallBulkOutputCapacityUsage(
                    requestIdentifier, bandwidthClassForCapacityUsage, capacityUsage));
          }
        };
    long probeUid = FcpRuntimeAdapters.nextSecureLong(handler.getServer().runtime().randomness());
    handler
        .getServer()
        .messageRuntimeSupport()
        .startProbe(hopsToLive, probeUid, probeType, listener);
  }
}
