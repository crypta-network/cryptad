package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * FCP message that asks the node to stream its configuration metadata to the caller.
 *
 * <p>Instances are created from a {@link SimpleFieldSet} received over the socket and become
 * immutable thereafter; each boolean flag records whether the client wants current values,
 * defaults, ordering hints, expert visibility, force-write allowances, and both short and long
 * textual descriptions. The request is executed by the FCP server thread that owns the connection
 * and never touches mutable node state directly, making it safe to reuse across concurrent
 * connections as long as each instance is used once.
 *
 * <p>Typical usage constructs {@code GetConfig} immediately after parsing inbound fields and calls
 * {@link #run(FCPConnectionHandler, Node)} to validate access and send a {@link ConfigData}
 * response. The message refuses to run when the connection lacks full access, preventing
 * configuration disclosure to limited clients and aligning with the FCP access-control contract.
 *
 * <ul>
 *   <li>Responsibilities: capture client preferences and dispatch the configuration payload.
 *   <li>Notable behavior: strips the identifier from the inbound field set after caching it.
 *   <li>Concurrency: stateless after construction; thread-safe when each instance is single-use.
 * </ul>
 *
 * @see ConfigData
 * @see FCPConnectionHandler
 */
public class GetConfig extends FCPMessage {

  final boolean withCurrent;
  final boolean withDefaults;
  final boolean withSortOrder;
  final boolean withExpertFlag;
  final boolean withForceWriteFlag;
  final boolean withShortDescription;
  final boolean withLongDescription;
  final boolean withDataTypes;
  static final String NAME = "GetConfig";
  final String requestIdentifier;

  /**
   * Builds a {@code GetConfig} message from fields supplied by an FCP client.
   *
   * <p>The constructor copies all optional inclusion flags from the provided field set, falling
   * back to {@code false} when a flag is absent, and captures the caller-specified identifier for
   * correlation in the response. After extracting the identifier it removes it from the mutable
   * {@link SimpleFieldSet} to avoid leaking the token into subsequent processing. The resulting
   * instance is ready to be executed once and does not modify the provided field set again.
   *
   * @param fs incoming fields that describe which configuration details the caller wants; must not
   *     be {@code null} and is consumed for flag and identifier extraction.
   */
  public GetConfig(SimpleFieldSet fs) {
    withCurrent = fs.getBoolean("WithCurrent", false);
    withDefaults = fs.getBoolean("WithDefaults", false);
    withSortOrder = fs.getBoolean("WithSortOrder", false);
    withExpertFlag = fs.getBoolean("WithExpertFlag", false);
    withForceWriteFlag = fs.getBoolean("WithForceWriteFlag", false);
    withShortDescription = fs.getBoolean("WithShortDescription", false);
    withLongDescription = fs.getBoolean("WithLongDescription", false);
    withDataTypes = fs.getBoolean("WithDataTypes", false);
    this.requestIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  /**
   * Returns an empty field set because this message is built solely from incoming data.
   *
   * <p>The FCP framework invokes this method when it needs to serialise a request. For {@code
   * GetConfig} instances created from client input, the outbound representation is blank and acts
   * only as a signal to trigger the configuration transfer using the previously cached flags.
   * Callers should treat the returned field set as immutable and discard it after sending.
   *
   * @return a newly allocated {@link SimpleFieldSet} with no entries to transmit over FCP.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Returns the protocol-level message name used to route this request.
   *
   * <p>The value is constant for the lifetime of the application and matches the token expected by
   * FCP clients when sending command lines. FCP infrastructure uses the name to look up the handler
   * class, log activity, and map responses back to originating clients. Because the value is
   * immutable and public messages are keyed by it, the method is idempotent and inexpensive to call
   * repeatedly in routing, metrics collection, or debugging output.
   *
   * @return the fixed string {@code "GetConfig"} advertised in the FCP specification.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Validates the caller and sends the configuration snapshot back over the FCP connection.
   *
   * <p>The handler must present full-access credentials; otherwise this method halts execution by
   * raising a {@link MessageInvalidException} describing the access denial. When authorized, it
   * constructs a {@link ConfigData} response using the cached flags to decide whether to include
   * current values, defaults, sort order, expert-only markers, force-write allowances, short or
   * long descriptions, and data-type metadata. The response is streamed via the provided handler
   * without mutating the {@link Node}. Invocations are single-shot per instance; repeated calls
   * would resend identical configuration data until the connection closes.
   *
   * @param handler connection context responsible for permission checks and outbound delivery; must
   *     not be {@code null} and must expose full access for the call to proceed.
   * @param node backing node that supplies the configuration values reflected in the response; may
   *     be queried but is not modified during processing.
   * @throws MessageInvalidException if the caller lacks full access or message validation fails.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "GetConfig requires full access",
          requestIdentifier,
          false);
    }
    handler.send(
        new ConfigData(
            node,
            withCurrent,
            withDefaults,
            withSortOrder,
            withExpertFlag,
            withForceWriteFlag,
            withShortDescription,
            withLongDescription,
            withDataTypes,
            requestIdentifier));
  }
}
