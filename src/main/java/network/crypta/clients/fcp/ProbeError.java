package network.crypta.clients.fcp;

import network.crypta.node.probe.Error;
import network.crypta.node.probe.Listener;

/**
 * Immutable response envelope emitted whenever a running probe fails.
 *
 * <p>{@code ProbeError} captures the minimal context a client needs to correlate a probe failure
 * with its originating request and to determine whether the fault originated locally or was relayed
 * from a remote node. Instances are created synchronously by the probing subsystem right before the
 * response is serialized back to the waiting FCP connection, and they are not reused afterward.
 * This design keeps the object small, makes the serialized {@link
 * network.crypta.support.SimpleFieldSet} entirely deterministic, and spares the caller from having
 * to introspect internal probe state.
 *
 * <p>Although the class exposes only a constructor and {@link #getName()} today, documenting it
 * explicitly matters because it represents the only sanctioned way to surface probe-related
 * failures over FCP. The wrapped field set always obeys the canonical key names defined on {@link
 * FCPMessage}, guaranteeing that tooling can rely on fixed strings when parsing.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> mirror probe errors into the wire protocol without
 *       leaking implementation details.
 *   <li><strong>Notable behavior:</strong> stores the error type, optional vendor-specific code,
 *       and locality flag so clients know whether to retry or escalate.
 *   <li><strong>Concurrency:</strong> instances are confined to a single thread; no synchronization
 *       is performed and no mutable state escapes after serialization.
 * </ul>
 */
public class ProbeError extends FCPResponse {
  /**
   * Builds a serialized probe failure frame ready to stream over FCP.
   *
   * <p>The constructor eagerly records every supplied attribute in the backing field set so callers
   * can immediately hand the instance to the FCP writer without further mutation. When {@code code}
   * is {@code null}, the value is omitted to keep the wire format lean; otherwise the numeric value
   * is retained verbatim. The {@code local} flag distinguishes between node-internal failures and
   * conditions relayed from upstream peers, which is particularly important for retry heuristics.
   *
   * <pre>{@code
   * // Example: emit a remote timeout back to the client
   * var response = new ProbeError(id, Error.TIMEOUT, null, false);
   * handler.send(response);
   * }</pre>
   *
   * @param fcpIdentifier identifier correlating this response to the originating probe request;
   *     {@code null} skips the {@code Identifier} key entirely for one-shot notifications.
   * @param error type-safe categorization of the failure, aligned with {@link Listener#onError} and
   *     serialized via {@link Error#name()}.
   * @param code optional vendor or remote numeric code preserved only when non-{@code null}; use
   *     when reporting {@link Error#UNKNOWN} or {@link Error#UNRECOGNIZED_TYPE} variants.
   * @param local {@code true} when the node itself originated the failure and {@code false} when it
   *     merely relayed a remote peer's verdict.
   * @see Listener#onError(Error, Byte, boolean)
   * @see Error
   */
  public ProbeError(String fcpIdentifier, Error error, Byte code, boolean local) {
    super(fcpIdentifier);
    fs.putOverwrite(TYPE, error.name());
    if (code != null) fs.put(CODE, code);
    fs.put(LOCAL, local);
  }

  /**
   * Reports the stable FCP verb associated with this response type.
   *
   * <p>The name is constant and matches the value used on the wire so that routing tables,
   * connection logs, and downstream tooling all agree on a single identifier. Unlike most request
   * messages, response names never vary by payload, so this method performs no computation and can
   * be called repeatedly without allocation. Callers typically delegate to it while serializing the
   * message header, and tests may use it to assert the correct response subtype was emitted during
   * a probe run.
   *
   * @return immutable string {@code "ProbeError"}, suitable for use in logging, routing, or wire
   *     serialization, and never {@code null}.
   */
  @Override
  public String getName() {
    return "ProbeError";
  }
}
