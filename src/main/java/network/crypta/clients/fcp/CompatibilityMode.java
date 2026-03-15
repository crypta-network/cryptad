package network.crypta.clients.fcp;

import network.crypta.client.InsertContext;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;

/**
 * Outbound-only FCP message that conveys the compatibility bounds selected for an insert session.
 *
 * <p>The {@code CompatibilityMode} message encapsulates the lower and upper compatibility modes,
 * compression preference, cryptographic key, and additional bookkeeping flags that an {@link
 * CompatibilityAnalyser} discovered while evaluating multiple inputs. Clients typically create an
 * instance once an analyser settles on definitive values, set the {@code identifier} that ties the
 * message back to their request queue, and send it over an {@link FCPConnectionHandler} so the node
 * can acknowledge whether it understands the announced range. Because the message is purely
 * descriptive, the {@link #run(FCPConnectionHandler)} hook is intentionally unsupported.
 *
 * <p>The class keeps a reference to the analyser rather than copying individual values, ensuring
 * that {@link #getFieldSet()} always reflects the analyser's most recent view when serialization
 * occurs. Callers should therefore avoid mutating the analyser concurrently with serialization and
 * treat instances as effectively immutable snapshots built on top of mutable state. Typical usage
 * sends one message per insert job before any data transfer begins, especially when clients need
 * the server to confirm compatibility before allocating large resources.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> translate analyser findings into the field-set format
 *       expected by the FCP wire protocol.
 *   <li><strong>Notable behavior:</strong> includes optional cryptographic key material only when
 *       supplied by the analyser, and toggles between global/local semantics via the {@code global}
 *       flag.
 * </ul>
 *
 * @see InsertContext.CompatibilityMode
 * @see CompatibilityAnalyser
 */
public class CompatibilityMode extends FCPMessage {
  /**
   * Creates a message bound to the given identifier, visibility, and analyser snapshot.
   *
   * <p>Callers construct this type immediately before dispatching the FCP message so that the
   * serialised {@link SimpleFieldSet} mirrors the analyser's latest bounds. The {@code identifier}
   * must match the client-side job token, the {@code global} flag controls whether the node should
   * broadcast the constraints to other peers, and {@code compat} supplies all remaining state. The
   * constructor performs no defensive copies, so subsequent analyser mutations are observed when
   * {@link #getFieldSet()} executes.
   *
   * <pre>{@code
   * CompatibilityAnalyser analyser = buildAnalyser();
   * FCPMessage msg = new CompatibilityMode("insert-42", true, analyser);
   * connection.send(msg.getName(), msg.getFieldSet());
   * }</pre>
   *
   * @param identifier caller-generated token that correlates asynchronous FCP replies; must be
   *     non-empty and unique per outstanding request to avoid collisions.
   * @param global {@code true} when the compatibility choice should be visible across the node;
   *     {@code false} scopes it to the requesting client only.
   * @param compat analyser that exposes min/max modes, compression preference, crypto key, and
   *     definitiveness; must not be {@code null} and should already reflect merged constraints.
   */
  public CompatibilityMode(String identifier, boolean global, CompatibilityAnalyser compat) {
    this.messageIdentifier = identifier;
    this.global = global;
    this.compat = compat;
  }

  private final CompatibilityAnalyser compat;
  final String messageIdentifier;
  final boolean global;

  /**
   * Builds the {@link SimpleFieldSet} payload that will be sent across FCP.
   *
   * <p>The returned structure enumerates the analyser's minimum and maximum compatibility modes in
   * both symbolic and numeric form, emits the message identifier and the {@code global} toggle, and
   * copies optional crypto key and compression flags. When {@link
   * CompatibilityAnalyser#getCryptoKey()} returns {@code null}, the {@code SplitfileCryptoKey}
   * field is omitted to keep the wire payload compact. Callers receive a newly allocated, mutable
   * field set whose lifetime they control.
   *
   * @return a newly created field set describing the analyser's compatibility findings and control
   *     flags; never {@code null}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putOverwrite("Min", compat.min().name());
    fs.putOverwrite("Max", compat.max().name());
    fs.put("Min.Number", compat.min().code);
    fs.put("Max.Number", compat.max().code);
    fs.putOverwrite("Identifier", messageIdentifier);
    fs.put("Global", global);
    byte[] cryptoKey = compat.getCryptoKey();
    if (cryptoKey != null) fs.putOverwrite("SplitfileCryptoKey", HexUtil.bytesToHex(cryptoKey));
    fs.put("DontCompress", compat.dontCompress());
    fs.put("Definitive", compat.definitive());
    return fs;
  }

  /**
   * Reports the FCP message name associated with this type.
   *
   * <p>The value is constant and used when serializing or dispatching the message so that the
   * remote endpoint can route it to the appropriate handler.
   *
   * @return the literal {@code "CompatibilityMode"} message identifier.
   */
  @Override
  public String getName() {
    return "CompatibilityMode";
  }

  /**
   * Server-side execution hook, which intentionally rejects invocation.
   *
   * <p>The message is designed for outbound client use only, so invoking this method from the
   * server pipeline always results in an {@link UnsupportedOperationException}. The signature is
   * preserved to satisfy the {@link FCPMessage} contract, but callers must not rely on it being
   * executable.
   *
   * @param handler connection handler provided by the FCP framework; ignored because the method is
   *     unsupported.
   * @throws MessageInvalidException declared for compatibility with the superclass but never thrown
   *     because the method terminates earlier with {@link UnsupportedOperationException}.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new UnsupportedOperationException();
  }

  /**
   * Exposes the analyser's raw compatibility modes array.
   *
   * <p>This convenience accessor relays {@link CompatibilityAnalyser#getModes()} so callers can
   * inspect every candidate mode instead of only the derived min/max bounds. The returned array is
   * owned by the analyser; modifications will affect subsequent serialization, so callers should
   * treat it as read-only.
   *
   * @return the analyser-provided array of compatibility modes in priority order; may be empty but
   *     never {@code null}.
   */
  public InsertContext.CompatibilityMode[] getModes() {
    return compat.getModes();
  }
}
