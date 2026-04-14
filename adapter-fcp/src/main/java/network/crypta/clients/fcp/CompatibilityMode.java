package network.crypta.clients.fcp;

import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;

/**
 * Outbound-only FCP message that conveys the compatibility bounds selected for an insert session.
 *
 * <p>The {@code CompatibilityMode} message encapsulates the lower and upper compatibility modes,
 * compression preference, cryptographic key, and additional bookkeeping flags that an {@link
 * FcpCompatibilityAnalysis} discovered while evaluating multiple inputs. Clients typically create
 * an instance once an analysis settles on definitive values, set the {@code identifier} that ties
 * the message back to their request queue, and send it over an {@link FCPConnectionHandler} so the
 * node can acknowledge whether it understands the announced range. Because the message is purely
 * descriptive, the {@link #run(FCPConnectionHandler)} hook is intentionally unsupported.
 *
 * <p>The class keeps a reference to the analysis rather than copying individual values, ensuring
 * that {@link #getFieldSet()} always reflects the analysis's most recent view when serialization
 * occurs. Callers should therefore avoid mutating the analysis concurrently with serialization and
 * treat instances as effectively immutable snapshots built on top of the mutable state.
 */
public class CompatibilityMode extends FCPMessage {
  private final FcpCompatibilityAnalysis compat;
  final String messageIdentifier;
  final boolean global;

  /**
   * Creates a message bound to the given identifier, visibility, and analysis snapshot.
   *
   * @param identifier caller-generated token that correlates asynchronous FCP replies.
   * @param global {@code true} when the compatibility choice should be visible across the node.
   * @param compat analysis that exposes min/max modes, compression preference, crypto key, and
   *     definitiveness; must not be {@code null}.
   */
  public CompatibilityMode(String identifier, boolean global, FcpCompatibilityAnalysis compat) {
    this.messageIdentifier = identifier;
    this.global = global;
    this.compat = compat;
  }

  /**
   * Builds the {@link SimpleFieldSet} payload that will be sent across FCP.
   *
   * @return a newly created field set describing the analysis's compatibility findings and control
   *     flags; never {@code null}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putOverwrite("Min", compat.min().name());
    fs.putOverwrite("Max", compat.max().name());
    fs.put("Min.Number", compat.min().code());
    fs.put("Max.Number", compat.max().code());
    fs.putOverwrite("Identifier", messageIdentifier);
    fs.put("Global", global);
    byte[] cryptoKey = compat.getCryptoKey();
    if (cryptoKey != null) {
      fs.putOverwrite("SplitfileCryptoKey", HexUtil.bytesToHex(cryptoKey));
    }
    fs.put("DontCompress", compat.dontCompress());
    fs.put("Definitive", compat.definitive());
    return fs;
  }

  @Override
  public String getName() {
    return "CompatibilityMode";
  }

  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new UnsupportedOperationException();
  }

  /** Returns the analysis's current compatibility mode window. */
  public FcpCompatibilityMode[] getModes() {
    return compat.getModes();
  }
}
