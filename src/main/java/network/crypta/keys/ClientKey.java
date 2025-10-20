package network.crypta.keys;

import java.io.Serial;
import java.io.Serializable;

/**
 * Abstract base for client-facing keys used to fetch and decrypt content.
 *
 * <p>Client keys (for example {@code CHK} and {@code SSK}) carry the information required to
 * decrypt data that a node retrieves. Node-level keys (see {@link Key}) are routing-only and do not
 * include client secrets. After the node fetches a {@link KeyBlock}, the data can be decoded only
 * by combining that block with the appropriate {@link ClientKey} to create a {@link ClientKeyBlock}
 * which performs decryption and optional decompression.
 *
 * <p>The client portion commonly embeds decryption material present in the URI (typically after the
 * comma in the canonical form) that the node itself does not retain.
 */
public abstract class ClientKey extends BaseClientKey implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Derive the node-level routing key corresponding to this client key.
   *
   * <p>The returned instance drops client-only secrets and contains only the information required
   * for routing and storage (for example, {@link NodeCHK} or {@link NodeSSK}).
   *
   * @param cloneKey when {@code true}, return a defensive clone of the derived node key; when
   *     {@code false}, the implementation may return a cached instance
   * @return the node-level {@link Key} corresponding to this client key (never {@code null})
   */
  public abstract Key getNodeKey(boolean cloneKey);

  /**
   * Convenience overload that returns a cloned node-level key.
   *
   * @return a defensive copy of the derived node {@link Key}
   */
  public Key getNodeKey() {
    return getNodeKey(true);
  }

  /**
   * Create a deep copy of this client key.
   *
   * <p>Implementations return a logically equivalent key that does not share mutable internal
   * arrays or cached node-key instances with the original.
   *
   * @return an independent copy of this key
   */
  public abstract ClientKey cloneKey();

  protected ClientKey() {
    // For Java serialization frameworks only; not intended for regular construction.
  }
}
