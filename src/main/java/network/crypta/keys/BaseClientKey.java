package network.crypta.keys;

import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;

/**
 * Base type for keys that identify content a node can fetch.
 *
 * <p>Subclasses model concrete client key kinds, such as {@code CHK}, {@code SSK}, and {@code KSK}
 * (derived from the URI's document name). Higher-level keys like {@code USK} also extend this class
 * even though they may not map directly to a single routing key at construction time.
 *
 * <p><strong>Persistence note:</strong> This class is {@link java.io.Serializable}. Changing
 * non-transient members on serializable classes can invalidate on-disk state and may cause active
 * downloads to restart or pending uploads to be lost after an upgrade. Avoid altering the
 * serialized shape without a compatible migration plan.
 */
public abstract class BaseClientKey implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates a {@code BaseClientKey} from the supplied URI.
   *
   * <p>The factory inspects the key type encoded in {@code origURI} and returns the corresponding
   * client key implementation:
   *
   * <ul>
   *   <li>{@code CHK} → {@link ClientCHK}
   *   <li>{@code SSK} → {@link ClientSSK}
   *   <li>{@code KSK} → {@link ClientKSK} (constructed from the URI's document name)
   *   <li>{@code USK} → {@link USK}
   * </ul>
   *
   * <p>The method does not otherwise validate the URI beyond delegating to the specific constructor
   * or factory of the chosen key type.
   *
   * @param origURI source URI; must not be {@code null}.
   * @return a key instance matching the URI's type.
   * @throws MalformedURLException if the key type is unrecognized or if a specific key
   *     implementation rejects the URI.
   */
  public static BaseClientKey getBaseKey(FreenetURI origURI) throws MalformedURLException {
    String keyType = origURI.getKeyType();
    if ("CHK".equals(keyType)) return new ClientCHK(origURI);
    if ("SSK".equals(keyType)) return new ClientSSK(origURI);
    if ("KSK".equals(keyType)) return ClientKSK.create(origURI.getDocName());
    if ("USK".equals(keyType)) return USK.create(origURI);
    throw new MalformedURLException("Unknown keytype from " + origURI);
  }

  /**
   * Returns the URI representation of this key.
   *
   * @return a non-{@code null} {@link FreenetURI} describing this key.
   */
  public abstract FreenetURI getURI();

  /**
   * No-arg constructor for serialization frameworks.
   *
   * <p>Subclasses are expected to expose public constructors or factories for regular use. This
   * constructor exists to support Java serialization only.
   */
  protected BaseClientKey() {
    // Intentionally empty; used by Java serialization only.
  }
}
