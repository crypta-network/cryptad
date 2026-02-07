package network.crypta.crypt;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import network.crypta.support.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base type for cryptographic keys used by the Crypta node.
 *
 * <p>Implementations define the concrete key material and encoding. A key exposes a human‑readable
 * {@link #keyType()} identifier, a stable display fingerprint via {@link #fingerprint()}, and a
 * byte representation through {@link #asBytes()}.
 *
 * <p>Serialization helpers in this class support a simple polymorphic format in which the first
 * field is the fully qualified class name of the concrete key, written with {@link
 * java.io.DataOutput#writeUTF(String)}. The corresponding {@link #read(InputStream)} method
 * resolves that class and delegates to a public static {@code readKey(InputStream)} factory on the
 * key type, with a fallback to legacy {@code read(InputStream)} factories.
 */
public abstract class CryptoKey implements CryptoElement, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(CryptoKey.class);

  @Serial private static final long serialVersionUID = 1L;

  CryptoKey() {}

  /**
   * Read a {@code CryptoKey} from the given stream.
   *
   * <p>The stream must start with a UTF string containing the fully qualified class name of the
   * concrete key type (as written by {@link DataOutput#writeUTF(String)}). The loader locates that
   * class, obtains a public static factory with the exact signature {@code readKey(InputStream)},
   * and invokes it to parse the remainder of the data. For compatibility with older key
   * implementations, the loader falls back to {@code read(InputStream)} when {@code readKey} is
   * absent.
   *
   * <p>On failures that represent normal parse conditions, such as malformed input, this method
   * propagates the underlying {@link CryptFormatException} or {@link IOException}. Other failures
   * (unknown type, reflective errors, or unchecked exceptions) are logged and result in a {@code
   * null} return value.
   *
   * @param i source stream positioned at the beginning of a serialized key; not closed
   * @return the parsed key instance, or {@code null} if the type cannot be resolved or an
   *     unexpected runtime error occurs
   * @throws IOException if the stream cannot be read
   * @throws CryptFormatException if the data is recognized but invalid for the target type
   */
  public static CryptoKey read(InputStream i) throws IOException, CryptFormatException {
    DataInputStream dis = new DataInputStream(i);
    String type = dis.readUTF();
    try {
      Class<?> keyClass = Class.forName(type);
      Method m = resolveReadMethod(keyClass);
      return (CryptoKey) m.invoke(null, dis);
    } catch (InvocationTargetException e) {
      // Unwrap and rethrow expected checked exceptions from the delegate factory.
      Throwable cause = e.getCause();
      if (cause instanceof CryptFormatException exception) throw exception;
      if (cause instanceof IOException exception) throw exception;
      LOG.error("Error in delegated CryptoKey.read()", cause);
      return null;
    } catch (ReflectiveOperationException e) {
      LOG.error("Reflection failure while reading CryptoKey of type {}", type, e);
      return null;
    } catch (RuntimeException e) {
      LOG.error("Runtime exception while reading CryptoKey", e);
      return null;
    }
  }

  private static Method resolveReadMethod(Class<?> keyClass) throws NoSuchMethodException {
    try {
      return keyClass.getMethod("readKey", InputStream.class);
    } catch (NoSuchMethodException e) {
      return keyClass.getMethod("read", InputStream.class);
    }
  }

  /**
   * Short type identifier used for display and serialization.
   *
   * <p>The value typically matches the concrete key family and may be included in human‑readable
   * strings such as {@link #toString()}.
   *
   * @return a non‑empty identifier describing the key family
   */
  public abstract String keyType();

  /**
   * Return a stable fingerprint for this key.
   *
   * <p>The fingerprint is intended for UI and logging. Implementations derive it from canonical key
   * parameters. Callers must not rely on a specific hash algorithm; use {@link
   * #fingerprintToString()} or {@link #toString()} for display.
   *
   * @return byte array containing the fingerprint
   */
  public abstract byte[] fingerprint();

  /**
   * Return the encoded key material.
   *
   * <p>The exact encoding is implementation‑specific and suitable for persistence or transport in
   * contexts that understand the corresponding concrete key type.
   *
   * @return a byte array representation of the key
   */
  public abstract byte[] asBytes();

  /**
   * Compute an SHA‑1 digest over the provided big‑integer quantities encoded as MPIs.
   *
   * <p>Each quantity is converted via {@link Util#mpiBytes(BigInteger)} and fed to the digest in
   * order. The resulting digest is commonly used as a key fingerprint.
   *
   * @param quantities key parameters encoded as big integers, in deterministic order
   * @return the SHA‑1 digest of the concatenated MPI encodings
   */
  protected byte[] fingerprint(BigInteger[] quantities) {
    // Digest MPI-encoded values using SHA-1 to produce a compact fingerprint.
    MessageDigest shactx = HashType.SHA1.get();
    for (BigInteger quantity : quantities) {
      byte[] mpi = Util.mpiBytes(quantity);
      shactx.update(mpi, 0, mpi.length);
    }
    return shactx.digest();
  }

  /**
   * Verbose string that includes the compact identifier and the full fingerprint.
   *
   * <p>The format is equivalent to {@code toString() + "\t" + fingerprintToString()} and is
   * intended for logs and diagnostics.
   *
   * @return a human‑readable string with both identifier and fingerprint
   */
  @SuppressWarnings("unused")
  public String verboseToString() {
    return String.valueOf(this) + '\t' + fingerprintToString();
  }

  /**
   * Return a compact identifier for this key.
   *
   * <p>The string has the form {@code keyType()/...} where the suffix is a shortened hexadecimal
   * rendering of the fingerprint. The result is stable for a given key and suitable for logs.
   */
  @Override
  public String toString() {
    StringBuilder b = new StringBuilder(keyType().length() + 1 + 4);
    b.append(keyType()).append('/');
    HexUtil.bytesToHexAppend(fingerprint(), 16, 4, b);
    return b.toString();
  }

  /**
   * Return the fingerprint as grouped hexadecimal suitable for display.
   *
   * <p>The output renders 40 hexadecimal characters (20 bytes) grouped into blocks separated by
   * spaces, with a double space in the middle for readability. This is intended for UIs and
   * diagnostics and does not include the key type.
   *
   * @return the formatted fingerprint string
   */
  public String fingerprintToString() {
    String fphex = HexUtil.bytesToHex(fingerprint());
    return fphex.substring(0, 4)
        + ' '
        + fphex.substring(4, 8)
        + ' '
        + fphex.substring(8, 12)
        + ' '
        + fphex.substring(12, 16)
        + ' '
        + fphex.substring(16, 20)
        + "  "
        + fphex.substring(20, 24)
        + ' '
        + fphex.substring(24, 28)
        + ' '
        + fphex.substring(28, 32)
        + ' '
        + fphex.substring(32, 36)
        + ' '
        + fphex.substring(36, 40);
  }
}
