package network.crypta.keys;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/** Bundles the parameters needed to build a client-side CHK block. */
public final class ClientCHKEncodeParams {
  private final byte[] data;
  private final int dataLength;
  private final MessageDigest md256;
  private final byte[] encKey;
  private final boolean asMetadata;
  private final short compressionAlgorithm;
  private final byte cryptoAlgorithm;
  private final int blockHashAlgorithm;

  /**
   * Creates a parameter bundle for CHK block encoding.
   *
   * @param data padded data (exactly {@link CHKBlock#DATA_LENGTH} bytes)
   * @param dataLength original, unpadded length in bytes
   * @param md256 reusable SHA-256 instance
   * @param encKey encryption key to use
   * @param asMetadata whether the resulting key is metadata
   * @param compressionAlgorithm compression algorithm identifier stored in the key
   * @param cryptoAlgorithm crypto algorithm identifier
   * @param blockHashAlgorithm block-hash identifier to store in the header
   */
  public ClientCHKEncodeParams(
      byte[] data,
      int dataLength,
      MessageDigest md256,
      byte[] encKey,
      boolean asMetadata,
      short compressionAlgorithm,
      byte cryptoAlgorithm,
      int blockHashAlgorithm) {
    this.data = data;
    this.dataLength = dataLength;
    this.md256 = md256;
    this.encKey = encKey;
    this.asMetadata = asMetadata;
    this.compressionAlgorithm = compressionAlgorithm;
    this.cryptoAlgorithm = cryptoAlgorithm;
    this.blockHashAlgorithm = blockHashAlgorithm;
  }

  public byte[] data() {
    return data;
  }

  public int dataLength() {
    return dataLength;
  }

  public MessageDigest md256() {
    return md256;
  }

  public byte[] encKey() {
    return encKey;
  }

  public boolean asMetadata() {
    return asMetadata;
  }

  public short compressionAlgorithm() {
    return compressionAlgorithm;
  }

  public byte cryptoAlgorithm() {
    return cryptoAlgorithm;
  }

  public int blockHashAlgorithm() {
    return blockHashAlgorithm;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof ClientCHKEncodeParams other)) return false;
    return dataLength == other.dataLength
        && asMetadata == other.asMetadata
        && compressionAlgorithm == other.compressionAlgorithm
        && cryptoAlgorithm == other.cryptoAlgorithm
        && blockHashAlgorithm == other.blockHashAlgorithm
        && Arrays.equals(data, other.data)
        && Objects.equals(md256, other.md256)
        && Arrays.equals(encKey, other.encKey);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            md256,
            dataLength,
            asMetadata,
            compressionAlgorithm,
            cryptoAlgorithm,
            blockHashAlgorithm);
    result = 31 * result + Arrays.hashCode(data);
    result = 31 * result + Arrays.hashCode(encKey);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "ClientCHKEncodeParams["
        + "data="
        + Arrays.toString(data)
        + ", dataLength="
        + dataLength
        + ", md256="
        + md256
        + ", encKey="
        + Arrays.toString(encKey)
        + ", asMetadata="
        + asMetadata
        + ", compressionAlgorithm="
        + compressionAlgorithm
        + ", cryptoAlgorithm="
        + cryptoAlgorithm
        + ", blockHashAlgorithm="
        + blockHashAlgorithm
        + "]";
  }
}
