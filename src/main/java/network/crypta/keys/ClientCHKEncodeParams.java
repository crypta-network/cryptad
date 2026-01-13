package network.crypta.keys;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the parameters needed to build a client-side CHK block.
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
public record ClientCHKEncodeParams(
    byte[] data,
    int dataLength,
    MessageDigest md256,
    byte[] encKey,
    boolean asMetadata,
    short compressionAlgorithm,
    byte cryptoAlgorithm,
    int blockHashAlgorithm) {

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj
        instanceof
        ClientCHKEncodeParams(
            byte[] otherData,
            int otherDataLength,
            MessageDigest otherMd256,
            byte[] otherEncKey,
            boolean otherAsMetadata,
            short otherCompressionAlgorithm,
            byte otherCryptoAlgorithm,
            int otherBlockHashAlgorithm))) return false;
    return dataLength == otherDataLength
        && asMetadata == otherAsMetadata
        && compressionAlgorithm == otherCompressionAlgorithm
        && cryptoAlgorithm == otherCryptoAlgorithm
        && blockHashAlgorithm == otherBlockHashAlgorithm
        && Arrays.equals(data, otherData)
        && Objects.equals(md256, otherMd256)
        && Arrays.equals(encKey, otherEncKey);
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
