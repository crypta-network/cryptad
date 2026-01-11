package network.crypta.clients.fcp;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.InsertContext;
import network.crypta.keys.FreenetURI;
import org.jetbrains.annotations.NotNull;

/**
 * Shared metadata describing persistent put requests.
 *
 * <p>This record groups the optional private URI alongside retry and compression settings that are
 * reused by both single-file and directory persistent put messages.
 *
 * @param privateURI optional private insert URI for resume or cancellation
 * @param started whether the request has already begun processing
 * @param maxRetries maximum retry attempts configured for the insert
 * @param compatMode insert compatibility mode requested by the client
 * @param dontCompress whether compression should be avoided for this insert
 * @param compressorDescriptor optional codec pipeline description
 * @param splitfileCryptoKey encryption key for splitfile segments, if known
 */
public record PersistentPutRequestMetadata(
    FreenetURI privateURI,
    boolean started,
    int maxRetries,
    InsertContext.CompatibilityMode compatMode,
    boolean dontCompress,
    String compressorDescriptor,
    byte[] splitfileCryptoKey) {
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        PersistentPutRequestMetadata(
            FreenetURI otherPrivateUri,
            boolean otherStarted,
            int otherMaxRetries,
            InsertContext.CompatibilityMode otherCompatMode,
            boolean otherDontCompress,
            String otherCompressorDescriptor,
            byte[] otherSplitfileCryptoKey))) return false;
    return started == otherStarted
        && maxRetries == otherMaxRetries
        && dontCompress == otherDontCompress
        && Objects.equals(privateURI, otherPrivateUri)
        && compatMode == otherCompatMode
        && Objects.equals(compressorDescriptor, otherCompressorDescriptor)
        && Arrays.equals(splitfileCryptoKey, otherSplitfileCryptoKey);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            privateURI, started, maxRetries, compatMode, dontCompress, compressorDescriptor);
    result = 31 * result + Arrays.hashCode(splitfileCryptoKey);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "PersistentPutRequestMetadata[privateURI="
        + privateURI
        + ", started="
        + started
        + ", maxRetries="
        + maxRetries
        + ", compatMode="
        + compatMode
        + ", dontCompress="
        + dontCompress
        + ", compressorDescriptor="
        + compressorDescriptor
        + ", splitfileCryptoKey="
        + (splitfileCryptoKey == null ? "null" : Arrays.toString(splitfileCryptoKey))
        + ']';
  }
}
