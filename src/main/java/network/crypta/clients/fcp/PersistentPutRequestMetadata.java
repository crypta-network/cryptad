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
 */
public final class PersistentPutRequestMetadata {
  private final FreenetURI privateURI;
  private final boolean started;
  private final int maxRetries;
  private final InsertContext.CompatibilityMode compatMode;
  private final boolean dontCompress;
  private final String compressorDescriptor;
  private final byte[] splitfileCryptoKey;

  /**
   * Creates a metadata bundle describing a persistent insert request.
   *
   * @param privateURI optional private insert URI for resume or cancellation
   * @param started whether the request has already begun processing
   * @param maxRetries maximum retry attempts configured for the insert
   * @param compatMode insert compatibility mode requested by the client
   * @param dontCompress whether compression should be avoided for this insert
   * @param compressorDescriptor optional codec pipeline description
   * @param splitfileCryptoKey encryption key for splitfile segments, if known
   */
  public PersistentPutRequestMetadata(
      FreenetURI privateURI,
      boolean started,
      int maxRetries,
      InsertContext.CompatibilityMode compatMode,
      boolean dontCompress,
      String compressorDescriptor,
      byte[] splitfileCryptoKey) {
    this.privateURI = privateURI;
    this.started = started;
    this.maxRetries = maxRetries;
    this.compatMode = compatMode;
    this.dontCompress = dontCompress;
    this.compressorDescriptor = compressorDescriptor;
    this.splitfileCryptoKey = splitfileCryptoKey;
  }

  public FreenetURI privateURI() {
    return privateURI;
  }

  public boolean started() {
    return started;
  }

  public int maxRetries() {
    return maxRetries;
  }

  public InsertContext.CompatibilityMode compatMode() {
    return compatMode;
  }

  public boolean dontCompress() {
    return dontCompress;
  }

  public String compressorDescriptor() {
    return compressorDescriptor;
  }

  public byte[] splitfileCryptoKey() {
    return splitfileCryptoKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof PersistentPutRequestMetadata other)) return false;
    return started == other.started
        && maxRetries == other.maxRetries
        && dontCompress == other.dontCompress
        && Objects.equals(privateURI, other.privateURI)
        && compatMode == other.compatMode
        && Objects.equals(compressorDescriptor, other.compressorDescriptor)
        && Arrays.equals(splitfileCryptoKey, other.splitfileCryptoKey);
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
