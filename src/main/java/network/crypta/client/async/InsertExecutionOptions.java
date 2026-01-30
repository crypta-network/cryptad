package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import org.jetbrains.annotations.NotNull;

/**
 * Shared execution options for insert operations.
 *
 * <p>This record groups configuration flags that affect compression behavior, metadata-only
 * operation, archive handling, crypto settings, and scheduling hints. It is intentionally a simple
 * data carrier: values are stored as provided and no validation or defensive copying is performed.
 *
 * <p>The {@code forceCryptoKey} array is stored by reference and compared by content for equality.
 * Callers should avoid mutating it after construction if they rely on stable equality or hash
 * semantics.
 *
 * @param dontCompress whether compression is disabled for the insert
 * @param reportMetadataOnly whether to stop after preparing metadata and report it directly
 * @param archiveType optional archive type used when building metadata for redirects or manifests
 * @param forceCryptoKey optional explicit crypto key material; {@code null} to derive or randomize
 * @param cryptoAlgorithm crypto algorithm identifier understood by downstream inserters
 * @param realTimeFlag whether to request real-time scheduling behavior
 */
@SuppressWarnings("ArrayRecordComponent")
public record InsertExecutionOptions(
    boolean dontCompress,
    boolean reportMetadataOnly,
    ARCHIVE_TYPE archiveType,
    byte[] forceCryptoKey,
    byte cryptoAlgorithm,
    boolean realTimeFlag) {

  /**
   * Compares two option bundles by value, including array contents.
   *
   * @param o object to compare against; may be {@code null}
   * @return {@code true} when all components match by value
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        InsertExecutionOptions(
            boolean otherDontCompress,
            boolean otherReportMetadataOnly,
            ARCHIVE_TYPE otherArchiveType,
            byte[] otherForceCryptoKey,
            byte otherCryptoAlgorithm,
            boolean otherRealTimeFlag))) return false;
    return dontCompress == otherDontCompress
        && reportMetadataOnly == otherReportMetadataOnly
        && cryptoAlgorithm == otherCryptoAlgorithm
        && realTimeFlag == otherRealTimeFlag
        && archiveType == otherArchiveType
        && Arrays.equals(forceCryptoKey, otherForceCryptoKey);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * @return hash code derived from all components, including array contents
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(dontCompress, reportMetadataOnly, archiveType, cryptoAlgorithm, realTimeFlag);
    result = 31 * result + Arrays.hashCode(forceCryptoKey);
    return result;
  }

  /**
   * Returns a descriptive string without exposing crypto key material.
   *
   * @return non-null string representation of this options bundle
   */
  @Override
  public @NotNull String toString() {
    String keyState = (forceCryptoKey == null) ? "null" : "<redacted>";
    return "InsertExecutionOptions["
        + "dontCompress="
        + dontCompress
        + ", reportMetadataOnly="
        + reportMetadataOnly
        + ", archiveType="
        + archiveType
        + ", forceCryptoKey="
        + keyState
        + ", cryptoAlgorithm="
        + cryptoAlgorithm
        + ", realTimeFlag="
        + realTimeFlag
        + "]";
  }
}
