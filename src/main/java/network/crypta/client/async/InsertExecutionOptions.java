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
 */
public final class InsertExecutionOptions {
  private final boolean dontCompress;
  private final boolean reportMetadataOnly;
  private final ARCHIVE_TYPE archiveType;
  private final byte[] forceCryptoKey;
  private final byte cryptoAlgorithm;
  private final boolean realTimeFlag;

  /**
   * Creates an immutable execution options bundle for inserts.
   *
   * @param dontCompress whether compression is disabled for the insert
   * @param reportMetadataOnly whether to stop after preparing metadata and report it directly
   * @param archiveType optional archive type used when building metadata for redirects or manifests
   * @param forceCryptoKey optional explicit crypto key material; {@code null} to derive or
   *     randomize
   * @param cryptoAlgorithm crypto algorithm identifier understood by downstream inserters
   * @param realTimeFlag whether to request real-time scheduling behavior
   */
  public InsertExecutionOptions(
      boolean dontCompress,
      boolean reportMetadataOnly,
      ARCHIVE_TYPE archiveType,
      byte[] forceCryptoKey,
      byte cryptoAlgorithm,
      boolean realTimeFlag) {
    this.dontCompress = dontCompress;
    this.reportMetadataOnly = reportMetadataOnly;
    this.archiveType = archiveType;
    this.forceCryptoKey = forceCryptoKey;
    this.cryptoAlgorithm = cryptoAlgorithm;
    this.realTimeFlag = realTimeFlag;
  }

  public boolean dontCompress() {
    return dontCompress;
  }

  public boolean reportMetadataOnly() {
    return reportMetadataOnly;
  }

  public ARCHIVE_TYPE archiveType() {
    return archiveType;
  }

  public byte[] forceCryptoKey() {
    return forceCryptoKey;
  }

  public byte cryptoAlgorithm() {
    return cryptoAlgorithm;
  }

  public boolean realTimeFlag() {
    return realTimeFlag;
  }

  /**
   * Compares two option bundles by value, including array contents.
   *
   * @param o object to compare against; may be {@code null}
   * @return {@code true} when all components match by value
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof InsertExecutionOptions other)) return false;
    return dontCompress == other.dontCompress
        && reportMetadataOnly == other.reportMetadataOnly
        && cryptoAlgorithm == other.cryptoAlgorithm
        && realTimeFlag == other.realTimeFlag
        && archiveType == other.archiveType
        && Arrays.equals(forceCryptoKey, other.forceCryptoKey);
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
