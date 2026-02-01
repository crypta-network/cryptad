package network.crypta.clients.fcp;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.InsertContext;
import org.jetbrains.annotations.NotNull;

/**
 * Captures insert-specific tuning knobs supplied by FCP callers.
 *
 * <p>The options encapsulate retry limits, compression preferences, cache behaviors, redundancy
 * factors, real-time scheduling, and compatibility mode hints. They are shared between file and
 * directory put requests to ensure consistent configuration across insert flows.
 */
public final class FcpInsertOptions {
  private final boolean getCHKOnly;
  private final boolean dontCompress;
  private final boolean localRequestOnly;
  private final int maxRetries;
  private final boolean earlyEncode;
  private final boolean canWriteClientCache;
  private final boolean forkOnCacheable;
  private final String compressorDescriptor;
  private final int extraInsertsSingleBlock;
  private final int extraInsertsSplitfileHeaderBlock;
  private final boolean realTimeFlag;
  private final InsertContext.CompatibilityMode compatibilityMode;
  private final boolean ignoreUSKDatehints;
  private final byte[] overrideSplitfileCryptoKey;

  /**
   * Creates an insert options bundle.
   *
   * @param getCHKOnly whether to compute the CHK without persisting blocks
   * @param dontCompress whether compression should be disabled for the insert
   * @param localRequestOnly whether the insert should remain on the local node only
   * @param maxRetries maximum retries before failing the insert
   * @param earlyEncode whether encoding should begin before all data is received
   * @param canWriteClientCache whether client cache writes are permitted
   * @param forkOnCacheable whether to fork insert contexts when blocks become cacheable
   * @param compressorDescriptor optional compressor descriptor string; may be {@code null}
   * @param extraInsertsSingleBlock redundancy factor for single-block inserts
   * @param extraInsertsSplitfileHeaderBlock redundancy factor for splitfile header blocks
   * @param realTimeFlag whether to schedule the insert in real-time queues
   * @param compatibilityMode compatibility mode guiding splitfile encoding parameters
   * @param ignoreUSKDatehints whether USK datehints should be ignored during insert
   * @param overrideSplitfileCryptoKey optional splitfile crypto key override; may be {@code null}
   */
  public FcpInsertOptions(
      boolean getCHKOnly,
      boolean dontCompress,
      boolean localRequestOnly,
      int maxRetries,
      boolean earlyEncode,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      String compressorDescriptor,
      int extraInsertsSingleBlock,
      int extraInsertsSplitfileHeaderBlock,
      boolean realTimeFlag,
      InsertContext.CompatibilityMode compatibilityMode,
      boolean ignoreUSKDatehints,
      byte[] overrideSplitfileCryptoKey) {
    this.getCHKOnly = getCHKOnly;
    this.dontCompress = dontCompress;
    this.localRequestOnly = localRequestOnly;
    this.maxRetries = maxRetries;
    this.earlyEncode = earlyEncode;
    this.canWriteClientCache = canWriteClientCache;
    this.forkOnCacheable = forkOnCacheable;
    this.compressorDescriptor = compressorDescriptor;
    this.extraInsertsSingleBlock = extraInsertsSingleBlock;
    this.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeaderBlock;
    this.realTimeFlag = realTimeFlag;
    this.compatibilityMode = compatibilityMode;
    this.ignoreUSKDatehints = ignoreUSKDatehints;
    this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
  }

  public boolean getCHKOnly() {
    return getCHKOnly;
  }

  public boolean dontCompress() {
    return dontCompress;
  }

  public boolean localRequestOnly() {
    return localRequestOnly;
  }

  public int maxRetries() {
    return maxRetries;
  }

  public boolean earlyEncode() {
    return earlyEncode;
  }

  public boolean canWriteClientCache() {
    return canWriteClientCache;
  }

  public boolean forkOnCacheable() {
    return forkOnCacheable;
  }

  public String compressorDescriptor() {
    return compressorDescriptor;
  }

  public int extraInsertsSingleBlock() {
    return extraInsertsSingleBlock;
  }

  public int extraInsertsSplitfileHeaderBlock() {
    return extraInsertsSplitfileHeaderBlock;
  }

  public boolean realTimeFlag() {
    return realTimeFlag;
  }

  public InsertContext.CompatibilityMode compatibilityMode() {
    return compatibilityMode;
  }

  public boolean ignoreUSKDatehints() {
    return ignoreUSKDatehints;
  }

  public byte[] overrideSplitfileCryptoKey() {
    return overrideSplitfileCryptoKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof FcpInsertOptions other)) return false;
    return getCHKOnly == other.getCHKOnly
        && dontCompress == other.dontCompress
        && localRequestOnly == other.localRequestOnly
        && maxRetries == other.maxRetries
        && earlyEncode == other.earlyEncode
        && canWriteClientCache == other.canWriteClientCache
        && forkOnCacheable == other.forkOnCacheable
        && Objects.equals(compressorDescriptor, other.compressorDescriptor)
        && extraInsertsSingleBlock == other.extraInsertsSingleBlock
        && extraInsertsSplitfileHeaderBlock == other.extraInsertsSplitfileHeaderBlock
        && realTimeFlag == other.realTimeFlag
        && compatibilityMode == other.compatibilityMode
        && ignoreUSKDatehints == other.ignoreUSKDatehints
        && Arrays.equals(overrideSplitfileCryptoKey, other.overrideSplitfileCryptoKey);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            getCHKOnly,
            dontCompress,
            localRequestOnly,
            maxRetries,
            earlyEncode,
            canWriteClientCache,
            forkOnCacheable,
            compressorDescriptor,
            extraInsertsSingleBlock,
            extraInsertsSplitfileHeaderBlock,
            realTimeFlag,
            compatibilityMode,
            ignoreUSKDatehints);
    result = 31 * result + Arrays.hashCode(overrideSplitfileCryptoKey);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "FcpInsertOptions[getCHKOnly="
        + getCHKOnly
        + ", dontCompress="
        + dontCompress
        + ", localRequestOnly="
        + localRequestOnly
        + ", maxRetries="
        + maxRetries
        + ", earlyEncode="
        + earlyEncode
        + ", canWriteClientCache="
        + canWriteClientCache
        + ", forkOnCacheable="
        + forkOnCacheable
        + ", compressorDescriptor="
        + compressorDescriptor
        + ", extraInsertsSingleBlock="
        + extraInsertsSingleBlock
        + ", extraInsertsSplitfileHeaderBlock="
        + extraInsertsSplitfileHeaderBlock
        + ", realTimeFlag="
        + realTimeFlag
        + ", compatibilityMode="
        + compatibilityMode
        + ", ignoreUSKDatehints="
        + ignoreUSKDatehints
        + ", overrideSplitfileCryptoKey="
        + (overrideSplitfileCryptoKey == null
            ? "null"
            : Arrays.toString(overrideSplitfileCryptoKey))
        + ']';
  }
}
