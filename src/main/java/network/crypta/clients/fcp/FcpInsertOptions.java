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
 *
 * @param getCHKOnly whether to compute the CHK without persisting blocks
 * @param dontCompress whether compression should be disabled for the insert
 * @param maxRetries maximum retries before failing the insert
 * @param earlyEncode whether encoding should begin before all data is received
 * @param canWriteClientCache whether client cache writes are permitted
 * @param forkOnCacheable whether to fork insert contexts when blocks become cacheable
 * @param extraInsertsSingleBlock redundancy factor for single-block inserts
 * @param extraInsertsSplitfileHeaderBlock redundancy factor for splitfile header blocks
 * @param realTimeFlag whether to schedule the insert in real-time queues
 * @param compatibilityMode compatibility mode guiding splitfile encoding parameters
 * @param overrideSplitfileCryptoKey optional splitfile crypto key override; may be {@code null}
 */
public record FcpInsertOptions(
    boolean getCHKOnly,
    boolean dontCompress,
    int maxRetries,
    boolean earlyEncode,
    boolean canWriteClientCache,
    boolean forkOnCacheable,
    int extraInsertsSingleBlock,
    int extraInsertsSplitfileHeaderBlock,
    boolean realTimeFlag,
    InsertContext.CompatibilityMode compatibilityMode,
    byte[] overrideSplitfileCryptoKey) {
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        FcpInsertOptions(
            boolean otherGetCHKOnly,
            boolean otherDontCompress,
            int otherMaxRetries,
            boolean otherEarlyEncode,
            boolean otherCanWriteClientCache,
            boolean otherForkOnCacheable,
            int otherExtraInsertsSingleBlock,
            int otherExtraInsertsSplitfileHeaderBlock,
            boolean otherRealTimeFlag,
            InsertContext.CompatibilityMode otherCompatibilityMode,
            byte[] otherOverrideSplitfileCryptoKey))) return false;
    return getCHKOnly == otherGetCHKOnly
        && dontCompress == otherDontCompress
        && maxRetries == otherMaxRetries
        && earlyEncode == otherEarlyEncode
        && canWriteClientCache == otherCanWriteClientCache
        && forkOnCacheable == otherForkOnCacheable
        && extraInsertsSingleBlock == otherExtraInsertsSingleBlock
        && extraInsertsSplitfileHeaderBlock == otherExtraInsertsSplitfileHeaderBlock
        && realTimeFlag == otherRealTimeFlag
        && compatibilityMode == otherCompatibilityMode
        && Arrays.equals(overrideSplitfileCryptoKey, otherOverrideSplitfileCryptoKey);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            getCHKOnly,
            dontCompress,
            maxRetries,
            earlyEncode,
            canWriteClientCache,
            forkOnCacheable,
            extraInsertsSingleBlock,
            extraInsertsSplitfileHeaderBlock,
            realTimeFlag,
            compatibilityMode);
    result = 31 * result + Arrays.hashCode(overrideSplitfileCryptoKey);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "FcpInsertOptions[getCHKOnly="
        + getCHKOnly
        + ", dontCompress="
        + dontCompress
        + ", maxRetries="
        + maxRetries
        + ", earlyEncode="
        + earlyEncode
        + ", canWriteClientCache="
        + canWriteClientCache
        + ", forkOnCacheable="
        + forkOnCacheable
        + ", extraInsertsSingleBlock="
        + extraInsertsSingleBlock
        + ", extraInsertsSplitfileHeaderBlock="
        + extraInsertsSplitfileHeaderBlock
        + ", realTimeFlag="
        + realTimeFlag
        + ", compatibilityMode="
        + compatibilityMode
        + ", overrideSplitfileCryptoKey="
        + (overrideSplitfileCryptoKey == null
            ? "null"
            : Arrays.toString(overrideSplitfileCryptoKey))
        + ']';
  }
}
