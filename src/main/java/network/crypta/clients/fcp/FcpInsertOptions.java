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
@SuppressWarnings("ArrayRecordComponent")
public record FcpInsertOptions(
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
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        FcpInsertOptions(
            boolean otherGetCHKOnly,
            boolean otherDontCompress,
            boolean otherLocalRequestOnly,
            int otherMaxRetries,
            boolean otherEarlyEncode,
            boolean otherCanWriteClientCache,
            boolean otherForkOnCacheable,
            String otherCompressorDescriptor,
            int otherExtraInsertsSingleBlock,
            int otherExtraInsertsSplitfileHeaderBlock,
            boolean otherRealTimeFlag,
            InsertContext.CompatibilityMode otherCompatibilityMode,
            boolean otherIgnoreUSKDatehints,
            byte[] otherOverrideSplitfileCryptoKey))) return false;
    return getCHKOnly == otherGetCHKOnly
        && dontCompress == otherDontCompress
        && localRequestOnly == otherLocalRequestOnly
        && maxRetries == otherMaxRetries
        && earlyEncode == otherEarlyEncode
        && canWriteClientCache == otherCanWriteClientCache
        && forkOnCacheable == otherForkOnCacheable
        && Objects.equals(compressorDescriptor, otherCompressorDescriptor)
        && extraInsertsSingleBlock == otherExtraInsertsSingleBlock
        && extraInsertsSplitfileHeaderBlock == otherExtraInsertsSplitfileHeaderBlock
        && realTimeFlag == otherRealTimeFlag
        && compatibilityMode == otherCompatibilityMode
        && ignoreUSKDatehints == otherIgnoreUSKDatehints
        && Arrays.equals(overrideSplitfileCryptoKey, otherOverrideSplitfileCryptoKey);
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
