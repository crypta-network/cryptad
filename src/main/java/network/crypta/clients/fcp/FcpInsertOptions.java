package network.crypta.clients.fcp;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.InsertContext;
import org.jetbrains.annotations.NotNull;

/**
 * Captures insert-specific tuning knobs supplied by FCP callers.
 *
 * <p>This value object aggregates caller-selected flags and numeric limits that shape how insert
 * requests are scheduled, encoded, and cached. Typical call sites assemble the two option group
 * records for behavior and tuning, then pass this instance into a request constructor that
 * initializes an {@link network.crypta.client.InsertContext}. The class is immutable in terms of
 * its field references and does not validate or normalize any inputs, which preserves legacy
 * behavior and keeps construction lightweight. Callers therefore remain responsible for providing
 * coherent combinations such as compatible retry limits and compression settings.
 *
 * <p>Instances are safe to share between threads because all fields are final, but the optional
 * {@code overrideSplitfileCryptoKey} array is stored by reference; if callers mutate the array
 * after construction, observers will see those mutations. Prefer supplying a stable array or a
 * defensive copy when sharing instances across components.
 *
 * <ul>
 *   <li>Groups behavior flags like real-time scheduling and local-only inserts.
 *   <li>Captures cache and redundancy tuning used by insert contexts.
 *   <li>Retains optional compressor and splitfile key hints without modification.
 * </ul>
 *
 * @see FcpInsertBehaviorOptions
 * @see FcpInsertTuningOptions
 * @see network.crypta.client.InsertContext
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
   * Creates an insert options bundle from the supplied option groups.
   *
   * <p>The constructor copies the provided option values into fixed fields and retains the override
   * key array reference as-is. It performs no validation, range checking, or normalization because
   * the surrounding FCP request pipeline already enforces field syntax and defaults. For
   * predictable behavior, callers should pass non-null option records and supply an override key
   * only when the insert workflow expects a precomputed splitfile crypto key.
   *
   * @param behaviorOptions flags and scheduling hints for the insert; must be non-null and already
   *     validated by the caller for consistency.
   * @param tuningOptions cache and redundancy tuning parameters; must be non-null and represent the
   *     desired compressor, redundancy, and compatibility choices.
   * @param overrideSplitfileCryptoKey optional splitfile crypto key override; may be {@code null}
   *     and is stored by reference without defensive copying.
   */
  public FcpInsertOptions(
      FcpInsertBehaviorOptions behaviorOptions,
      FcpInsertTuningOptions tuningOptions,
      byte[] overrideSplitfileCryptoKey) {
    this.getCHKOnly = behaviorOptions.getCHKOnly();
    this.dontCompress = behaviorOptions.dontCompress();
    this.localRequestOnly = behaviorOptions.localRequestOnly();
    this.maxRetries = behaviorOptions.maxRetries();
    this.earlyEncode = behaviorOptions.earlyEncode();
    this.realTimeFlag = behaviorOptions.realTimeFlag();
    this.ignoreUSKDatehints = behaviorOptions.ignoreUSKDatehints();
    this.canWriteClientCache = tuningOptions.canWriteClientCache();
    this.forkOnCacheable = tuningOptions.forkOnCacheable();
    this.compressorDescriptor = tuningOptions.compressorDescriptor();
    this.extraInsertsSingleBlock = tuningOptions.extraInsertsSingleBlock();
    this.extraInsertsSplitfileHeaderBlock = tuningOptions.extraInsertsSplitfileHeaderBlock();
    this.compatibilityMode = tuningOptions.compatibilityMode();
    this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
  }

  /**
   * Returns whether the insert is limited to computing the CHK without persisting blocks.
   *
   * <p>When this flag is {@code true}, downstream insert contexts typically avoid writing data to
   * the node stores and instead focus on deriving the final key. The value is a direct reflection
   * of the caller's request and is not interpreted or normalized here. The method is a simple
   * accessor and is idempotent; repeated calls return the same value.
   *
   * @return {@code true} when the insert should only compute the CHK and avoid persistence.
   */
  public boolean getCHKOnly() {
    return getCHKOnly;
  }

  /**
   * Returns whether compression is disabled for this insert.
   *
   * <p>This flag is passed through to the underlying insert context to control whether compression
   * codecs are considered. The value is stored exactly as provided and does not imply that data is
   * already compressed; it simply signals that the insert pipeline should skip compression logic.
   * The method is side-effect-free and always returns the stored value.
   *
   * @return {@code true} when compression should be bypassed for the insert payload.
   */
  public boolean dontCompress() {
    return dontCompress;
  }

  /**
   * Returns whether the insert must remain local to the current node.
   *
   * <p>Local-only inserts typically avoid network propagation and are used for workflows that only
   * need the key derivation or local storage side effects. This method exposes the stored flag
   * without interpretation or additional validation, allowing higher-level logic to decide how
   * strictly to enforce local-only behavior.
   *
   * @return {@code true} when the insert should not leave the local node.
   */
  public boolean localRequestOnly() {
    return localRequestOnly;
  }

  /**
   * Returns the maximum retry limit configured for this insert.
   *
   * <p>The value is used by the insert context to cap the number of retry attempts per block. It is
   * stored as provided and may follow sentinel conventions defined elsewhere (for example, negative
   * values may mean unlimited retries). This method does not enforce any range constraints and is
   * purely a value accessor.
   *
   * @return the maximum retry limit value supplied by the caller, unchanged.
   */
  public int maxRetries() {
    return maxRetries;
  }

  /**
   * Returns whether the insert should start encoding before all data is received.
   *
   * <p>Early encoding can reduce latency for streaming workflows by allowing block generation to
   * begin as soon as partial data is available. The flag is retained without modification; any
   * constraints or safety checks are handled by the caller or the insert pipeline. The accessor is
   * deterministic and has no side effects.
   *
   * @return {@code true} when early encoding is requested for this insert.
   */
  public boolean earlyEncode() {
    return earlyEncode;
  }

  /**
   * Returns whether writing to the client cache is permitted.
   *
   * <p>This flag is passed to the insert context to decide whether successfully produced blocks may
   * be stored in the client cache. It does not imply that caching will occur, only that it is
   * allowed. The value is stored exactly as provided and returned unchanged on each invocation.
   *
   * @return {@code true} when client cache writes are allowed for this insert.
   */
  public boolean canWriteClientCache() {
    return canWriteClientCache;
  }

  /**
   * Returns whether insert contexts may fork when blocks become cacheable.
   *
   * <p>Forking can allow insert scheduling to proceed with different cache-related assumptions once
   * data is known to be cacheable. The flag is stored as a simple boolean and is not interpreted
   * here. Consumers of this option decide how to use it in their scheduling and caching logic.
   *
   * @return {@code true} when insert contexts may fork on cacheable results.
   */
  public boolean forkOnCacheable() {
    return forkOnCacheable;
  }

  /**
   * Returns the optional compressor descriptor string, if supplied.
   *
   * <p>The descriptor typically names compressors or codec preferences to be used by the insert
   * pipeline. This class does not parse or validate the descriptor; it simply preserves the value
   * from the caller. A {@code null} return value indicates that no explicit descriptor was
   * specified and defaults should be applied by downstream logic.
   *
   * @return the compressor descriptor string, or {@code null} when no descriptor is provided.
   */
  public String compressorDescriptor() {
    return compressorDescriptor;
  }

  /**
   * Returns the redundancy factor for single-block inserts.
   *
   * <p>This value influences how many extra insert attempts are scheduled for payloads that fit in
   * a single block. It is preserved exactly as provided, including any sentinel values interpreted
   * by downstream logic. The method is a direct accessor and does not enforce any bounds.
   *
   * @return the extra insert count configured for single-block payloads.
   */
  public int extraInsertsSingleBlock() {
    return extraInsertsSingleBlock;
  }

  /**
   * Returns the redundancy factor for splitfile header blocks.
   *
   * <p>Splitfiles may have special header blocks that benefit from additional insert attempts. This
   * value is used by the insert context to configure that redundancy, but this class does not
   * interpret or validate the number. The accessor is deterministic and returns the stored value
   * exactly.
   *
   * @return the extra insert count configured for splitfile header blocks.
   */
  public int extraInsertsSplitfileHeaderBlock() {
    return extraInsertsSplitfileHeaderBlock;
  }

  /**
   * Returns whether the insert should be scheduled in real-time queues.
   *
   * <p>Real-time scheduling typically prioritizes lower latency over bulk throughput and is useful
   * for interactive insert workflows. This flag is stored exactly as provided and does not imply
   * any particular priority class; those decisions are made by higher-level scheduling logic. The
   * accessor is side-effect-free.
   *
   * @return {@code true} when real-time queueing is requested.
   */
  public boolean realTimeFlag() {
    return realTimeFlag;
  }

  /**
   * Returns the compatibility mode that guides splitfile encoding parameters.
   *
   * <p>The compatibility mode influences how metadata and block layouts are generated for insert
   * payloads. This value is stored as provided and is expected to be non-null; this class does not
   * perform any normalization or default selection. Downstream components should treat it as the
   * authoritative compatibility hint for the insert.
   *
   * @return the compatibility mode selected by the caller for this insert.
   */
  public InsertContext.CompatibilityMode compatibilityMode() {
    return compatibilityMode;
  }

  /**
   * Returns whether USK datehints should be ignored during insert.
   *
   * <p>When this flag is {@code true}, USK-specific date hints are bypassed so the insert proceeds
   * without those optimizations or constraints. The value is stored directly from the caller and is
   * exposed unchanged. No additional validation or normalization is performed.
   *
   * @return {@code true} when USK datehints should be ignored for this insert.
   */
  public boolean ignoreUSKDatehints() {
    return ignoreUSKDatehints;
  }

  /**
   * Returns the optional override splitfile crypto key reference.
   *
   * <p>The returned value is the same array reference supplied at construction time and may be
   * {@code null}. Because the array is not defensively copied, callers should treat the returned
   * reference as read-only to avoid surprising mutations elsewhere in the insert pipeline. If no
   * override key was supplied, downstream logic should fall back to generated keys.
   *
   * @return the override splitfile crypto key array reference, or {@code null} if none is set.
   */
  public byte[] overrideSplitfileCryptoKey() {
    return overrideSplitfileCryptoKey;
  }

  /**
   * Compares this instance to another for value equality.
   *
   * <p>The comparison checks every stored field, including a deep array comparison for the override
   * splitfile crypto key. Equality therefore reflects the content of the byte array at the time of
   * comparison; if the array is mutated after construction, equality results may change. This
   * method is symmetric, transitive, and consistent as long as inputs are not mutated.
   *
   * @param o object to compare against; may be {@code null}.
   * @return {@code true} when all fields match and array contents are equal.
   */
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

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash combines all scalar fields with a content-based hash of the override splitfile key
   * array. If the array contents are mutated after construction, the hash code will change and may
   * break usage in hashed collections. Callers should therefore treat the array as immutable once
   * inserted into maps or sets.
   *
   * @return a hash code derived from all fields and array contents.
   */
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

  /**
   * Returns a detailed string representation of this options bundle.
   *
   * <p>The output includes each field name and value, including the override splitfile key rendered
   * via {@link Arrays#toString(byte[])} when present. The method does not redact or sanitize
   * values, so callers should avoid logging the result if the raw key material is sensitive in
   * their context. The returned string is non-null and reflects the current field values.
   *
   * @return a non-null string containing all option fields and their current values.
   */
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
