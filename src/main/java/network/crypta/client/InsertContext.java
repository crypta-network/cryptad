package network.crypta.client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.support.compress.Compressor;

/**
 * Configuration container for a single insert operation, covering both simple and multi-file
 * inserts.
 *
 * <p>An {@code InsertContext} captures all tunable parameters that influence how data is prepared
 * for insertion into the network: compression behavior, splitfile sizing, redundancy, cache
 * policies, and compatibility rules for on-disk and on-wire formats. Higher-level clients typically
 * obtain a baseline instance from a helper or {@code ClientContext} and then adjust a small subset
 * of fields via the provided setters before starting an insert. The same context may be reused
 * across multiple operations when the caller wants a consistent policy.
 *
 * <p>The instance is mutable and not thread-safe; callers should either confine it to a single
 * thread or perform external synchronization if multiple threads may mutate it concurrently.
 * Compatibility-related fields are normalized so that callers observe concrete {@link
 * CompatibilityMode} values rather than placeholders such as {@link
 * CompatibilityMode#COMPAT_CURRENT}. Serialization is supported for persistent requests, and care
 * must be taken when changing the set of non-transient fields to avoid breaking upgrades.
 *
 * <ul>
 *   <li>Controls compression, client-cache usage, and redundancy for inserts.
 *   <li>Exposes compatibility settings that affect key and metadata layout.
 *   <li>Provides an associated {@link network.crypta.client.events.ClientEventProducer} for
 *       progress events.
 * </ul>
 *
 * <p><strong>Warning:</strong> Changing non-transient members on classes that implement {@link
 * Serializable} can make previously persisted requests unreadable or cause uploads to be lost
 * across upgrades.
 */
public class InsertContext implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /** If true, don't try to compress the data */
  private boolean dontCompress;

  /** Splitfile algorithm. */
  private final SplitfileAlgorithm splitfileAlgo;

  /** For migration only. */
  private final short splitfileAlgorithm;

  /**
   * Maximum number of retries (after the initial attempt) for each block inserted. -1 = retry
   * forever or until it succeeds (subject to consecutiveRNFsCountAsSuccess) or until a fatal error.
   */
  private int maxInsertRetries;

  /**
   * On a very small network, any insert will RNF. Therefore, we allow some number of RNFs to equal
   * success.
   */
  private int consecutiveRNFsCountAsSuccess;

  /** Maximum number of data blocks per segment for splitfiles */
  private int splitfileSegmentDataBlocks;

  /**
   * Maximum number of check blocks per segment for splitfiles. Will be reduced proportionally if
   * there are fewer data blocks.
   */
  private int splitfileSegmentCheckBlocks;

  /** Client events will be published to this, you can subscribe to them */
  private ClientEventProducer eventProducer;

  /**
   * Can this insert write to the client-cache? We don't store all requests in the client cache, in
   * particular big stuff usually isn't written to it, to maximize its effectiveness. Plus, local
   * inserts are not written to the client-cache by default for privacy reasons.
   */
  private boolean canWriteClientCache;

  /**
   * a string that contains the codecs to use/try if the string is null it defaults to
   * COMPRESSOR_TYPES.Values(), so old persistent inserts are not affected after update.
   *
   * @see Compressor.COMPRESSOR_TYPE#getCompressorsArray(String)
   */
  private String compressorDescriptor;

  /**
   * Whether inserts may fork additional work when results are cacheable.
   *
   * <p>When enabled, the insert pipeline may create extra requests for cacheable content in order
   * to improve redundancy and fetch performance at the cost of additional network traffic.
   */
  private boolean forkOnCacheable;

  /** Number of extra inserts for a single block inserted on its own. */
  private int extraInsertsSingleBlock;

  /** Number of extra inserts for a block inserted above a splitfile. */
  private int extraInsertsSplitfileHeaderBlock;

  /**
   * Whether this insert is restricted to local requests only.
   *
   * <p>When {@code true}, the insert avoids announcing data to the wider network and instead keeps
   * processing local to the node, which can be desirable for privacy-sensitive or testing
   * scenarios.
   */
  private boolean localRequestOnly;

  /** Don't insert USK DATEHINTs (and ignore them on polling for maximum edition). */
  private boolean ignoreUSKDatehints;

  /**
   * Compatibility mode. This determines exactly how we insert data, so that we can produce the same
   * CHK when reinserting a key even if it is with a later version of Freenet. It is also important
   * for e.g. auto-update to be able to insert keys compatible with older nodes, but
   * CompatibilityMode's are sometimes backwards compatible, there are separate versioning systems
   * for keys and Metadata, which will be set as appropriate for an insert depending on the
   * CompatibilityMode.
   */
  public enum CompatibilityMode {

    /** We do not know. */
    COMPAT_UNKNOWN((short) 0),
    /**
     * No compatibility issues, use the most efficient metadata possible. Used only in the
     * front-end: MUST NOT be stored: Code should convert this to a specific mode as early as
     * possible, or inserts will break when a new mode is added. InsertContext does this.
     */
    COMPAT_CURRENT((short) 1),
    // The below *are* used in Metadata compatibility mode detection. And they are comparable by
    // code.
    // This means we have to check for COMPAT_CURRENT as a special case.
    /** Exactly as before 1250: Segments of exactly 128 data, 128 check, check = data */
    COMPAT_1250_EXACT((short) 2),
    /** 1250 or previous: Segments up to 128 data 128 check, check &lt;= data. */
    COMPAT_1250((short) 3),
    /**
     * 1251/2/3: Basic even splitting, 1 extra check block if data blocks &lt; 128, max 131 data
     * blocks.
     */
    COMPAT_1251((short) 4),
    /**
     * 1255: Second stage of even splitting, a bunch of segments lose one block rather than the last
     * segment losing lots of blocks. And hashes too!
     */
    COMPAT_1255((short) 5),
    /** 1416: New CHK encryption */
    COMPAT_1416((short) 6),
    /**
     * 1468: Fill in topDontCompress and topCompatibilityMode on splitfiles. Same blocks, but
     * slightly different metadata.
     */
    COMPAT_1468((short) 7);

    /**
     * Code used in metadata for this CompatibilityMode. Hence, we can remove old
     * CompatibilityMode's, and it's also convenient.
     */
    public final short code;

    CompatibilityMode(short code) {
      this.code = code;
    }

    /** Cached result of {@link #values()}. Never modify or expose this array directly. */
    private static final CompatibilityMode[] values = values();

    // Inserts should be converted to a specific compatibility mode as soon as possible, to avoid
    // problems when an insert is restarted on a newer build with a newer default compat mode.
    /**
     * Returns the most recent compatibility mode understood by this build.
     *
     * <p>The value corresponds to the last declared enum constant and is used as the target when
     * normalizing {@link #COMPAT_CURRENT}. It does not necessarily match {@link #COMPAT_DEFAULT},
     * which may intentionally lag behind while new modes are rolled out.
     *
     * @return the latest known compatibility mode supported by this implementation.
     */
    public static CompatibilityMode latest() {
      return values[values.length - 1];
    }

    /**
     * Must be called whenever we accept a CompatibilityMode as e.g. a config option. Converts the
     * pseudo-current {@link #COMPAT_CURRENT} into a concrete, stable mode.
     *
     * <p>Callers that accept configuration from the outside world should invoke this method before
     * persisting or otherwise relying on a {@code CompatibilityMode} value. All non-current modes
     * are returned unchanged, so it is safe to call unconditionally.
     *
     * @return either {@link #latest()} when invoked on {@link #COMPAT_CURRENT}, or {@code this} for
     *     all other modes.
     */
    public CompatibilityMode intern() {
      if (this == COMPAT_CURRENT) return latest();
      return this;
    }

    private static final Map<Short, CompatibilityMode> modesByCode;

    static {
      HashMap<Short, CompatibilityMode> cmodes = new HashMap<>();
      for (CompatibilityMode mode : CompatibilityMode.values) {
        if (cmodes.containsKey(mode.code)) {
          throw new IllegalStateException("Duplicated compatibility mode code: " + mode.code);
        }
        cmodes.put(mode.code, mode);
      }
      modesByCode = Collections.unmodifiableMap(cmodes);
    }

    /**
     * Returns the mode associated with the given numeric code.
     *
     * <p>The mapping is primarily used for serialization and interoperation with legacy data
     * formats. Only codes that have been explicitly assigned to an enum constant are accepted;
     * callers can probe future codes via {@link #maybeFutureCode(short)} before attempting to use
     * them.
     *
     * @param code the numeric code previously obtained from {@link #code} or persisted data.
     * @return the compatibility mode corresponding to {@code code}.
     * @throws IllegalArgumentException if {@code code} does not correspond to a known mode.
     */
    public static CompatibilityMode byCode(short code) {
      if (!modesByCode.containsKey(code)) throw new IllegalArgumentException();
      return modesByCode.get(code);
    }

    /**
     * Indicates whether the supplied numeric code represents a known mode.
     *
     * <p>This is a convenience for callers that need to validate configuration or serialized data
     * before attempting to convert it with {@link #byCode(short)}.
     *
     * @param min the numeric code to test for presence in the mode table.
     * @return {@code true} if {@code min} maps to a defined mode; otherwise {@code false}.
     */
    public static boolean hasCode(short min) {
      return modesByCode.containsKey(min);
    }

    /**
     * Indicates whether the supplied code might represent a future compatibility mode.
     *
     * <p>A value is considered “maybe future” when it is numerically greater than the {@link
     * #latest()} mode. Callers can use this to distinguish between clearly invalid codes and those
     * that may become meaningful in later releases.
     *
     * @param code the numeric code to inspect.
     * @return {@code true} if {@code code} is larger than any known mode code; {@code false} if it
     *     is known or clearly invalid.
     */
    public static boolean maybeFutureCode(short code) {
      return code > latest().code;
    }

    /**
     * The default compatibility mode for new inserts when it is not specified. Usually this will be
     * COMPAT_CURRENT (it will get converted into a specific mode later), but when a new
     * compatibility mode is deployed we may want to keep this at an earlier version to avoid a
     * period when data inserted with the new/testing builds can't be fetched with earlier versions.
     */
    public static final CompatibilityMode COMPAT_DEFAULT = COMPAT_CURRENT;
  }

  /** Backward compatibility support for network level metadata. */
  private CompatibilityMode realCompatMode;

  /** Legacy numeric compatibility code preserved for deserialization. */
  private long compatibilityMode;

  /** If true, don't insert, just generate the CHK */
  private boolean getCHKOnly;

  /**
   * If true, try to find the final URI as quickly as possible, and insert the upper layers as soon
   * as we can, rather than waiting for the lower layers. The default behavior is safer, because an
   * attacker can usually only identify the datastream once he has the top block, or once you have
   * announced the key.
   */
  private boolean earlyEncode;

  /**
   * Returns the effective compatibility mode configured for this context.
   *
   * <p>The returned value is always a concrete mode; if {@link CompatibilityMode#COMPAT_CURRENT}
   * was supplied earlier, it is normalized via {@link CompatibilityMode#intern()} when stored. The
   * mode influences how splitfiles are constructed and how metadata is encoded.
   *
   * @return the concrete compatibility mode applied to this context; never {@code null} after
   *     construction.
   */
  public CompatibilityMode getCompatibilityMode() {
    return realCompatMode;
  }

  /**
   * Returns the numeric code corresponding to the current compatibility mode.
   *
   * <p>This method exposes the numeric code of {@link #getCompatibilityMode()} and is primarily
   * intended for persistence and diagnostics. Callers should prefer the enum form where possible to
   * avoid depending on the numeric representation.
   *
   * @return the numeric code of the current compatibility mode, suitable for stable serialized
   *     storage or comparison.
   */
  public long getCompatibilityCode() {
    return realCompatMode.code;
  }

  /**
   * Sets the compatibility mode for this context.
   *
   * <p>The supplied {@code mode} is normalized through {@link CompatibilityMode#intern()} so that
   * {@link CompatibilityMode#COMPAT_CURRENT} is converted to the latest known concrete mode. This
   * prevents ambiguity when requests are persisted or resumed on newer builds.
   *
   * @param mode the desired compatibility mode; {@code null} is not permitted and will cause a
   *     {@link NullPointerException} when dereferenced.
   */
  public void setCompatibilityMode(CompatibilityMode mode) {
    this.realCompatMode = mode.intern();
  }

  /**
   * Custom deserialization hook that restores transient invariants after reading the object state.
   *
   * <p>The default Java serialization mechanism reconstructs non-transient fields but may leave the
   * event producer {@code null} when loading data written by older versions. This method ensures
   * that {@link #eventProducer} is always non-null by creating a fresh {@link SimpleEventProducer}
   * when necessary.
   *
   * @param in the object input stream positioned at the start of this instance’s serialized form.
   * @throws IOException if the underlying stream encounters an I/O error while reading state.
   * @throws ClassNotFoundException if a required class definition cannot be resolved.
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (eventProducer == null) {
      eventProducer = new SimpleEventProducer();
    }
  }

  /**
   * Creates a new insert context using the supplied options.
   *
   * <p>Callers typically build an {@link InsertContextOptions} instance by selecting a baseline
   * configuration and then overriding only the fields that must differ for a particular request. No
   * validation is performed here; the caller is responsible for supplying values that are
   * meaningful for the surrounding system.
   *
   * @param options bundle of parameters that control insert behavior; must not be {@code null}.
   */
  public InsertContext(InsertContextOptions options) {
    dontCompress = false;
    splitfileAlgo = SplitfileAlgorithm.ONION_STANDARD;
    splitfileAlgorithm = splitfileAlgo.code;
    this.consecutiveRNFsCountAsSuccess = options.consecutiveRNFsCountAsSuccess();
    this.maxInsertRetries = options.maxInsertRetries();
    this.eventProducer = options.eventProducer();
    this.splitfileSegmentDataBlocks = options.splitfileSegmentDataBlocks();
    this.splitfileSegmentCheckBlocks = options.splitfileSegmentCheckBlocks();
    this.canWriteClientCache = options.canWriteClientCache();
    this.forkOnCacheable = options.forkOnCacheable();
    this.compressorDescriptor = options.compressorDescriptor();
    this.extraInsertsSingleBlock = options.extraInsertsSingleBlock();
    this.extraInsertsSplitfileHeaderBlock = options.extraInsertsSplitfileHeaderBlock();
    this.realCompatMode = options.compatibilityMode().intern();
    this.localRequestOnly = options.localRequestOnly();
    this.ignoreUSKDatehints = false;
  }

  /**
   * Creates a new context by copying configuration from an existing one but using a different event
   * producer.
   *
   * <p>This constructor is useful when callers want to reuse all operational settings while
   * separating event streams, for example when multiple independent listeners should not share the
   * same {@link SimpleEventProducer} instance.
   *
   * @param ctx source context whose configuration fields are copied.
   * @param producer the event producer to associate with the new context; must not be {@code null}.
   */
  public InsertContext(InsertContext ctx, SimpleEventProducer producer) {
    this.dontCompress = ctx.dontCompress;
    this.splitfileAlgo = ctx.splitfileAlgo;
    splitfileAlgorithm = splitfileAlgo.code;
    this.consecutiveRNFsCountAsSuccess = ctx.consecutiveRNFsCountAsSuccess;
    this.maxInsertRetries = ctx.maxInsertRetries;
    this.eventProducer = producer;
    this.splitfileSegmentDataBlocks = ctx.splitfileSegmentDataBlocks;
    this.splitfileSegmentCheckBlocks = ctx.splitfileSegmentCheckBlocks;
    this.compressorDescriptor = ctx.compressorDescriptor;
    this.forkOnCacheable = ctx.forkOnCacheable;
    this.extraInsertsSingleBlock = ctx.extraInsertsSingleBlock;
    this.extraInsertsSplitfileHeaderBlock = ctx.extraInsertsSplitfileHeaderBlock;
    this.realCompatMode = ctx.realCompatMode;
    this.localRequestOnly = ctx.localRequestOnly;
    this.ignoreUSKDatehints = ctx.ignoreUSKDatehints;
  }

  /**
   * Copy constructor. Creates a shallow copy of the provided {@code InsertContext}. The {@link
   * #eventProducer} reference is copied as-is; if a new event stream is desired, use {@link
   * #InsertContext(InsertContext, SimpleEventProducer)} instead.
   *
   * @param other source context whose configuration and behavior should be duplicated.
   */
  public InsertContext(InsertContext other) {
    this.dontCompress = other.dontCompress;
    this.splitfileAlgo = other.splitfileAlgo;
    this.splitfileAlgorithm = this.splitfileAlgo.code;
    this.maxInsertRetries = other.maxInsertRetries;
    this.consecutiveRNFsCountAsSuccess = other.consecutiveRNFsCountAsSuccess;
    this.splitfileSegmentDataBlocks = other.splitfileSegmentDataBlocks;
    this.splitfileSegmentCheckBlocks = other.splitfileSegmentCheckBlocks;
    this.eventProducer = other.eventProducer;
    this.canWriteClientCache = other.canWriteClientCache;
    this.forkOnCacheable = other.forkOnCacheable;
    this.compressorDescriptor = other.compressorDescriptor;
    this.extraInsertsSingleBlock = other.extraInsertsSingleBlock;
    this.extraInsertsSplitfileHeaderBlock = other.extraInsertsSplitfileHeaderBlock;
    this.localRequestOnly = other.localRequestOnly;
    this.ignoreUSKDatehints = other.ignoreUSKDatehints;
    this.realCompatMode = other.realCompatMode;
    this.compatibilityMode = other.compatibilityMode;
    this.getCHKOnly = other.getCHKOnly;
    this.earlyEncode = other.earlyEncode;
  }

  /**
   * Creates a shallow copy of the supplied context.
   *
   * <p>The returned instance shares the same {@link #eventProducer} reference as {@code other} but
   * has independent configuration fields. Changes to scalar properties on the copy do not affect
   * the original instance.
   *
   * @param other source context whose configuration and producer reference should be duplicated.
   * @return a new {@code InsertContext} instance that initially mirrors {@code other}.
   */
  public static InsertContext copyOf(InsertContext other) {
    return new InsertContext(other);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (canWriteClientCache ? 1231 : 1237);
    result = prime * result + realCompatMode.code;
    result =
        prime * result + ((compressorDescriptor == null) ? 0 : compressorDescriptor.hashCode());
    result = prime * result + consecutiveRNFsCountAsSuccess;
    result = prime * result + (dontCompress ? 1231 : 1237);
    // eventProducer is ignored.
    result = prime * result + extraInsertsSingleBlock;
    result = prime * result + extraInsertsSplitfileHeaderBlock;
    result = prime * result + (forkOnCacheable ? 1231 : 1237);
    result = prime * result + (ignoreUSKDatehints ? 1231 : 1237);
    result = prime * result + (localRequestOnly ? 1231 : 1237);
    result = prime * result + maxInsertRetries;
    result = prime * result + splitfileAlgo.code;
    result = prime * result + splitfileSegmentCheckBlocks;
    result = prime * result + splitfileSegmentDataBlocks;
    return result;
  }

  /**
   * Are two InsertContext's equal? Ignores the EventProducer, compares only the actual config
   * values.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    InsertContext other = (InsertContext) obj;
    if (canWriteClientCache != other.canWriteClientCache) return false;
    if (compatibilityMode != other.compatibilityMode) return false;
    if (compressorDescriptor == null) {
      if (other.compressorDescriptor != null) return false;
    } else if (!compressorDescriptor.equals(other.compressorDescriptor)) return false;
    if (consecutiveRNFsCountAsSuccess != other.consecutiveRNFsCountAsSuccess) return false;
    if (dontCompress != other.dontCompress) return false;
    // eventProducer is ignored, and assumed to be unique.
    if (extraInsertsSingleBlock != other.extraInsertsSingleBlock) return false;
    if (extraInsertsSplitfileHeaderBlock != other.extraInsertsSplitfileHeaderBlock) return false;
    if (forkOnCacheable != other.forkOnCacheable) return false;
    if (ignoreUSKDatehints != other.ignoreUSKDatehints) return false;
    if (localRequestOnly != other.localRequestOnly) return false;
    if (maxInsertRetries != other.maxInsertRetries) return false;
    if (splitfileAlgo != other.splitfileAlgo) return false;
    if (splitfileSegmentCheckBlocks != other.splitfileSegmentCheckBlocks) return false;
    return splitfileSegmentDataBlocks == other.splitfileSegmentDataBlocks;
  }

  /**
   * Returns the splitfile algorithm configured for this context.
   *
   * <p>The algorithm determines how large content is partitioned into segments and blocks. This
   * method asserts that the legacy numeric field used for migration is consistent with the enum
   * value.
   *
   * @return the splitfile algorithm that will be used when inserting data with this context.
   */
  public SplitfileAlgorithm getSplitfileAlgorithm() {
    assert splitfileAlgorithm == splitfileAlgo.code;
    return splitfileAlgo;
  }

  /**
   * Indicates whether compression is disabled for this insert.
   *
   * @return {@code true} if the context is configured to skip compression for the inserted data;
   *     {@code false} if compression is allowed.
   */
  public boolean isDontCompress() {
    return dontCompress;
  }

  /**
   * Sets whether compression should be disabled for this insert.
   *
   * @param dontCompress {@code true} to skip compression entirely; {@code false} to allow the
   *     configured compressor to operate as usual.
   */
  public void setDontCompress(boolean dontCompress) {
    this.dontCompress = dontCompress;
  }

  /**
   * Returns the maximum number of retries permitted for each block.
   *
   * @return the configured retry limit per block; negative values indicate retrying indefinitely
   *     until success or a fatal error occurs.
   */
  public int getMaxInsertRetries() {
    return maxInsertRetries;
  }

  /**
   * Updates the maximum number of retries permitted for each block.
   *
   * @param maxInsertRetries retry limit per block; negative values indicate retrying indefinitely
   *     until success or a fatal error occurs.
   */
  public void setMaxInsertRetries(int maxInsertRetries) {
    this.maxInsertRetries = maxInsertRetries;
  }

  /**
   * Returns how many route-not-found (RNF) outcomes are tolerated as success.
   *
   * @return the number of RNF results that are treated as success on very small networks.
   */
  public int getConsecutiveRNFsCountAsSuccess() {
    return consecutiveRNFsCountAsSuccess;
  }

  /**
   * Sets how many route-not-found (RNF) outcomes are tolerated as success.
   *
   * @param consecutiveRNFsCountAsSuccess number of RNFs that may occur while still treating the
   *     insert as successful overall.
   */
  @SuppressWarnings("unused")
  public void setConsecutiveRNFsCountAsSuccess(int consecutiveRNFsCountAsSuccess) {
    this.consecutiveRNFsCountAsSuccess = consecutiveRNFsCountAsSuccess;
  }

  /**
   * Returns the maximum number of data blocks per splitfile segment.
   *
   * @return the configured limit of data blocks per segment; must be non-negative.
   */
  public int getSplitfileSegmentDataBlocks() {
    return splitfileSegmentDataBlocks;
  }

  /**
   * Sets the maximum number of data blocks per splitfile segment.
   *
   * @param splitfileSegmentDataBlocks maximum number of data blocks per segment; callers should
   *     provide a non-negative value appropriate for the chosen algorithm.
   */
  @SuppressWarnings("unused")
  public void setSplitfileSegmentDataBlocks(int splitfileSegmentDataBlocks) {
    this.splitfileSegmentDataBlocks = splitfileSegmentDataBlocks;
  }

  /**
   * Returns the maximum number of check (parity) blocks per segment.
   *
   * @return the configured limit of check blocks per segment; may be reduced when fewer data blocks
   *     are present.
   */
  public int getSplitfileSegmentCheckBlocks() {
    return splitfileSegmentCheckBlocks;
  }

  /**
   * Sets the maximum number of check (parity) blocks per segment.
   *
   * @param splitfileSegmentCheckBlocks maximum number of check blocks per segment; callers should
   *     provide a non-negative value.
   */
  @SuppressWarnings("unused")
  public void setSplitfileSegmentCheckBlocks(int splitfileSegmentCheckBlocks) {
    this.splitfileSegmentCheckBlocks = splitfileSegmentCheckBlocks;
  }

  /**
   * Indicates whether this insert may write to the client cache.
   *
   * @return {@code true} if client-cache writes are permitted; {@code false} otherwise.
   */
  public boolean isCanWriteClientCache() {
    return canWriteClientCache;
  }

  /**
   * Sets whether this insert may write to the client cache.
   *
   * @param canWriteClientCache {@code true} to allow client-cache writes; {@code false} to prevent
   *     caching of this insert’s data.
   */
  public void setCanWriteClientCache(boolean canWriteClientCache) {
    this.canWriteClientCache = canWriteClientCache;
  }

  /**
   * Returns the compressor descriptor used for this insert.
   *
   * @return the descriptor string naming compressors to try, or {@code null} to indicate default
   *     compressor selection.
   */
  public String getCompressorDescriptor() {
    return compressorDescriptor;
  }

  /**
   * Sets the compressor descriptor used for this insert.
   *
   * @param compressorDescriptor descriptor string naming compressors to try; {@code null} lets the
   *     implementation fall back to its default compressor set.
   */
  public void setCompressorDescriptor(String compressorDescriptor) {
    this.compressorDescriptor = compressorDescriptor;
  }

  /**
   * Indicates whether inserts may fork additional work when results are cacheable.
   *
   * @return {@code true} if fork-on-cacheable behavior is enabled; otherwise {@code false}.
   */
  public boolean isForkOnCacheable() {
    return forkOnCacheable;
  }

  /**
   * Sets whether inserts may fork additional work when results are cacheable.
   *
   * @param forkOnCacheable {@code true} to allow additional work for cacheable inserts; {@code
   *     false} to disable this behavior.
   */
  public void setForkOnCacheable(boolean forkOnCacheable) {
    this.forkOnCacheable = forkOnCacheable;
  }

  /**
   * Returns the number of extra insert attempts for single-block inserts.
   *
   * @return the number of additional insert attempts for single-block inserts to increase
   *     redundancy.
   */
  public int getExtraInsertsSingleBlock() {
    return extraInsertsSingleBlock;
  }

  /**
   * Sets the number of extra insert attempts for single-block inserts.
   *
   * @param extraInsertsSingleBlock additional insert attempts for single-block inserts to increase
   *     redundancy; non-negative values are expected.
   */
  public void setExtraInsertsSingleBlock(int extraInsertsSingleBlock) {
    this.extraInsertsSingleBlock = extraInsertsSingleBlock;
  }

  /**
   * Returns the number of extra insert attempts for splitfile header blocks.
   *
   * @return the number of additional insert attempts reserved for splitfile header blocks.
   */
  public int getExtraInsertsSplitfileHeaderBlock() {
    return extraInsertsSplitfileHeaderBlock;
  }

  /**
   * Sets the number of extra insert attempts for splitfile header blocks.
   *
   * @param extraInsertsSplitfileHeaderBlock additional insert attempts for splitfile header blocks;
   *     non-negative values are expected.
   */
  public void setExtraInsertsSplitfileHeaderBlock(int extraInsertsSplitfileHeaderBlock) {
    this.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeaderBlock;
  }

  /**
   * Indicates whether this insert is restricted to local requests only.
   *
   * @return {@code true} if the insert must remain local; {@code false} if it may use the wider
   *     network.
   */
  public boolean isLocalRequestOnly() {
    return localRequestOnly;
  }

  /**
   * Sets whether this insert is restricted to local requests only.
   *
   * @param localRequestOnly {@code true} to restrict the insert to local requests; {@code false} to
   *     allow using the wider network.
   */
  public void setLocalRequestOnly(boolean localRequestOnly) {
    this.localRequestOnly = localRequestOnly;
  }

  /**
   * Indicates whether USK date hints are ignored for this insert.
   *
   * @return {@code true} if USK date hints are ignored; {@code false} if they are honored.
   */
  public boolean isIgnoreUSKDatehints() {
    return ignoreUSKDatehints;
  }

  /**
   * Sets whether USK date hints should be ignored for this insert.
   *
   * @param ignoreUSKDatehints {@code true} to ignore USK date hints; {@code false} to honor them
   *     when polling for the maximum edition.
   */
  public void setIgnoreUSKDatehints(boolean ignoreUSKDatehints) {
    this.ignoreUSKDatehints = ignoreUSKDatehints;
  }

  /**
   * Indicates whether this context is configured to compute only the CHK without inserting data.
   *
   * @return {@code true} if the insert should compute and return only the CHK; {@code false}
   *     otherwise.
   */
  public boolean isGetCHKOnly() {
    return getCHKOnly;
  }

  /**
   * Sets whether this context should compute only the CHK without inserting data.
   *
   * @param getCHKOnly {@code true} to compute the CHK without performing a full insert; {@code
   *     false} to perform a normal insert.
   */
  public void setGetCHKOnly(boolean getCHKOnly) {
    this.getCHKOnly = getCHKOnly;
  }

  /**
   * Indicates whether the insert should attempt to finalize the URI as early as possible.
   *
   * @return {@code true} if early encode is enabled; {@code false} if the safer default behavior is
   *     used.
   */
  public boolean isEarlyEncode() {
    return earlyEncode;
  }

  /**
   * Sets whether the insert should attempt to finalize the URI as early as possible.
   *
   * @param earlyEncode {@code true} to enable early URI determination; {@code false} to use the
   *     safer default behavior.
   */
  public void setEarlyEncode(boolean earlyEncode) {
    this.earlyEncode = earlyEncode;
  }

  /**
   * Returns the event producer used to publish client-visible events for this context.
   *
   * <p>The returned producer may be shared with other contexts. Callers can attach additional
   * listeners to receive progress and status updates, but should avoid mutating listener sets
   * concurrently from multiple threads.
   *
   * @return the non-null event producer associated with this context.
   */
  public ClientEventProducer getEventProducer() {
    return eventProducer;
  }
}
