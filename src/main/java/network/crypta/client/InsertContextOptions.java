package network.crypta.client;

import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;

/**
 * Immutable bundle of parameters used to construct an {@link InsertContext}.
 *
 * <p>Use {@link Builder} to populate the full set of values. {@link InsertContext} performs no
 * validation, so callers are responsible for supplying values that are meaningful for their
 * environment.
 */
public final class InsertContextOptions {
  private final int maxInsertRetries;
  private final int consecutiveRNFsCountAsSuccess;
  private final int splitfileSegmentDataBlocks;
  private final int splitfileSegmentCheckBlocks;
  private final ClientEventProducer eventProducer;
  private final boolean canWriteClientCache;
  private final boolean forkOnCacheable;
  private final boolean localRequestOnly;
  private final String compressorDescriptor;
  private final int extraInsertsSingleBlock;
  private final int extraInsertsSplitfileHeaderBlock;
  private final InsertContext.CompatibilityMode compatibilityMode;

  private InsertContextOptions(Builder builder) {
    this.maxInsertRetries = builder.maxInsertRetries;
    this.consecutiveRNFsCountAsSuccess = builder.consecutiveRNFsCountAsSuccess;
    this.splitfileSegmentDataBlocks = builder.splitfileSegmentDataBlocks;
    this.splitfileSegmentCheckBlocks = builder.splitfileSegmentCheckBlocks;
    this.eventProducer = builder.eventProducer;
    this.canWriteClientCache = builder.canWriteClientCache;
    this.forkOnCacheable = builder.forkOnCacheable;
    this.localRequestOnly = builder.localRequestOnly;
    this.compressorDescriptor = builder.compressorDescriptor;
    this.extraInsertsSingleBlock = builder.extraInsertsSingleBlock;
    this.extraInsertsSplitfileHeaderBlock = builder.extraInsertsSplitfileHeaderBlock;
    this.compatibilityMode = builder.compatibilityMode;
  }

  public int maxInsertRetries() {
    return maxInsertRetries;
  }

  public int consecutiveRNFsCountAsSuccess() {
    return consecutiveRNFsCountAsSuccess;
  }

  public int splitfileSegmentDataBlocks() {
    return splitfileSegmentDataBlocks;
  }

  public int splitfileSegmentCheckBlocks() {
    return splitfileSegmentCheckBlocks;
  }

  public ClientEventProducer eventProducer() {
    return eventProducer;
  }

  public boolean canWriteClientCache() {
    return canWriteClientCache;
  }

  public boolean forkOnCacheable() {
    return forkOnCacheable;
  }

  public boolean localRequestOnly() {
    return localRequestOnly;
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

  public InsertContext.CompatibilityMode compatibilityMode() {
    return compatibilityMode;
  }

  /**
   * Returns a new builder for {@link InsertContextOptions}.
   *
   * @return builder instance for configuring insert context parameters.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for {@link InsertContextOptions}.
   *
   * <p>The builder is mutable and not thread-safe. Callers should set each option group and then
   * call {@link #build()} to obtain an immutable snapshot.
   */
  public static final class Builder {
    private int maxInsertRetries;
    private int consecutiveRNFsCountAsSuccess;
    private int splitfileSegmentDataBlocks;
    private int splitfileSegmentCheckBlocks;
    private ClientEventProducer eventProducer = new SimpleEventProducer();
    private boolean canWriteClientCache;
    private boolean forkOnCacheable;
    private boolean localRequestOnly;
    private String compressorDescriptor;
    private int extraInsertsSingleBlock;
    private int extraInsertsSplitfileHeaderBlock;
    private InsertContext.CompatibilityMode compatibilityMode =
        InsertContext.CompatibilityMode.COMPAT_DEFAULT;

    /**
     * Sets retry limits for the insert.
     *
     * @param maxInsertRetries maximum retries per block; {@code -1} for unlimited retries.
     * @param consecutiveRNFsCountAsSuccess number of route-not-found results that still count as
     *     success on very small networks.
     * @return this builder for chaining.
     */
    public Builder retryLimits(int maxInsertRetries, int consecutiveRNFsCountAsSuccess) {
      this.maxInsertRetries = maxInsertRetries;
      this.consecutiveRNFsCountAsSuccess = consecutiveRNFsCountAsSuccess;
      return this;
    }

    /**
     * Sets splitfile segment sizing limits.
     *
     * @param splitfileSegmentDataBlocks maximum data blocks per segment.
     * @param splitfileSegmentCheckBlocks maximum check blocks per segment.
     * @return this builder for chaining.
     */
    public Builder splitfileSegmentLimits(
        int splitfileSegmentDataBlocks, int splitfileSegmentCheckBlocks) {
      this.splitfileSegmentDataBlocks = splitfileSegmentDataBlocks;
      this.splitfileSegmentCheckBlocks = splitfileSegmentCheckBlocks;
      return this;
    }

    /**
     * Sets client-facing behavior flags and the event producer.
     *
     * @param eventProducer producer used to publish insert events; may be {@code null}.
     * @param canWriteClientCache whether inserted data may be written to the client cache.
     * @param forkOnCacheable whether inserts may fork when results are cacheable.
     * @param localRequestOnly whether inserts must remain local to the node.
     * @return this builder for chaining.
     */
    public Builder clientOptions(
        ClientEventProducer eventProducer,
        boolean canWriteClientCache,
        boolean forkOnCacheable,
        boolean localRequestOnly) {
      this.eventProducer = eventProducer;
      this.canWriteClientCache = canWriteClientCache;
      this.forkOnCacheable = forkOnCacheable;
      this.localRequestOnly = localRequestOnly;
      return this;
    }

    /**
     * Sets the compressor descriptor string.
     *
     * @param compressorDescriptor descriptor string naming compressors to try.
     * @return this builder for chaining.
     */
    public Builder compressorDescriptor(String compressorDescriptor) {
      this.compressorDescriptor = compressorDescriptor;
      return this;
    }

    /**
     * Sets redundancy parameters for extra insert attempts.
     *
     * @param extraInsertsSingleBlock extra inserts for single-block payloads.
     * @param extraInsertsSplitfileHeaderBlock extra inserts for splitfile header blocks.
     * @return this builder for chaining.
     */
    public Builder redundancy(int extraInsertsSingleBlock, int extraInsertsSplitfileHeaderBlock) {
      this.extraInsertsSingleBlock = extraInsertsSingleBlock;
      this.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeaderBlock;
      return this;
    }

    /**
     * Sets the compatibility mode for the insert.
     *
     * @param compatibilityMode compatibility mode used to shape metadata and block layout.
     * @return this builder for chaining.
     */
    public Builder compatibility(InsertContext.CompatibilityMode compatibilityMode) {
      this.compatibilityMode = compatibilityMode;
      return this;
    }

    /**
     * Builds a new immutable {@link InsertContextOptions} instance.
     *
     * @return configured {@link InsertContextOptions} snapshot.
     */
    public InsertContextOptions build() {
      return new InsertContextOptions(this);
    }
  }
}
