package network.crypta.client;

import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;

/**
 * Immutable bundle of parameters used to construct a {@link FetchContext}.
 *
 * <p>Use {@link Builder} to populate the full set of values. {@link FetchContext} performs
 * validation so this class can remain a lightweight carrier of configuration.
 */
public final class FetchContextOptions {
  private final long maxOutputLength;
  private final long maxTempLength;
  private final int maxMetadataSize;
  private final int maxRecursionLevel;
  private final int maxArchiveRestarts;
  private final int maxArchiveLevels;
  private final boolean dontEnterImplicitArchives;
  private final int maxSplitfileBlockRetries;
  private final int maxNonSplitfileRetries;
  private final int maxUSKRetries;
  private final boolean allowSplitfiles;
  private final boolean followRedirects;
  private final boolean localRequestOnly;
  private final boolean filterData;
  private final int maxDataBlocksPerSegment;
  private final int maxCheckBlocksPerSegment;
  private final ClientEventProducer eventProducer;
  private final boolean ignoreTooManyPathComponents;
  private final boolean canWriteClientCache;
  private final String charset;
  private final String overrideMIME;
  private final String schemeHostAndPort;

  private FetchContextOptions(Builder builder) {
    this.maxOutputLength = builder.maxOutputLength;
    this.maxTempLength = builder.maxTempLength;
    this.maxMetadataSize = builder.maxMetadataSize;
    this.maxRecursionLevel = builder.maxRecursionLevel;
    this.maxArchiveRestarts = builder.maxArchiveRestarts;
    this.maxArchiveLevels = builder.maxArchiveLevels;
    this.dontEnterImplicitArchives = builder.dontEnterImplicitArchives;
    this.maxSplitfileBlockRetries = builder.maxSplitfileBlockRetries;
    this.maxNonSplitfileRetries = builder.maxNonSplitfileRetries;
    this.maxUSKRetries = builder.maxUSKRetries;
    this.allowSplitfiles = builder.allowSplitfiles;
    this.followRedirects = builder.followRedirects;
    this.localRequestOnly = builder.localRequestOnly;
    this.filterData = builder.filterData;
    this.maxDataBlocksPerSegment = builder.maxDataBlocksPerSegment;
    this.maxCheckBlocksPerSegment = builder.maxCheckBlocksPerSegment;
    this.eventProducer = builder.eventProducer;
    this.ignoreTooManyPathComponents = builder.ignoreTooManyPathComponents;
    this.canWriteClientCache = builder.canWriteClientCache;
    this.charset = builder.charset;
    this.overrideMIME = builder.overrideMIME;
    this.schemeHostAndPort = builder.schemeHostAndPort;
  }

  public long maxOutputLength() {
    return maxOutputLength;
  }

  public long maxTempLength() {
    return maxTempLength;
  }

  public int maxMetadataSize() {
    return maxMetadataSize;
  }

  public int maxRecursionLevel() {
    return maxRecursionLevel;
  }

  public int maxArchiveRestarts() {
    return maxArchiveRestarts;
  }

  public int maxArchiveLevels() {
    return maxArchiveLevels;
  }

  public boolean dontEnterImplicitArchives() {
    return dontEnterImplicitArchives;
  }

  public int maxSplitfileBlockRetries() {
    return maxSplitfileBlockRetries;
  }

  public int maxNonSplitfileRetries() {
    return maxNonSplitfileRetries;
  }

  public int maxUSKRetries() {
    return maxUSKRetries;
  }

  public boolean allowSplitfiles() {
    return allowSplitfiles;
  }

  public boolean followRedirects() {
    return followRedirects;
  }

  public boolean localRequestOnly() {
    return localRequestOnly;
  }

  public boolean filterData() {
    return filterData;
  }

  public int maxDataBlocksPerSegment() {
    return maxDataBlocksPerSegment;
  }

  public int maxCheckBlocksPerSegment() {
    return maxCheckBlocksPerSegment;
  }

  public ClientEventProducer eventProducer() {
    return eventProducer;
  }

  public boolean ignoreTooManyPathComponents() {
    return ignoreTooManyPathComponents;
  }

  public boolean canWriteClientCache() {
    return canWriteClientCache;
  }

  public String charset() {
    return charset;
  }

  public String overrideMIME() {
    return overrideMIME;
  }

  public String schemeHostAndPort() {
    return schemeHostAndPort;
  }

  /**
   * Returns a new builder for {@link FetchContextOptions}.
   *
   * @return builder instance for configuring fetch context parameters.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for {@link FetchContextOptions}.
   *
   * <p>The builder is mutable and not thread-safe. Callers should set each option group and then
   * call {@link #build()} to obtain an immutable snapshot.
   */
  public static final class Builder {
    private long maxOutputLength;
    private long maxTempLength;
    private int maxMetadataSize;
    private int maxRecursionLevel;
    private int maxArchiveRestarts;
    private int maxArchiveLevels;
    private boolean dontEnterImplicitArchives;
    private int maxSplitfileBlockRetries;
    private int maxNonSplitfileRetries;
    private int maxUSKRetries;
    private boolean allowSplitfiles;
    private boolean followRedirects;
    private boolean localRequestOnly;
    private boolean filterData;
    private int maxDataBlocksPerSegment;
    private int maxCheckBlocksPerSegment;
    private ClientEventProducer eventProducer = new SimpleEventProducer();
    private boolean ignoreTooManyPathComponents;
    private boolean canWriteClientCache;
    private String charset;
    private String overrideMIME;
    private String schemeHostAndPort;

    /**
     * Sets size limits for the fetch operation.
     *
     * @param maxOutputLength maximum size of the returned payload in bytes; must be non-negative.
     * @param maxTempLength maximum size of intermediary data (metadata, containers) in bytes; must
     *     be non-negative.
     * @param maxMetadataSize maximum allowed metadata size in bytes; must be non-negative.
     * @return this builder for chaining.
     */
    public Builder limits(long maxOutputLength, long maxTempLength, int maxMetadataSize) {
      this.maxOutputLength = maxOutputLength;
      this.maxTempLength = maxTempLength;
      this.maxMetadataSize = maxMetadataSize;
      return this;
    }

    /**
     * Sets recursion and archive traversal limits.
     *
     * @param maxRecursionLevel maximum recursion depth for redirects and container lookups; {@code
     *     1} means only a single block is fetched.
     * @param maxArchiveRestarts maximum number of archive restarts permitted; must be non-negative.
     * @param maxArchiveLevels maximum number of manifest lookups within containers; must be
     *     non-negative.
     * @param dontEnterImplicitArchives when {@code true}, do not descend into implicit archives on
     *     the path.
     * @return this builder for chaining.
     */
    public Builder archiveLimits(
        int maxRecursionLevel,
        int maxArchiveRestarts,
        int maxArchiveLevels,
        boolean dontEnterImplicitArchives) {
      this.maxRecursionLevel = maxRecursionLevel;
      this.maxArchiveRestarts = maxArchiveRestarts;
      this.maxArchiveLevels = maxArchiveLevels;
      this.dontEnterImplicitArchives = dontEnterImplicitArchives;
      return this;
    }

    /**
     * Sets retry limits for the request.
     *
     * @param maxSplitfileBlockRetries maximum retries for splitfile blocks; {@code -1} for
     *     unlimited, otherwise non-negative.
     * @param maxNonSplitfileRetries maximum retries for non-splitfile blocks; {@code -1} for
     *     unlimited, otherwise non-negative.
     * @param maxUSKRetries maximum retries for USK requests; {@code -1} for unlimited, otherwise
     *     non-negative.
     * @return this builder for chaining.
     */
    public Builder retryLimits(
        int maxSplitfileBlockRetries, int maxNonSplitfileRetries, int maxUSKRetries) {
      this.maxSplitfileBlockRetries = maxSplitfileBlockRetries;
      this.maxNonSplitfileRetries = maxNonSplitfileRetries;
      this.maxUSKRetries = maxUSKRetries;
      return this;
    }

    /**
     * Sets splitfile limits for block segmentation.
     *
     * @param allowSplitfiles whether splitfiles are allowed to be downloaded.
     * @param maxDataBlocksPerSegment maximum allowed data blocks per splitfile segment; must be
     *     within codec bounds.
     * @param maxCheckBlocksPerSegment maximum allowed check blocks per splitfile segment; must be
     *     within codec bounds.
     * @return this builder for chaining.
     */
    public Builder splitfileLimits(
        boolean allowSplitfiles, int maxDataBlocksPerSegment, int maxCheckBlocksPerSegment) {
      this.allowSplitfiles = allowSplitfiles;
      this.maxDataBlocksPerSegment = maxDataBlocksPerSegment;
      this.maxCheckBlocksPerSegment = maxCheckBlocksPerSegment;
      return this;
    }

    /**
     * Sets redirect, locality, and filtering behavior.
     *
     * @param followRedirects whether simple redirects may be followed by the fetcher.
     * @param localRequestOnly whether the request must be satisfied from local stores only.
     * @param filterData whether the content filter should be applied to fetched data.
     * @return this builder for chaining.
     */
    public Builder behavior(boolean followRedirects, boolean localRequestOnly, boolean filterData) {
      this.followRedirects = followRedirects;
      this.localRequestOnly = localRequestOnly;
      this.filterData = filterData;
      return this;
    }

    /**
     * Sets event and cache-related options.
     *
     * <p>If this method is not called, the builder will use a new {@link SimpleEventProducer}.
     *
     * @param eventProducer event producer to receive client events; must not be {@code null}.
     * @param ignoreTooManyPathComponents whether to ignore excess path components during
     *     resolution.
     * @param canWriteClientCache whether the client cache may be written by this request.
     * @return this builder for chaining.
     */
    public Builder clientOptions(
        ClientEventProducer eventProducer,
        boolean ignoreTooManyPathComponents,
        boolean canWriteClientCache) {
      if (eventProducer == null) {
        throw new IllegalArgumentException("eventProducer must not be null");
      }
      this.eventProducer = eventProducer;
      this.ignoreTooManyPathComponents = ignoreTooManyPathComponents;
      this.canWriteClientCache = canWriteClientCache;
      return this;
    }

    /**
     * Sets filter override hints for the request.
     *
     * @param charset optional charset to assume for filtration when needed; {@code null} to use
     *     defaults.
     * @param overrideMIME optional MIME type to force for the content filter; {@code null} to
     *     clear.
     * @param schemeHostAndPort optional forced URI prefix in the form {@code scheme://host:port}.
     * @return this builder for chaining.
     */
    public Builder filterOverrides(String charset, String overrideMIME, String schemeHostAndPort) {
      this.charset = charset;
      this.overrideMIME = overrideMIME;
      this.schemeHostAndPort = schemeHostAndPort;
      return this;
    }

    /**
     * Builds an immutable {@link FetchContextOptions} snapshot from the builder values.
     *
     * @return new options instance capturing the current builder state.
     */
    public FetchContextOptions build() {
      return new FetchContextOptions(this);
    }
  }
}
