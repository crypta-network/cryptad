package network.crypta.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import network.crypta.client.async.BlockSet;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.FoundURICallback;
import network.crypta.client.filter.TagReplacerCallback;
import network.crypta.node.RequestScheduler;
import network.crypta.support.io.StorageFormatException;

/**
 * Mutable configuration for a single client fetch operation.
 *
 * <p>This class aggregates all tunables that influence how a request is executed: limits for data
 * and metadata, recursion and archive handling, retry behavior, filtering and caching flags,
 * network locality, and serialization support to persist and later reconstruct an identical
 * context. Typical call patterns are:
 *
 * <ol>
 *   <li>Create a context with explicit limits using the main constructor, or start from a library
 *       default via {@code HighLevelSimpleClientImpl.makeDefaultFetchContext(...)}.
 *   <li>Optionally adjust individual flags (for example {@link #setFollowRedirects(boolean)},
 *       {@link #setFilterData(boolean)}, {@link #setMaxRecursionLevel(int)}).
 *   <li>Persist with {@link #writeTo(java.io.DataOutputStream)} or reconstruct with {@link
 *       #FetchContext(java.io.DataInputStream)} when resuming a request.
 * </ol>
 *
 * <p>Instances are mutable and not thread-safe. A context is intended to be owned by a single
 * request at a time; copying is supported via the masking constructors to derive variants for
 * sub-operations (for example fetching a container member). Invariants include non‑negative sizes
 * and retry counts (or {@code -1} for unlimited retries where supported). Cooldown settings are
 * bounded by constants in {@link RequestScheduler}.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Retry semantics differ for splitfile and non‑splitfile blocks, with {@code -1} meaning
 *       unbounded retries until success or a fatal error.
 *   <li>Archive navigation limits apply to manifest lookups within container formats.
 *   <li>When filtering is enabled, allowed MIME types and an optional override MIME/charset may
 *       constrain processing.
 * </ul>
 *
 * @see RequestScheduler
 * @see HighLevelSimpleClientImpl
 */
public class FetchContext implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /** Mask value that produces a copy identical to the source context. */
  public static final int IDENTICAL_MASK = 0;

  /**
   * Mask value that constrains the copy for a single splitfile block: one level only, no redirects,
   * and no archive traversal.
   */
  public static final int SPLITFILE_DEFAULT_BLOCK_MASK = 1;

  /** Mask value that applies default splitfile settings for multi‑block operations. */
  public static final int SPLITFILE_DEFAULT_MASK = 2;

  /** Mask bit that forces ZIP manifest returns when copying a context. */
  public static final int SET_RETURN_ARCHIVES = 4;

  /** Maximum length of the final returned data */
  private long maxOutputLength;

  /**
   * Maximum length of data fetched in order to obtain the final data - metadata, containers, etc.
   */
  private long maxTempLength;

  /**
   * 1 = only fetch a single block. 2 = allow one redirect, e.g. metadata block pointing to actual
   * data block. Etc. 0 may work sometimes but is not recommended.
   */
  private int maxRecursionLevel;

  /** Maximum number of times an archive read may be restarted. */
  private int maxArchiveRestarts;

  /**
   * Maximum number of manifest lookups during a request. A manifest lookup is looking up a part of
   * a pathname in a "manifest", which is essentially a directory (folder). Usually manifest lookups
   * are inside containers (archives), which are usually tar files, which may or may not be
   * compressed (compression occurs transparently on a different level). This is not necessarily the
   * same as the number of slashes in the key after the part for the key itself, since keys can
   * redirect to other keys. If you are fetching user-uploaded keys, e.g. in fproxy, especially
   * freesites, you will want this to be non-zero. However, if you are using keys only internally,
   * and never upload freesites, you should set this to 0.
   *
   * @see ArchiveContext where this is enforced.
   */
  private int maxArchiveLevels;

  /** When true, avoid entering implicit archives discovered during traversal. */
  private boolean dontEnterImplicitArchives;

  /**
   * Maximum number of retries (after the original attempt) for a splitfile block. -1 = try forever
   * or until success or a fatal error. A fatal error is either an internal error (problem with the
   * node) or something resulting from the original data being corrupt as inserted. So with retries
   * = -1 we will not report Data not found, Route not found, All data not found, etc., because
   * these are nonfatal errors and we will retry. Note that after every 3 attempts the request is
   * put on the cooldown queue for 30 minutes, so the cost of retries = -1 is really not that high.
   */
  private int maxSplitfileBlockRetries;

  /**
   * Maximum number of retries (after the original attempt) for a non-splitfile block. -1 = try
   * forever or until success or a fatal error. -1 = try forever or until success or a fatal error.
   * A fatal error is either an internal error (problem with the node) or something resulting from
   * the original data being corrupt as inserted. So with retries = -1 we will not report Data not
   * found, Route not found, All data not found, etc., because these are nonfatal errors and we will
   * retry. Note that after every 3 attempts the request is put on the cooldown queue for 30
   * minutes, so the cost of retries = -1 is really not that high.
   */
  private int maxNonSplitfileRetries;

  /** Maximum number of retries allowed for USK requests; {@code -1} means unlimited. */
  public final int maxUSKRetries;

  /** Whether to download splitfiles */
  private boolean allowSplitfiles;

  /** Whether to follow simple redirects */
  private boolean followRedirects;

  /** If true, only read from the datastore and caches, do not send the request to the network */
  private boolean localRequestOnly;

  /**
   * If true, send the request to the network without checking whether the data is in the local
   * store
   */
  private boolean ignoreStore;

  /** Client events will be published to this, you can subscribe to them */
  private final transient ClientEventProducer eventProducer;

  /** Maximum metadata size permitted for the request, in bytes. */
  private int maxMetadataSize;

  /** Maximum number of data blocks per segment for splitfiles */
  private int maxDataBlocksPerSegment;

  /** Maximum number of check blocks per segment for splitfiles. */
  private int maxCheckBlocksPerSegment;

  /**
   * If true, and we get a ZIP manifest, and we have no meta-strings left, then return the manifest
   * contents as data.
   */
  private boolean returnZIPManifests;

  /** When true, the fetched data is passed through the content filter. */
  private boolean filterData;

  /** Whether to ignore path components beyond an internal threshold during resolution. */
  public final boolean ignoreTooManyPathComponents;

  /** If set, contains a set of blocks to be consulted before checking the datastore. */
  public final transient BlockSet blocks;

  /**
   * If non-null, the request will be stopped if it has a MIME type that is not one of these, or has
   * no MIME type.
   */
  private transient Set<String> allowedMIMETypes;

  /**
   * If not-null, the request, if it requires a charset for filtration, will be assumed to use this
   * charset
   */
  private String charset;

  /** Do we have responsibility for removing the ClientEventProducer from the database? */
  private final boolean hasOwnEventProducer;

  /**
   * Can this request write to the client-cache? We don't store all requests in the client cache, in
   * particular big stuff usually isn't written to it, to maximise its effectiveness.
   */
  private boolean canWriteClientCache;

  /** Prefetch hook for HTML documents. Only really necessary for FProxy's web-pushing */
  private transient FoundURICallback prefetchHook;

  /** Callback needed for web-pushing */
  private transient TagReplacerCallback tagReplacer;

  /** Force the content fiter to use this MIME type */
  private String overrideMIME;

  /**
   * Number of attempts before we go into cooldown. Must be less than or equal to
   * RequestScheduler.COOLDOWN_RETRIES.
   */
  private int cooldownRetries;

  /**
   * Time period for which we go into cooldown. Must be NO LESS THAN
   * RequestScheduler.COOLDOWN_PERIOD, because ULPRs will ensure rapid success with that interval or
   * less.
   */
  private long cooldownTime;

  /** Ignore USK DATEHINTs */
  private boolean ignoreUSKDatehints;

  /**
   * scheme, host and port: force the prefix of a URI. Example: <a
   * href="https://localhost:1234">https://localhost:1234</a>
   */
  private final String schemeHostAndPort;

  /**
   * Construct a new fetch context with explicit limits and behavior flags.
   *
   * <p>Every numeric limit must be non‑negative unless documented to accept {@code -1} for
   * "unlimited". Values are validated and an {@link IllegalArgumentException} is thrown when a
   * constraint is violated. The supplied {@code producer} is used for client events emitted during
   * the request.
   *
   * @param curMaxLength Maximum size of the returned payload in bytes; must be non‑negative.
   * @param curMaxTempLength Maximum size of intermediary data (metadata, containers) in bytes; must
   *     be non‑negative.
   * @param maxMetadataSize Maximum allowed metadata size in bytes; must be non‑negative.
   * @param maxRecursionLevel Maximum recursion depth for redirects and container lookups; {@code 1}
   *     means only a single block is fetched.
   * @param maxArchiveRestarts Maximum number of archive restarts permitted; must be non‑negative.
   * @param maxArchiveLevels Maximum number of manifest lookups within containers; must be
   *     non‑negative.
   * @param dontEnterImplicitArchives When {@code true}, do not descend into implicit archives on
   *     the path.
   * @param maxSplitfileBlockRetries Maximum retries for splitfile blocks; {@code -1} for unlimited,
   *     otherwise non‑negative.
   * @param maxNonSplitfileRetries Maximum retries for non‑splitfile blocks; {@code -1} for
   *     unlimited, otherwise non‑negative.
   * @param maxUSKRetries Maximum retries for USK requests; {@code -1} for unlimited, otherwise
   *     non‑negative.
   * @param allowSplitfiles Whether splitfiles are allowed to be downloaded.
   * @param followRedirects Whether simple redirects may be followed by the fetcher.
   * @param localRequestOnly Whether the request must be satisfied from local stores only.
   * @param filterData Whether the content filter should be applied to fetched data.
   * @param maxDataBlocksPerSegment Maximum allowed data blocks per splitfile segment; must be
   *     within codec bounds.
   * @param maxCheckBlocksPerSegment Maximum allowed check blocks per splitfile segment; must be
   *     within codec bounds.
   * @param producer Event producer to receive client events; must not be {@code null}.
   * @param ignoreTooManyPathComponents Whether to ignore excess path components during resolution.
   * @param canWriteClientCache Whether the client cache may be written by this request.
   * @param charset Optional charset to assume for filtration when needed; {@code null} to use
   *     defaults.
   * @param overrideMIME Optional MIME type to force for the content filter; {@code null} to clear.
   * @param schemeHostAndPort Optional forced URI prefix in the form {@code scheme://host:port}.
   */
  public FetchContext(
      long curMaxLength,
      long curMaxTempLength,
      int maxMetadataSize,
      int maxRecursionLevel,
      int maxArchiveRestarts,
      int maxArchiveLevels,
      boolean dontEnterImplicitArchives,
      int maxSplitfileBlockRetries,
      int maxNonSplitfileRetries,
      int maxUSKRetries,
      boolean allowSplitfiles,
      boolean followRedirects,
      boolean localRequestOnly,
      boolean filterData,
      int maxDataBlocksPerSegment,
      int maxCheckBlocksPerSegment,
      ClientEventProducer producer,
      boolean ignoreTooManyPathComponents,
      boolean canWriteClientCache,
      String charset,
      String overrideMIME,
      String schemeHostAndPort) {
    this.blocks = null;
    this.maxOutputLength = curMaxLength;
    if (maxOutputLength < 0) throw new IllegalArgumentException("Bad max output length");
    this.maxTempLength = curMaxTempLength;
    if (maxTempLength < 0) throw new IllegalArgumentException("Bad max temp length");
    this.maxMetadataSize = maxMetadataSize;
    if (maxMetadataSize < 0) throw new IllegalArgumentException("Bad max metadata size");
    this.maxRecursionLevel = maxRecursionLevel;
    if (maxRecursionLevel < 0) throw new IllegalArgumentException("Bad max recursion level");
    this.maxArchiveRestarts = maxArchiveRestarts;
    if (maxArchiveRestarts < 0) throw new IllegalArgumentException("Bad max archive restarts");
    this.maxArchiveLevels = maxArchiveLevels;
    if (maxArchiveLevels < 0) throw new IllegalArgumentException("Bad max archive levels");
    this.dontEnterImplicitArchives = dontEnterImplicitArchives;
    this.maxSplitfileBlockRetries = maxSplitfileBlockRetries;
    if (maxSplitfileBlockRetries < -1)
      throw new IllegalArgumentException("Bad max splitfile block retries");
    this.maxNonSplitfileRetries = maxNonSplitfileRetries;
    if (maxNonSplitfileRetries < -1)
      throw new IllegalArgumentException("Bad non-splitfile retries");
    this.maxUSKRetries = maxUSKRetries;
    if (maxUSKRetries < -1) throw new IllegalArgumentException("Bad max USK retries");
    this.allowSplitfiles = allowSplitfiles;
    this.followRedirects = followRedirects;
    this.localRequestOnly = localRequestOnly;
    this.eventProducer = producer;
    this.maxDataBlocksPerSegment = maxDataBlocksPerSegment;
    if (maxDataBlocksPerSegment < 0
        || maxDataBlocksPerSegment > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new IllegalArgumentException("Bad max blocks per segment");
    this.maxCheckBlocksPerSegment = maxCheckBlocksPerSegment;
    if (maxCheckBlocksPerSegment < 0
        || maxCheckBlocksPerSegment > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new IllegalArgumentException("Bad max blocks per segment");
    this.filterData = filterData;
    this.ignoreTooManyPathComponents = ignoreTooManyPathComponents;
    this.canWriteClientCache = canWriteClientCache;
    this.charset = charset;
    this.overrideMIME = overrideMIME;
    this.cooldownRetries = RequestScheduler.COOLDOWN_RETRIES;
    this.cooldownTime = RequestScheduler.COOLDOWN_PERIOD;
    // Default behavior: do not ignore USK DATEHINTs.
    this.ignoreUSKDatehints = false;
    hasOwnEventProducer = true;
    this.schemeHostAndPort = schemeHostAndPort;
  }

  /**
   * Copy a FetchContext, creating a new EventProducer and not changing the blocks list.
   *
   * @param ctx The old FetchContext to copy.
   * @param maskID Mask mode for the copy operation e.g. SPLITFILE_DEFAULT_BLOCK_MASK.
   */
  public FetchContext(FetchContext ctx, int maskID) {
    this(ctx, maskID, false, null);
  }

  /**
   * Copy a FetchContext.
   *
   * @param ctx The old FetchContext to copy.
   * @param maskID Mask mode for the copy operation e.g. SPLITFILE_DEFAULT_BLOCK_MASK.
   * @param keepProducer If true, keep the existing EventProducer. Must be false if we are creating
   *     a new request. Can be true if we are masking the FetchContext within a single request, e.g.
   *     to download a container. This is important so that we see the progress updates for the
   *     request and not for other requests sharing the FetchContext, but also it could break
   *     serialization.
   * @param blocks Storing a BlockSet to the database is not supported, see comments on
   *     SimpleBlockSet.objectCanNew().
   */
  public FetchContext(FetchContext ctx, int maskID, boolean keepProducer, BlockSet blocks) {
    if (keepProducer) this.eventProducer = ctx.eventProducer;
    else this.eventProducer = new SimpleEventProducer();
    hasOwnEventProducer = !keepProducer;
    this.ignoreTooManyPathComponents = ctx.ignoreTooManyPathComponents;
    if (blocks != null) this.blocks = blocks;
    else this.blocks = ctx.blocks;

    this.allowedMIMETypes = ctx.allowedMIMETypes;
    this.maxUSKRetries = ctx.maxUSKRetries;
    this.localRequestOnly = ctx.localRequestOnly;
    this.ignoreStore = ctx.ignoreStore;
    this.maxArchiveLevels = ctx.maxArchiveLevels;
    this.maxMetadataSize = ctx.maxMetadataSize;
    this.maxNonSplitfileRetries = ctx.maxNonSplitfileRetries;
    this.maxOutputLength = ctx.maxOutputLength;
    this.maxSplitfileBlockRetries = ctx.maxSplitfileBlockRetries;
    this.maxTempLength = ctx.maxTempLength;
    this.allowSplitfiles = ctx.allowSplitfiles;
    this.dontEnterImplicitArchives = ctx.dontEnterImplicitArchives;
    this.followRedirects = ctx.followRedirects;
    this.maxArchiveRestarts = ctx.maxArchiveRestarts;
    this.maxCheckBlocksPerSegment = ctx.maxCheckBlocksPerSegment;
    this.maxDataBlocksPerSegment = ctx.maxDataBlocksPerSegment;
    this.filterData = ctx.filterData;
    this.maxRecursionLevel = ctx.maxRecursionLevel;
    this.returnZIPManifests = ctx.returnZIPManifests;
    this.canWriteClientCache = ctx.canWriteClientCache;
    this.charset = ctx.charset;
    this.prefetchHook = ctx.prefetchHook;
    this.tagReplacer = ctx.tagReplacer;
    this.overrideMIME = ctx.overrideMIME;
    this.cooldownRetries = ctx.cooldownRetries;
    this.cooldownTime = ctx.cooldownTime;
    this.ignoreUSKDatehints = ctx.ignoreUSKDatehints;
    this.schemeHostAndPort = ctx.schemeHostAndPort;

    switch (maskID) {
      case IDENTICAL_MASK, SPLITFILE_DEFAULT_MASK -> {
        // default: no changes
      }
      case SPLITFILE_DEFAULT_BLOCK_MASK -> {
        this.maxRecursionLevel = 1;
        this.maxArchiveRestarts = 0;
        this.dontEnterImplicitArchives = true;
        this.allowSplitfiles = false;
        this.followRedirects = false;
        this.maxDataBlocksPerSegment = 0;
        this.maxCheckBlocksPerSegment = 0;
        this.returnZIPManifests = false;
      }
      case SET_RETURN_ARCHIVES -> this.returnZIPManifests = true;
      default -> throw new IllegalArgumentException();
    }
  }

  /**
   * Set how many attempts are allowed before entering cooldown.
   *
   * @param cooldownRetries Number of tries before cooldown; must be between {@code 0} and {@link
   *     RequestScheduler#COOLDOWN_RETRIES} inclusive.
   * @throws IllegalArgumentException if the value is negative or exceeds the scheduler bound.
   */
  public void setCooldownRetries(int cooldownRetries) {
    if (cooldownRetries < 0) throw new IllegalArgumentException("Bogus negative retries");
    if (cooldownRetries > RequestScheduler.COOLDOWN_RETRIES)
      throw new IllegalArgumentException(
          "Invalid COOLDOWN_RETRIES: Must be <= "
              + RequestScheduler.COOLDOWN_RETRIES
              + " since the network will not tolerate more than that");
    this.cooldownRetries = cooldownRetries;
  }

  /**
   * Set the cooldown time window in milliseconds.
   *
   * @param cooldownTime Duration of cooldown in milliseconds; must be non‑negative and typically
   *     not less than {@link RequestScheduler#COOLDOWN_PERIOD}.
   * @throws IllegalArgumentException if negative or below the minimum when not forced.
   */
  public void setCooldownTime(long cooldownTime) {
    setCooldownTime(cooldownTime, false);
  }

  /**
   * Set the cooldown time window, with a testing override.
   *
   * @param cooldownTime Duration of cooldown in milliseconds; must be non‑negative.
   * @param force When {@code true}, bypasses the minimum period guard for testing scenarios only.
   * @throws IllegalArgumentException if the time is negative or violates the minimum when {@code
   *     force} is {@code false}.
   */
  public void setCooldownTime(long cooldownTime, boolean force) {
    if (cooldownTime < 0) throw new IllegalArgumentException("Bogus negative cooldown time");
    if (cooldownTime < RequestScheduler.COOLDOWN_PERIOD && !force)
      throw new IllegalArgumentException(
          "Invalid COOLDOWN_PERIOD: Must be >= "
              + RequestScheduler.COOLDOWN_PERIOD
              + " since ULPRs will ensure fast response at that level");
    this.cooldownTime = cooldownTime;
  }

  /**
   * Get the number of attempts permitted before entering cooldown.
   *
   * @return Allowed attempts before a request is placed on cooldown.
   */
  public int getCooldownRetries() {
    return cooldownRetries;
  }

  /**
   * Get the maximum length of the final returned data, in bytes.
   *
   * @return Upper bound for the payload size in bytes.
   */
  public long getMaxOutputLength() {
    return maxOutputLength;
  }

  /**
   * Set the maximum length of the final returned data, in bytes.
   *
   * @param maxOutputLength Upper bound for the returned payload size; must be non‑negative.
   */
  public void setMaxOutputLength(long maxOutputLength) {
    this.maxOutputLength = maxOutputLength;
  }

  /**
   * Get the maximum length of intermediary data (metadata, containers), in bytes.
   *
   * @return Upper bound for intermediate fetches in bytes.
   */
  public long getMaxTempLength() {
    return maxTempLength;
  }

  /**
   * Set the maximum length of intermediary data (metadata, containers), in bytes.
   *
   * @param maxTempLength Upper bound for temporary fetches; must be non‑negative.
   */
  public void setMaxTempLength(long maxTempLength) {
    this.maxTempLength = maxTempLength;
  }

  /**
   * Get the maximum recursion depth allowed for redirects and container lookups.
   *
   * @return Depth limit; {@code 1} fetches only a single block.
   */
  public int getMaxRecursionLevel() {
    return maxRecursionLevel;
  }

  /**
   * Set the maximum recursion depth for redirects and container lookups.
   *
   * @param maxRecursionLevel Depth of recursion; {@code 1} fetches only a single block.
   */
  public void setMaxRecursionLevel(int maxRecursionLevel) {
    this.maxRecursionLevel = maxRecursionLevel;
  }

  /**
   * Get the maximum number of archive restarts permitted.
   *
   * @return Non‑negative count of allowed restarts.
   */
  public int getMaxArchiveRestarts() {
    return maxArchiveRestarts;
  }

  /**
   * Set the maximum number of archive restarts permitted.
   *
   * @param maxArchiveRestarts Non‑negative count of allowed restarts while parsing archives.
   */
  public void setMaxArchiveRestarts(int maxArchiveRestarts) {
    this.maxArchiveRestarts = maxArchiveRestarts;
  }

  /**
   * Get the maximum number of manifest lookups allowed within containers.
   *
   * @return Non‑negative count of directory level lookups.
   */
  public int getMaxArchiveLevels() {
    return maxArchiveLevels;
  }

  /**
   * Set the maximum number of manifest lookups allowed within containers.
   *
   * @param maxArchiveLevels Non‑negative count of directory level lookups within archives.
   */
  public void setMaxArchiveLevels(int maxArchiveLevels) {
    this.maxArchiveLevels = maxArchiveLevels;
  }

  /**
   * Whether implicit archives should be avoided during traversal.
   *
   * @return {@code true} when implicit archives are not entered.
   */
  public boolean getDontEnterImplicitArchives() {
    return dontEnterImplicitArchives;
  }

  /**
   * Control whether implicit archives discovered during traversal may be entered.
   *
   * @param dontEnterImplicitArchives When {@code true}, do not descend into implicit archives.
   */
  public void setDontEnterImplicitArchives(boolean dontEnterImplicitArchives) {
    this.dontEnterImplicitArchives = dontEnterImplicitArchives;
  }

  /**
   * Get the maximum number of retries for a splitfile block (or {@code -1} for unlimited).
   *
   * @return Retry limit for splitfile blocks, or {@code -1} for unbounded.
   */
  public int getMaxSplitfileBlockRetries() {
    return maxSplitfileBlockRetries;
  }

  /**
   * Set the maximum number of retries for a splitfile block.
   *
   * @param maxSplitfileBlockRetries {@code -1} for unlimited retries; otherwise a non‑negative
   *     count.
   */
  public void setMaxSplitfileBlockRetries(int maxSplitfileBlockRetries) {
    this.maxSplitfileBlockRetries = maxSplitfileBlockRetries;
  }

  /**
   * Get the maximum number of retries for a non‑splitfile block (or {@code -1} for unlimited).
   *
   * @return Retry limit for non‑splitfile blocks, or {@code -1} for unbounded.
   */
  public int getMaxNonSplitfileRetries() {
    return maxNonSplitfileRetries;
  }

  /**
   * Set the maximum number of retries for a non‑splitfile block.
   *
   * @param maxNonSplitfileRetries {@code -1} for unlimited retries; otherwise a non‑negative count.
   */
  public void setMaxNonSplitfileRetries(int maxNonSplitfileRetries) {
    this.maxNonSplitfileRetries = maxNonSplitfileRetries;
  }

  /**
   * Get the maximum number of retries for USK requests (or {@code -1} for unlimited).
   *
   * @return Retry limit for USK requests, or {@code -1} for unbounded.
   */
  @SuppressWarnings("unused")
  public int getMaxUSKRetries() {
    return maxUSKRetries;
  }

  /**
   * Whether splitfiles are allowed to be downloaded during this request.
   *
   * @return {@code true} when splitfile retrieval is permitted.
   */
  public boolean getAllowSplitfiles() {
    return allowSplitfiles;
  }

  /**
   * Control whether splitfiles are allowed to be downloaded during this request.
   *
   * @param allowSplitfiles {@code true} to allow splitfile retrieval, {@code false} to disallow.
   */
  public void setAllowSplitfiles(boolean allowSplitfiles) {
    this.allowSplitfiles = allowSplitfiles;
  }

  /**
   * Whether simple redirects are followed by the fetcher.
   *
   * @return {@code true} when redirects are followed automatically.
   */
  public boolean getFollowRedirects() {
    return followRedirects;
  }

  /**
   * Control whether simple redirects are followed by the fetcher.
   *
   * @param followRedirects {@code true} to follow redirects; {@code false} to disable following.
   */
  public void setFollowRedirects(boolean followRedirects) {
    this.followRedirects = followRedirects;
  }

  /**
   * Whether the request must be satisfied from local stores without network access.
   *
   * @return {@code true} for local‑only requests; otherwise {@code false}.
   */
  public boolean getLocalRequestOnly() {
    return localRequestOnly;
  }

  /**
   * Control whether the request must be satisfied from local stores only.
   *
   * @param localRequestOnly {@code true} to avoid network access; {@code false} to allow it.
   */
  public void setLocalRequestOnly(boolean localRequestOnly) {
    this.localRequestOnly = localRequestOnly;
  }

  /**
   * Whether the local store should be ignored when deciding to send the request to the network.
   *
   * @return {@code true} to bypass the local store check.
   */
  public boolean getIgnoreStore() {
    return ignoreStore;
  }

  /**
   * Control whether the local store should be ignored before sending a request to the network.
   *
   * @param ignoreStore {@code true} to bypass the local store check; otherwise {@code false}.
   */
  public void setIgnoreStore(boolean ignoreStore) {
    this.ignoreStore = ignoreStore;
  }

  /**
   * Get the event producer associated with this request context.
   *
   * @return The {@link ClientEventProducer} used to publish client events.
   */
  public ClientEventProducer getEventProducer() {
    return eventProducer;
  }

  /**
   * Get the maximum size of metadata, in bytes.
   *
   * @return Upper bound for metadata size in bytes.
   */
  public int getMaxMetadataSize() {
    return maxMetadataSize;
  }

  /**
   * Set the maximum size of metadata, in bytes.
   *
   * @param maxMetadataSize Non‑negative size limit; larger metadata is rejected.
   */
  public void setMaxMetadataSize(int maxMetadataSize) {
    this.maxMetadataSize = maxMetadataSize;
  }

  /**
   * Get the maximum number of data blocks permitted per splitfile segment.
   *
   * @return Allowed count of data blocks per segment.
   */
  public int getMaxDataBlocksPerSegment() {
    return maxDataBlocksPerSegment;
  }

  /**
   * Set the maximum number of data blocks permitted per splitfile segment.
   *
   * @param maxDataBlocksPerSegment Non‑negative count not exceeding the codec maximum.
   */
  public void setMaxDataBlocksPerSegment(int maxDataBlocksPerSegment) {
    this.maxDataBlocksPerSegment = maxDataBlocksPerSegment;
  }

  /**
   * Get the maximum number of check blocks permitted per splitfile segment.
   *
   * @return Allowed count of check blocks per segment.
   */
  public int getMaxCheckBlocksPerSegment() {
    return maxCheckBlocksPerSegment;
  }

  /**
   * Set the maximum number of check blocks permitted per splitfile segment.
   *
   * @param maxCheckBlocksPerSegment Non‑negative count not exceeding the codec maximum.
   */
  public void setMaxCheckBlocksPerSegment(int maxCheckBlocksPerSegment) {
    this.maxCheckBlocksPerSegment = maxCheckBlocksPerSegment;
  }

  /**
   * Whether ZIP manifests may be returned rather than full archive content.
   *
   * @return {@code true} when returning manifests is allowed.
   */
  public boolean getReturnZIPManifests() {
    return returnZIPManifests;
  }

  /**
   * Control whether ZIP manifests may be returned rather than full archive content.
   *
   * @param returnZIPManifests {@code true} to allow returning manifests; otherwise {@code false}.
   */
  public void setReturnZIPManifests(boolean returnZIPManifests) {
    this.returnZIPManifests = returnZIPManifests;
  }

  /**
   * Whether data should be passed through the content filter.
   *
   * @return {@code true} when filtration is enabled.
   */
  public boolean getFilterData() {
    return filterData;
  }

  /**
   * Control whether data should be passed through the content filter.
   *
   * @param filterData {@code true} to enable filtering; {@code false} to return raw bytes.
   */
  public void setFilterData(boolean filterData) {
    this.filterData = filterData;
  }

  /**
   * Whether path components beyond a configured threshold are ignored.
   *
   * @return {@code true} when excess components are ignored.
   */
  @SuppressWarnings("unused")
  public boolean getIgnoreTooManyPathComponents() {
    return ignoreTooManyPathComponents;
  }

  /**
   * Get the optional {@link BlockSet} representing preselected blocks for the request.
   *
   * @return A {@link BlockSet} reference, or {@code null} when none is associated.
   */
  public BlockSet getBlocks() {
    return blocks;
  }

  /**
   * Get the set of MIME types that are allowed when filtering is enabled.
   *
   * @return A possibly {@code null} set of allowed MIME type strings; empty when no constraints are
   *     configured.
   */
  public Set<String> getAllowedMIMETypes() {
    return allowedMIMETypes;
  }

  /**
   * Configure the set of MIME types that are allowed when filtering is enabled.
   *
   * @param allowedMIMETypes Set of allowed types, or {@code null} to clear the constraint. An empty
   *     set is treated as no allowed types.
   */
  public void setAllowedMIMETypes(Set<String> allowedMIMETypes) {
    this.allowedMIMETypes = allowedMIMETypes;
  }

  /**
   * Get the explicit charset to assume for filtration when needed.
   *
   * @return Charset name such as {@code "UTF-8"}, or {@code null} when unspecified.
   */
  public String getCharset() {
    return charset;
  }

  /**
   * Set the explicit charset to assume for filtration when needed.
   *
   * @param charset Charset name such as {@code "UTF-8"}, or {@code null} to use defaults.
   */
  public void setCharset(String charset) {
    this.charset = charset;
  }

  /**
   * Whether the client cache may be written to by this request.
   *
   * @return {@code true} when writing to the client cache is allowed.
   */
  public boolean getCanWriteClientCache() {
    return canWriteClientCache;
  }

  /**
   * Control whether the client cache may be written to by this request.
   *
   * @param canWriteClientCache {@code true} to enable writing; {@code false} to disable.
   */
  public void setCanWriteClientCache(boolean canWriteClientCache) {
    this.canWriteClientCache = canWriteClientCache;
  }

  /**
   * Get the optional prefetch hook used by HTML document processing.
   *
   * @return The callback instance, or {@code null} when not configured.
   */
  public FoundURICallback getPrefetchHook() {
    return prefetchHook;
  }

  /**
   * Set the optional prefetch hook used by HTML document processing.
   *
   * @param prefetchHook Callback invoked to prefetch discovered URIs; may be {@code null}.
   */
  public void setPrefetchHook(FoundURICallback prefetchHook) {
    this.prefetchHook = prefetchHook;
  }

  /**
   * Get the tag replacer callback used for web‑pushing.
   *
   * @return The callback instance, or {@code null} when not configured.
   */
  public TagReplacerCallback getTagReplacer() {
    return tagReplacer;
  }

  /**
   * Set the tag replacer callback used for web‑pushing.
   *
   * @param tagReplacer Callback that may rewrite tags during processing; may be {@code null}.
   */
  public void setTagReplacer(TagReplacerCallback tagReplacer) {
    this.tagReplacer = tagReplacer;
  }

  /**
   * Get the MIME type forced for the content filter, when non‑null.
   *
   * @return MIME type string if forced, else {@code null}.
   */
  public String getOverrideMIME() {
    return overrideMIME;
  }

  /**
   * Force the content filter to use a specific MIME type.
   *
   * @param overrideMIME MIME type string to use, or {@code null} to clear the override.
   */
  public void setOverrideMIME(String overrideMIME) {
    this.overrideMIME = overrideMIME;
  }

  /**
   * Whether USK DATEHINTs should be ignored by the client.
   *
   * @return {@code true} when date hints are ignored.
   */
  public boolean getIgnoreUSKDatehints() {
    return ignoreUSKDatehints;
  }

  /**
   * Control whether USK DATEHINTs should be ignored by the client.
   *
   * @param ignoreUSKDatehints {@code true} to ignore date hints; otherwise {@code false}.
   */
  public void setIgnoreUSKDatehints(boolean ignoreUSKDatehints) {
    this.ignoreUSKDatehints = ignoreUSKDatehints;
  }

  /**
   * Get the forced URI prefix composed of scheme, host, and port.
   *
   * @return A string such as {@code "https://localhost:1234"}, or {@code null} when unset.
   */
  public String getSchemeHostAndPort() {
    return schemeHostAndPort;
  }

  /**
   * Get the cooldown time window in milliseconds.
   *
   * @return Milliseconds spent in cooldown after exceeding retries.
   */
  public long getCooldownTime() {
    return cooldownTime;
  }

  private static final long CLIENT_DETAIL_MAGIC = 0x5ae53b0ce18dd821L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  /**
   * Serialize this context into a compact binary format.
   *
   * <p>The output includes all configuration required to reconstruct an equivalent context via the
   * {@linkplain #FetchContext(java.io.DataInputStream) binary constructor}. Some transient or
   * callback fields are intentionally not persisted and will cause an {@link
   * UnsupportedOperationException} if present.
   *
   * @param dos Destination stream to receive the encoded context; the caller owns the stream.
   * @throws IOException If writing to {@code dos} fails.
   * @throws UnsupportedOperationException If transient fields that cannot be serialized are set.
   */
  public void writeTo(DataOutputStream dos) throws IOException {
    dos.writeLong(CLIENT_DETAIL_MAGIC);
    dos.writeInt(CLIENT_DETAIL_VERSION);
    dos.writeLong(maxOutputLength);
    dos.writeLong(maxTempLength);
    dos.writeInt(maxRecursionLevel);
    dos.writeInt(maxArchiveRestarts);
    dos.writeInt(maxArchiveLevels);
    dos.writeBoolean(dontEnterImplicitArchives);
    dos.writeInt(maxSplitfileBlockRetries);
    dos.writeInt(maxNonSplitfileRetries);
    dos.writeInt(maxUSKRetries);
    dos.writeBoolean(allowSplitfiles);
    dos.writeBoolean(followRedirects);
    dos.writeBoolean(localRequestOnly);
    dos.writeBoolean(ignoreStore);
    dos.writeInt(maxMetadataSize);
    dos.writeInt(maxDataBlocksPerSegment);
    dos.writeInt(maxCheckBlocksPerSegment);
    dos.writeBoolean(returnZIPManifests);
    dos.writeBoolean(filterData);
    dos.writeBoolean(ignoreTooManyPathComponents);
    if (blocks != null) throw new UnsupportedOperationException("Binary blob not supported");
    if (allowedMIMETypes != null) {
      dos.writeInt(allowedMIMETypes.size());
      for (String s : allowedMIMETypes) dos.writeUTF(s);
    } else {
      dos.writeInt(0);
    }
    if (charset == null) dos.writeUTF("");
    else dos.writeUTF(charset);
    dos.writeBoolean(canWriteClientCache);
    if (prefetchHook != null)
      throw new UnsupportedOperationException("Prefetch hook not supported");
    if (tagReplacer != null) throw new UnsupportedOperationException("Tag replacer not supported");
    if (overrideMIME != null) dos.writeUTF(overrideMIME);
    else dos.writeUTF("");
    dos.writeInt(cooldownRetries);
    dos.writeLong(cooldownTime);
    dos.writeBoolean(ignoreUSKDatehints);
    if (schemeHostAndPort != null) dos.writeUTF(schemeHostAndPort);
    else dos.writeUTF("");
  }

  /**
   * Create from a saved form, e.g. for restarting a request from scratch. Will create its own
   * SimpleEventProducer.
   *
   * @param dis Data stream positioned at the beginning of a context previously written by {@link
   *     #writeTo(java.io.DataOutputStream)}; the constructor reads all required fields.
   * @throws StorageFormatException If the data is badly formatted or cannot be read.
   * @throws IOException If unable to read from the stream.
   */
  public FetchContext(DataInputStream dis) throws StorageFormatException, IOException {
    validateHeader(dis);
    this.maxOutputLength = readNonNegativeLong(dis, "Bad max output length");
    this.maxTempLength = readNonNegativeLong(dis, "Bad max temp length");
    this.maxRecursionLevel = readNonNegativeInt(dis, "Bad max recursion level");
    this.maxArchiveRestarts = readNonNegativeInt(dis, "Bad max archive restarts");
    this.maxArchiveLevels = readNonNegativeInt(dis, "Bad max archive levels");
    this.dontEnterImplicitArchives = dis.readBoolean();
    int maxSplitfileBlockRetriesRead = dis.readInt();
    if (maxSplitfileBlockRetriesRead < -1)
      throw new StorageFormatException("Bad max splitfile block retries");
    this.maxSplitfileBlockRetries = maxSplitfileBlockRetriesRead;

    int maxNonSplitfileRetriesRead = dis.readInt();
    if (maxNonSplitfileRetriesRead < -1)
      throw new StorageFormatException("Bad non-splitfile retries");
    this.maxNonSplitfileRetries = maxNonSplitfileRetriesRead;

    int maxUSKRetriesRead = dis.readInt();
    if (maxUSKRetriesRead < -1) throw new StorageFormatException("Bad max USK retries");
    this.maxUSKRetries = maxUSKRetriesRead;
    this.allowSplitfiles = dis.readBoolean();
    this.followRedirects = dis.readBoolean();
    this.localRequestOnly = dis.readBoolean();
    this.ignoreStore = dis.readBoolean();
    this.maxMetadataSize = readNonNegativeInt(dis, "Bad max metadata size");
    int dataBlocks = dis.readInt();
    if (dataBlocks < 0 || dataBlocks > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new StorageFormatException("Bad max blocks per segment");
    this.maxDataBlocksPerSegment = dataBlocks;

    int checkBlocks = dis.readInt();
    if (checkBlocks < 0 || checkBlocks > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new StorageFormatException("Bad max blocks per segment");
    this.maxCheckBlocksPerSegment = checkBlocks;
    this.returnZIPManifests = dis.readBoolean();
    this.filterData = dis.readBoolean();
    this.ignoreTooManyPathComponents = dis.readBoolean();

    Set<String> mimes = readAllowedMimes(dis);
    this.allowedMIMETypes = mimes.isEmpty() ? null : mimes;

    String s = dis.readUTF();
    this.charset = s.isEmpty() ? null : s;
    this.canWriteClientCache = dis.readBoolean();
    s = dis.readUTF();
    this.overrideMIME = s.isEmpty() ? null : s;
    this.cooldownRetries = dis.readInt();
    this.cooldownTime = dis.readLong();
    this.ignoreUSKDatehints = dis.readBoolean();
    try {
      s = dis.readUTF();
    } catch (EOFException e) {
      // input stream reached EOF, so it must have been and old version without scehmeHostAndPort.
      s = "";
    }
    this.schemeHostAndPort = s.isEmpty() ? null : s;
    hasOwnEventProducer = true;
    eventProducer = new SimpleEventProducer();
    blocks = null;
  }

  private void validateHeader(DataInputStream dis) throws IOException, StorageFormatException {
    long magic = dis.readLong();
    if (magic != CLIENT_DETAIL_MAGIC)
      throw new StorageFormatException("Bad magic for fetch settings (FetchContext)");
    int version = dis.readInt();
    if (version != CLIENT_DETAIL_VERSION)
      throw new StorageFormatException("Bad version for fetch settings (FetchContext)");
  }

  private long readNonNegativeLong(DataInputStream dis, String errorMessage)
      throws IOException, StorageFormatException {
    long v = dis.readLong();
    if (v < 0) throw new StorageFormatException(errorMessage);
    return v;
  }

  private int readNonNegativeInt(DataInputStream dis, String errorMessage)
      throws IOException, StorageFormatException {
    int v = dis.readInt();
    if (v < 0) throw new StorageFormatException(errorMessage);
    return v;
  }

  private Set<String> readAllowedMimes(DataInputStream dis)
      throws IOException, StorageFormatException {
    int x = dis.readInt();
    if (x < 0) throw new StorageFormatException("Bad allowed MIME types length " + x);
    if (x == 0) return new HashSet<>();
    Set<String> set = new HashSet<>();
    for (int i = 0; i < x; i++) {
      set.add(dis.readUTF());
    }
    return set;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    // eventProducer is not included, assumed to be unique.
    result = prime * result + (allowSplitfiles ? 1231 : 1237);
    result = prime * result + ((allowedMIMETypes == null) ? 0 : allowedMIMETypes.hashCode());
    // Don't include blocks. It doesn't implement content-based hashCode() and equals().
    result = prime * result + (canWriteClientCache ? 1231 : 1237);
    result = prime * result + ((charset == null) ? 0 : charset.hashCode());
    result = prime * result + cooldownRetries;
    result = prime * result + Long.hashCode(cooldownTime);
    result = prime * result + (dontEnterImplicitArchives ? 1231 : 1237);
    result = prime * result + (filterData ? 1231 : 1237);
    result = prime * result + (followRedirects ? 1231 : 1237);
    result = prime * result + (hasOwnEventProducer ? 1231 : 1237);
    result = prime * result + (ignoreStore ? 1231 : 1237);
    result = prime * result + (ignoreTooManyPathComponents ? 1231 : 1237);
    result = prime * result + (ignoreUSKDatehints ? 1231 : 1237);
    result = prime * result + (localRequestOnly ? 1231 : 1237);
    result = prime * result + maxArchiveLevels;
    result = prime * result + maxArchiveRestarts;
    result = prime * result + maxCheckBlocksPerSegment;
    result = prime * result + maxDataBlocksPerSegment;
    result = prime * result + maxMetadataSize;
    result = prime * result + maxNonSplitfileRetries;
    result = prime * result + Long.hashCode(maxOutputLength);
    result = prime * result + maxRecursionLevel;
    result = prime * result + maxSplitfileBlockRetries;
    result = prime * result + Long.hashCode(maxTempLength);
    result = prime * result + maxUSKRetries;
    result = prime * result + ((overrideMIME == null) ? 0 : overrideMIME.hashCode());
    result = prime * result + ((prefetchHook == null) ? 0 : prefetchHook.hashCode());
    result = prime * result + (returnZIPManifests ? 1231 : 1237);
    result = prime * result + ((tagReplacer == null) ? 0 : tagReplacer.hashCode());
    result = prime * result + ((schemeHostAndPort == null) ? 0 : schemeHostAndPort.hashCode());
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
    FetchContext other = (FetchContext) obj;
    // eventProducer is ignored.
    if (allowSplitfiles != other.allowSplitfiles) return false;
    if (allowedMIMETypes == null) {
      if (other.allowedMIMETypes != null) return false;
    } else if (!allowedMIMETypes.equals(other.allowedMIMETypes)) return false;
    // We compare on blocks even without content-based equality.
    if (blocks == null) {
      if (other.blocks != null) return false;
    } else if (!blocks.equals(other.blocks)) return false;
    if (canWriteClientCache != other.canWriteClientCache) return false;
    if (charset == null) {
      if (other.charset != null) return false;
    } else if (!charset.equals(other.charset)) return false;
    if (cooldownRetries != other.cooldownRetries) return false;
    if (cooldownTime != other.cooldownTime) return false;
    if (dontEnterImplicitArchives != other.dontEnterImplicitArchives) return false;
    if (filterData != other.filterData) return false;
    if (followRedirects != other.followRedirects) return false;
    if (hasOwnEventProducer != other.hasOwnEventProducer) return false;
    if (ignoreStore != other.ignoreStore) return false;
    if (ignoreTooManyPathComponents != other.ignoreTooManyPathComponents) return false;
    if (ignoreUSKDatehints != other.ignoreUSKDatehints) return false;
    if (localRequestOnly != other.localRequestOnly) return false;
    if (maxArchiveLevels != other.maxArchiveLevels) return false;
    if (maxArchiveRestarts != other.maxArchiveRestarts) return false;
    if (maxCheckBlocksPerSegment != other.maxCheckBlocksPerSegment) return false;
    if (maxDataBlocksPerSegment != other.maxDataBlocksPerSegment) return false;
    if (maxMetadataSize != other.maxMetadataSize) return false;
    if (maxNonSplitfileRetries != other.maxNonSplitfileRetries) return false;
    if (maxOutputLength != other.maxOutputLength) return false;
    if (maxRecursionLevel != other.maxRecursionLevel) return false;
    if (maxSplitfileBlockRetries != other.maxSplitfileBlockRetries) return false;
    if (maxTempLength != other.maxTempLength) return false;
    if (maxUSKRetries != other.maxUSKRetries) return false;
    if (overrideMIME == null) {
      if (other.overrideMIME != null) return false;
    } else if (!overrideMIME.equals(other.overrideMIME)) return false;
    if (prefetchHook == null) {
      if (other.prefetchHook != null) return false;
    } else if (!prefetchHook.equals(other.prefetchHook)) return false;
    if (returnZIPManifests != other.returnZIPManifests) return false;
    if (tagReplacer == null) {
      if (other.tagReplacer != null) return false;
    } else if (!tagReplacer.equals(other.tagReplacer)) return false;
    if (schemeHostAndPort == null) {
      return other.schemeHostAndPort == null;
    } else return schemeHostAndPort.equals(other.schemeHostAndPort);
  }
}
