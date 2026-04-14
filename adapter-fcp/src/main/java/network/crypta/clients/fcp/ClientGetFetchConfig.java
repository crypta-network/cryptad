package network.crypta.clients.fcp;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Detached fetch configuration for one GET request.
 *
 * <p>This value object mirrors the subset of runtime fetch-context state that the FCP adapter needs
 * to persist, restore, inspect, and adjust for GET requests. It deliberately stays adapter-owned so
 * request parsing, replay, and status code can work with a stable representation instead of holding
 * onto live daemon fetch-context instances. The bridge layer is responsible for translating this
 * detached state back into a concrete runtime fetch context when a request is started or resumed.
 *
 * <p>The class is mutable because FCP request construction still follows the existing pattern of
 * cloning defaults and then applying per-request overrides. Callers should therefore treat each
 * instance as a request-scoped state rather than as a reusable shared template. The only collection
 * member, {@code allowedMimeTypes}, uses defensive copying on input and output so mutations outside
 * the object do not leak into persisted request state.
 */
@SuppressWarnings({"java:S6206"})
public final class ClientGetFetchConfig implements Serializable {
  /** Serialization version for the detached fetch configuration representation. */
  @Serial private static final long serialVersionUID = 1L;

  /** Maximum final payload length, in bytes, that the request is willing to return. */
  private long maxOutputLength;

  /** Maximum temporary storage length, in bytes, allowed while fetching or filtering. */
  private long maxTempLength;

  /** Maximum recursion depth when traversing nested metadata and archive structures. */
  private int maxRecursionLevel;

  /** Maximum number of archive restart attempts allowed during traversal. */
  private int maxArchiveRestarts;

  /** Maximum number of archive layers that may be entered during fetch processing. */
  private int maxArchiveLevels;

  /** Whether implicit archives should be skipped unless explicitly requested. */
  private boolean dontEnterImplicitArchives;

  /** Retry limit for splitfile block fetches. */
  private int maxSplitfileBlockRetries;

  /** Retry limit for non-splitfile fetches. */
  private int maxNonSplitfileRetries;

  /** Retry limit for USK lookups. */
  private int maxUSKRetries;

  /** Whether splitfiles may be fetched at all. */
  private boolean allowSplitfiles;

  /** Whether permanent or temporary, redirects should be followed automatically. */
  private boolean followRedirects;

  /** Whether the request should be restricted to datastore-only or otherwise local handling. */
  private boolean localRequestOnly;

  /** Whether the datastore should be bypassed when servicing the fetch. */
  private boolean ignoreStore;

  /** Maximum metadata size, in bytes, that the fetch should accept. */
  private int maxMetadataSize;

  /** Maximum data blocks per splitfile segment. */
  private int maxDataBlocksPerSegment;

  /** Maximum check blocks per splitfile segment. */
  private int maxCheckBlocksPerSegment;

  /** Whether ZIP manifests should be returned instead of being expanded automatically. */
  private boolean returnZIPManifests;

  /** Whether the fetched payload should be passed through the content filter. */
  private boolean filterData;

  /** Whether path components beyond the configured threshold should be tolerated. */
  private boolean ignoreTooManyPathComponents;

  /** Optional allowlist of MIME types that the request will accept. */
  private Set<String> allowedMimeTypes;

  /** Optional charset override supplied to the content filter. */
  private String charset;

  /** Whether the client cache may be written as part of this fetch. */
  private boolean canWriteClientCache;

  /** Optional MIME override supplied to the content filter. */
  private String overrideMime;

  /** Number of cooldown retries before the runtime should give up. */
  private int cooldownRetries;

  /** Cooldown duration, in milliseconds, between retry attempts. */
  private long cooldownTime;

  /** Whether USK date hints should be ignored while resolving editions. */
  private boolean ignoreUSKDatehints;

  /** Optional scheme, host, and port override used by filtering or URI rewriting logic. */
  private String schemeHostAndPort;

  /** Creates an empty detached fetch configuration. */
  public ClientGetFetchConfig() {}

  /**
   * Creates a deep copy of another detached fetch configuration.
   *
   * <p>Primitive and string members are copied directly, while mutable collection state is cloned
   * so later changes to either instance remain isolated.
   *
   * @param other source configuration to copy.
   */
  public ClientGetFetchConfig(ClientGetFetchConfig other) {
    maxOutputLength = other.maxOutputLength;
    maxTempLength = other.maxTempLength;
    maxRecursionLevel = other.maxRecursionLevel;
    maxArchiveRestarts = other.maxArchiveRestarts;
    maxArchiveLevels = other.maxArchiveLevels;
    dontEnterImplicitArchives = other.dontEnterImplicitArchives;
    maxSplitfileBlockRetries = other.maxSplitfileBlockRetries;
    maxNonSplitfileRetries = other.maxNonSplitfileRetries;
    maxUSKRetries = other.maxUSKRetries;
    allowSplitfiles = other.allowSplitfiles;
    followRedirects = other.followRedirects;
    localRequestOnly = other.localRequestOnly;
    ignoreStore = other.ignoreStore;
    maxMetadataSize = other.maxMetadataSize;
    maxDataBlocksPerSegment = other.maxDataBlocksPerSegment;
    maxCheckBlocksPerSegment = other.maxCheckBlocksPerSegment;
    returnZIPManifests = other.returnZIPManifests;
    filterData = other.filterData;
    ignoreTooManyPathComponents = other.ignoreTooManyPathComponents;
    allowedMimeTypes = copyAllowedMimeTypes(other.allowedMimeTypes);
    charset = other.charset;
    canWriteClientCache = other.canWriteClientCache;
    overrideMime = other.overrideMime;
    cooldownRetries = other.cooldownRetries;
    cooldownTime = other.cooldownTime;
    ignoreUSKDatehints = other.ignoreUSKDatehints;
    schemeHostAndPort = other.schemeHostAndPort;
  }

  /**
   * Returns a detached copy of this configuration.
   *
   * <p>Callers typically use this when they need to start from an existing baseline and apply
   * request-specific overrides without mutating the original instance.
   *
   * @return independent copy of this configuration.
   */
  public ClientGetFetchConfig copy() {
    return new ClientGetFetchConfig(this);
  }

  /**
   * Returns the configured maximum final payload length in bytes.
   *
   * @return maximum returned payload length, in bytes.
   */
  public long getMaxOutputLength() {
    return maxOutputLength;
  }

  /**
   * Sets the maximum final payload length in bytes.
   *
   * @param maxOutputLength maximum returned payload length, in bytes.
   */
  public void setMaxOutputLength(long maxOutputLength) {
    this.maxOutputLength = maxOutputLength;
  }

  /**
   * Returns the configured maximum temporary storage length in bytes.
   *
   * @return temporary storage limit, in bytes.
   */
  public long getMaxTempLength() {
    return maxTempLength;
  }

  /**
   * Sets the maximum temporary storage length in bytes.
   *
   * @param maxTempLength temporary storage limit, in bytes.
   */
  public void setMaxTempLength(long maxTempLength) {
    this.maxTempLength = maxTempLength;
  }

  /**
   * Returns the maximum metadata and archive recursion depth.
   *
   * @return recursion depth limit for metadata and archives.
   */
  public int getMaxRecursionLevel() {
    return maxRecursionLevel;
  }

  /**
   * Sets the maximum metadata and archive recursion depth.
   *
   * @param maxRecursionLevel recursion depth limit for metadata and archives.
   */
  public void setMaxRecursionLevel(int maxRecursionLevel) {
    this.maxRecursionLevel = maxRecursionLevel;
  }

  /**
   * Returns the maximum number of archive restart attempts.
   *
   * @return archive restart limit.
   */
  public int getMaxArchiveRestarts() {
    return maxArchiveRestarts;
  }

  /**
   * Sets the maximum number of archive restart attempts.
   *
   * @param maxArchiveRestarts archive restart limit.
   */
  public void setMaxArchiveRestarts(int maxArchiveRestarts) {
    this.maxArchiveRestarts = maxArchiveRestarts;
  }

  /**
   * Returns the maximum number of archive layers that may be traversed.
   *
   * @return archive depth limit.
   */
  public int getMaxArchiveLevels() {
    return maxArchiveLevels;
  }

  /**
   * Sets the maximum number of archive layers that may be traversed.
   *
   * @param maxArchiveLevels archive depth limit.
   */
  public void setMaxArchiveLevels(int maxArchiveLevels) {
    this.maxArchiveLevels = maxArchiveLevels;
  }

  /**
   * Returns whether implicit archives are skipped unless explicitly requested.
   *
   * @return {@code true} when implicit archives should not be entered automatically.
   */
  public boolean getDontEnterImplicitArchives() {
    return dontEnterImplicitArchives;
  }

  /**
   * Sets whether implicit archives are skipped unless explicitly requested.
   *
   * @param dontEnterImplicitArchives {@code true} to avoid entering implicit archives
   *     automatically.
   */
  public void setDontEnterImplicitArchives(boolean dontEnterImplicitArchives) {
    this.dontEnterImplicitArchives = dontEnterImplicitArchives;
  }

  /**
   * Returns the retry limit for splitfile block fetches.
   *
   * @return splitfile block retry limit.
   */
  public int getMaxSplitfileBlockRetries() {
    return maxSplitfileBlockRetries;
  }

  /**
   * Sets the retry limit for splitfile block fetches.
   *
   * @param maxSplitfileBlockRetries splitfile block retry limit.
   */
  public void setMaxSplitfileBlockRetries(int maxSplitfileBlockRetries) {
    this.maxSplitfileBlockRetries = maxSplitfileBlockRetries;
  }

  /**
   * Returns the retry limit for non-splitfile fetches.
   *
   * @return non-splitfile retry limit.
   */
  public int getMaxNonSplitfileRetries() {
    return maxNonSplitfileRetries;
  }

  /**
   * Sets the retry limit for non-splitfile fetches.
   *
   * @param maxNonSplitfileRetries non-splitfile retry limit.
   */
  public void setMaxNonSplitfileRetries(int maxNonSplitfileRetries) {
    this.maxNonSplitfileRetries = maxNonSplitfileRetries;
  }

  /**
   * Returns the retry limit for USK lookups.
   *
   * @return USK retry limit.
   */
  public int getMaxUSKRetries() {
    return maxUSKRetries;
  }

  /**
   * Sets the retry limit for USK lookups.
   *
   * @param maxUSKRetries USK retry limit.
   */
  public void setMaxUSKRetries(int maxUSKRetries) {
    this.maxUSKRetries = maxUSKRetries;
  }

  /**
   * Returns whether splitfiles may be fetched.
   *
   * @return {@code true} when splitfile handling is enabled.
   */
  public boolean getAllowSplitfiles() {
    return allowSplitfiles;
  }

  /**
   * Sets whether splitfiles may be fetched.
   *
   * @param allowSplitfiles {@code true} to permit splitfile handling.
   */
  public void setAllowSplitfiles(boolean allowSplitfiles) {
    this.allowSplitfiles = allowSplitfiles;
  }

  /**
   * Returns whether redirects should be followed automatically.
   *
   * @return {@code true} when redirect following is enabled.
   */
  public boolean getFollowRedirects() {
    return followRedirects;
  }

  /**
   * Sets whether redirects should be followed automatically.
   *
   * @param followRedirects {@code true} to follow redirects automatically.
   */
  public void setFollowRedirects(boolean followRedirects) {
    this.followRedirects = followRedirects;
  }

  /**
   * Returns whether the request should be handled locally only.
   *
   * @return {@code true} when the fetch should stay local to the node.
   */
  public boolean getLocalRequestOnly() {
    return localRequestOnly;
  }

  /**
   * Sets whether the request should be handled locally only.
   *
   * @param localRequestOnly {@code true} to keep the fetch local to the node.
   */
  public void setLocalRequestOnly(boolean localRequestOnly) {
    this.localRequestOnly = localRequestOnly;
  }

  /**
   * Returns whether the datastore should be bypassed.
   *
   * @return {@code true} when datastore lookups should be skipped.
   */
  public boolean getIgnoreStore() {
    return ignoreStore;
  }

  /**
   * Sets whether the datastore should be bypassed.
   *
   * @param ignoreStore {@code true} to skip datastore lookups.
   */
  public void setIgnoreStore(boolean ignoreStore) {
    this.ignoreStore = ignoreStore;
  }

  /**
   * Returns the maximum metadata size in bytes.
   *
   * @return metadata size limit, in bytes.
   */
  public int getMaxMetadataSize() {
    return maxMetadataSize;
  }

  /**
   * Sets the maximum metadata size in bytes.
   *
   * @param maxMetadataSize metadata size limit, in bytes.
   */
  public void setMaxMetadataSize(int maxMetadataSize) {
    this.maxMetadataSize = maxMetadataSize;
  }

  /**
   * Returns the maximum number of data blocks per splitfile segment.
   *
   * @return data-block limit per segment.
   */
  public int getMaxDataBlocksPerSegment() {
    return maxDataBlocksPerSegment;
  }

  /**
   * Sets the maximum number of data blocks per splitfile segment.
   *
   * @param maxDataBlocksPerSegment data-block limit per segment.
   */
  public void setMaxDataBlocksPerSegment(int maxDataBlocksPerSegment) {
    this.maxDataBlocksPerSegment = maxDataBlocksPerSegment;
  }

  /**
   * Returns the maximum number of check blocks per splitfile segment.
   *
   * @return check-block limit per segment.
   */
  public int getMaxCheckBlocksPerSegment() {
    return maxCheckBlocksPerSegment;
  }

  /**
   * Sets the maximum number of check blocks per splitfile segment.
   *
   * @param maxCheckBlocksPerSegment check-block limit per segment.
   */
  public void setMaxCheckBlocksPerSegment(int maxCheckBlocksPerSegment) {
    this.maxCheckBlocksPerSegment = maxCheckBlocksPerSegment;
  }

  /**
   * Returns whether ZIP manifests should be returned as ZIP data.
   *
   * @return {@code true} when ZIP manifests should not be expanded automatically.
   */
  public boolean getReturnZIPManifests() {
    return returnZIPManifests;
  }

  /**
   * Sets whether ZIP manifests should be returned as ZIP data.
   *
   * @param returnZIPManifests {@code true} to return ZIP manifests directly.
   */
  public void setReturnZIPManifests(boolean returnZIPManifests) {
    this.returnZIPManifests = returnZIPManifests;
  }

  /**
   * Returns whether the fetched payload should be filtered.
   *
   * @return {@code true} when content filtering is enabled.
   */
  public boolean getFilterData() {
    return filterData;
  }

  /**
   * Sets whether the fetched payload should be filtered.
   *
   * @param filterData {@code true} to enable content filtering.
   */
  public void setFilterData(boolean filterData) {
    this.filterData = filterData;
  }

  /**
   * Returns whether extra path components should be tolerated.
   *
   * @return {@code true} when excess path components should not fail the fetch.
   */
  public boolean getIgnoreTooManyPathComponents() {
    return ignoreTooManyPathComponents;
  }

  /**
   * Sets whether extra path components should be tolerated.
   *
   * @param ignoreTooManyPathComponents {@code true} to tolerate excess path components.
   */
  public void setIgnoreTooManyPathComponents(boolean ignoreTooManyPathComponents) {
    this.ignoreTooManyPathComponents = ignoreTooManyPathComponents;
  }

  /**
   * Returns the allowed MIME-type set as a defensive copy.
   *
   * <p>The caller may modify the returned set without affecting this configuration.
   *
   * @return copied allowlist of MIME types, or {@code null} when no allowlist is configured.
   */
  public Set<String> getAllowedMimeTypes() {
    return copyAllowedMimeTypes(allowedMimeTypes);
  }

  /**
   * Stores the allowed MIME-type set as a defensive copy.
   *
   * @param allowedMimeTypes allowlist to copy into this configuration, or {@code null} to clear the
   *     restriction.
   */
  public void setAllowedMimeTypes(Set<String> allowedMimeTypes) {
    this.allowedMimeTypes = copyAllowedMimeTypes(allowedMimeTypes);
  }

  /**
   * Returns the optional charset override used by filtering.
   *
   * @return charset override, or {@code null} when none is configured.
   */
  public String getCharset() {
    return charset;
  }

  /**
   * Sets the optional charset override used by filtering.
   *
   * @param charset charset override, or {@code null} to clear it.
   */
  public void setCharset(String charset) {
    this.charset = charset;
  }

  /**
   * Returns whether the client cache may be written during this fetch.
   *
   * @return {@code true} when client-cache writes are allowed.
   */
  public boolean getCanWriteClientCache() {
    return canWriteClientCache;
  }

  /**
   * Sets whether the client cache may be written during this fetch.
   *
   * @param canWriteClientCache {@code true} to allow client-cache writes.
   */
  public void setCanWriteClientCache(boolean canWriteClientCache) {
    this.canWriteClientCache = canWriteClientCache;
  }

  /**
   * Returns the optional MIME override used by filtering.
   *
   * @return MIME override, or {@code null} when none is configured.
   */
  public String getOverrideMime() {
    return overrideMime;
  }

  /**
   * Sets the optional MIME override used by filtering.
   *
   * @param overrideMime MIME override, or {@code null} to clear it.
   */
  public void setOverrideMime(String overrideMime) {
    this.overrideMime = overrideMime;
  }

  /**
   * Returns the configured number of cooldown retries.
   *
   * @return cooldown retry count.
   */
  public int getCooldownRetries() {
    return cooldownRetries;
  }

  /**
   * Sets the configured number of cooldown retries.
   *
   * @param cooldownRetries cooldown retry count.
   */
  public void setCooldownRetries(int cooldownRetries) {
    this.cooldownRetries = cooldownRetries;
  }

  /**
   * Returns the cooldown interval in milliseconds.
   *
   * @return cooldown interval, in milliseconds.
   */
  public long getCooldownTime() {
    return cooldownTime;
  }

  /**
   * Sets the cooldown interval in milliseconds.
   *
   * @param cooldownTime cooldown interval, in milliseconds.
   */
  public void setCooldownTime(long cooldownTime) {
    this.cooldownTime = cooldownTime;
  }

  /**
   * Returns whether USK date hints should be ignored.
   *
   * @return {@code true} when USK date hints are ignored.
   */
  public boolean getIgnoreUSKDatehints() {
    return ignoreUSKDatehints;
  }

  /**
   * Sets whether USK date hints should be ignored.
   *
   * @param ignoreUSKDatehints {@code true} to ignore USK date hints.
   */
  public void setIgnoreUSKDatehints(boolean ignoreUSKDatehints) {
    this.ignoreUSKDatehints = ignoreUSKDatehints;
  }

  /**
   * Returns the optional scheme, host, and port override used by filtering logic.
   *
   * @return scheme, host, and port override, or {@code null} when unset.
   */
  public String getSchemeHostAndPort() {
    return schemeHostAndPort;
  }

  /**
   * Sets the optional scheme, host, and port override used by filtering logic.
   *
   * @param schemeHostAndPort scheme, host, and port override, or {@code null} to clear it.
   */
  public void setSchemeHostAndPort(String schemeHostAndPort) {
    this.schemeHostAndPort = schemeHostAndPort;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ClientGetFetchConfig that)) {
      return false;
    }
    return maxOutputLength == that.maxOutputLength
        && maxTempLength == that.maxTempLength
        && maxRecursionLevel == that.maxRecursionLevel
        && maxArchiveRestarts == that.maxArchiveRestarts
        && maxArchiveLevels == that.maxArchiveLevels
        && dontEnterImplicitArchives == that.dontEnterImplicitArchives
        && maxSplitfileBlockRetries == that.maxSplitfileBlockRetries
        && maxNonSplitfileRetries == that.maxNonSplitfileRetries
        && maxUSKRetries == that.maxUSKRetries
        && allowSplitfiles == that.allowSplitfiles
        && followRedirects == that.followRedirects
        && localRequestOnly == that.localRequestOnly
        && ignoreStore == that.ignoreStore
        && maxMetadataSize == that.maxMetadataSize
        && maxDataBlocksPerSegment == that.maxDataBlocksPerSegment
        && maxCheckBlocksPerSegment == that.maxCheckBlocksPerSegment
        && returnZIPManifests == that.returnZIPManifests
        && filterData == that.filterData
        && ignoreTooManyPathComponents == that.ignoreTooManyPathComponents
        && canWriteClientCache == that.canWriteClientCache
        && cooldownRetries == that.cooldownRetries
        && cooldownTime == that.cooldownTime
        && ignoreUSKDatehints == that.ignoreUSKDatehints
        && Objects.equals(allowedMimeTypes, that.allowedMimeTypes)
        && Objects.equals(charset, that.charset)
        && Objects.equals(overrideMime, that.overrideMime)
        && Objects.equals(schemeHostAndPort, that.schemeHostAndPort);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        maxOutputLength,
        maxTempLength,
        maxRecursionLevel,
        maxArchiveRestarts,
        maxArchiveLevels,
        dontEnterImplicitArchives,
        maxSplitfileBlockRetries,
        maxNonSplitfileRetries,
        maxUSKRetries,
        allowSplitfiles,
        followRedirects,
        localRequestOnly,
        ignoreStore,
        maxMetadataSize,
        maxDataBlocksPerSegment,
        maxCheckBlocksPerSegment,
        returnZIPManifests,
        filterData,
        ignoreTooManyPathComponents,
        allowedMimeTypes,
        charset,
        canWriteClientCache,
        overrideMime,
        cooldownRetries,
        cooldownTime,
        ignoreUSKDatehints,
        schemeHostAndPort);
  }

  @Override
  public String toString() {
    return "ClientGetFetchConfig["
        + "maxOutputLength="
        + maxOutputLength
        + ", maxTempLength="
        + maxTempLength
        + ", maxRecursionLevel="
        + maxRecursionLevel
        + ", maxArchiveRestarts="
        + maxArchiveRestarts
        + ", maxArchiveLevels="
        + maxArchiveLevels
        + ", dontEnterImplicitArchives="
        + dontEnterImplicitArchives
        + ", maxSplitfileBlockRetries="
        + maxSplitfileBlockRetries
        + ", maxNonSplitfileRetries="
        + maxNonSplitfileRetries
        + ", maxUSKRetries="
        + maxUSKRetries
        + ", allowSplitfiles="
        + allowSplitfiles
        + ", followRedirects="
        + followRedirects
        + ", localRequestOnly="
        + localRequestOnly
        + ", ignoreStore="
        + ignoreStore
        + ", maxMetadataSize="
        + maxMetadataSize
        + ", maxDataBlocksPerSegment="
        + maxDataBlocksPerSegment
        + ", maxCheckBlocksPerSegment="
        + maxCheckBlocksPerSegment
        + ", returnZIPManifests="
        + returnZIPManifests
        + ", filterData="
        + filterData
        + ", ignoreTooManyPathComponents="
        + ignoreTooManyPathComponents
        + ", allowedMimeTypes="
        + allowedMimeTypes
        + ", charset="
        + charset
        + ", canWriteClientCache="
        + canWriteClientCache
        + ", overrideMime="
        + overrideMime
        + ", cooldownRetries="
        + cooldownRetries
        + ", cooldownTime="
        + cooldownTime
        + ", ignoreUSKDatehints="
        + ignoreUSKDatehints
        + ", schemeHostAndPort="
        + schemeHostAndPort
        + ']';
  }

  /**
   * Copies the allowlist set defensively.
   *
   * @param input source set to clone.
   * @return cloned set, or {@code null} when {@code input} is {@code null}.
   */
  private static Set<String> copyAllowedMimeTypes(Set<String> input) {
    return input == null ? null : new HashSet<>(input);
  }
}
