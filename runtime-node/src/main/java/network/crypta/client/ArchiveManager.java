package network.crypta.client;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.Serial;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.zip.GZIPInputStream;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.ExceptionWrapper;
import network.crypta.support.LRUMap;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.LzmaInputStream;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.SkipShieldingInputStream;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.lang3.mutable.MutableBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages extraction and caching for supported archive containers (ZIP and TAR).
 *
 * <p>This manager maintains a bounded in-memory index of recently opened containers and a
 * size-limited on-disk cache of extracted members. Typical usage is: get a handler for a key and
 * archive type, request specific entries by name, and read the resulting buckets. Frequently
 * requested members remain available through an LRU-managed cache, so repeated calls avoid
 * re-processing the full container.
 *
 * <p>Core responsibilities include streaming decompression, validating entry names to prevent path
 * traversal, enforcing per-entry and whole-archive expansion limits, and recording either the
 * extracted data or a readable error item. Extraction writes into temporary buckets supplied by a
 * {@link BucketFactory}; small outputs may stay in RAM depending on configured thresholds and
 * migrate to disk as they grow or as memory pressure increases.
 *
 * <p>Thread-safety: instances synchronize on themselves when mutating cache structures. When used
 * together with {@code ArchiveStoreContext}, always lock {@code ArchiveStoreContext} before {@code
 * ArchiveManager} to avoid deadlocks.
 */
public class ArchiveManager {
  private static final Logger LOG = LoggerFactory.getLogger(ArchiveManager.class);
  private static final int MAX_ARCHIVE_ENTRIES = 10_000;

  /**
   * Conventional name for generated metadata placed alongside extracted members.
   *
   * <p>When a container lacks explicit metadata, a synthetic description of its directory structure
   * may be produced under this filename so callers can introspect the archive without scanning it.
   */
  public static final String METADATA_NAME = ".metadata";

  private static final String ERR_FILE_TOO_BIG = "File too big: ";
  private static final String ERR_LIMIT_SUFFIX = " greater than current archived file size limit ";
  private static final String ERR_ARCHIVE_ENTRY_COUNT_PREFIX = "Archive has too many entries: ";
  private static final String ERR_ARCHIVE_EXPANDED_SIZE_PREFIX =
      "Expanded archive exceeds configured limit: ";

  /**
   * Supported archive formats.
   *
   * <p>This enum is persisted. Renaming or removing members can break existing data.
   */
  public enum ARCHIVE_TYPE {
    /** ZIP archives; common MIME aliases are supported. */
    ZIP(
        (short) 0,
        mimeTypes(
            "application/zip",
            "application/x-zip")), /* eventually get rid of ZIP support at some point */
    /** TAR archives; a standard TAR MIME type is supported. */
    TAR((short) 1, mimeTypes("application/x-tar"));

    /** Stable numeric identifier for this type used in serialized metadata and messages. */
    public final short metadataID;

    private final String mimeTypes;

    /** Cached values(). Never modify or pass this array to outside code! */
    private static final ARCHIVE_TYPE[] values = values();

    /**
     * Creates a new enum member.
     *
     * @param metadataID stable, persisted identifier for this archive type
     * @param mimeTypes recognized MIME aliases, compared case-insensitively
     */
    ARCHIVE_TYPE(short metadataID, String mimeTypes) {
      this.metadataID = metadataID;
      this.mimeTypes = mimeTypes;
    }

    private static String mimeTypes(String... values) {
      if (values.length == 0) {
        return "";
      }
      return String.join(",", values);
    }

    /**
     * Returns whether the provided identifier matches any defined archive type.
     *
     * @param id numeric type identifier to test
     * @return {@code true} if {@code id} equals a known {@link #metadataID}; otherwise {@code
     *     false}
     */
    public static boolean isValidMetadataID(short id) {
      for (ARCHIVE_TYPE current : values) if (id == current.metadataID) return true;
      return false;
    }

    /**
     * Reports whether the supplied MIME string maps to a supported archive type.
     *
     * @param type MIME string to check; case-insensitive and tolerant of common aliases
     * @return {@code true} if the MIME maps to one of the supported types; else {@code false}
     */
    public static boolean isUsableArchiveType(String type) {
      for (ARCHIVE_TYPE current : values) if (current.matchesMimeType(type)) return true;
      return false;
    }

    /**
     * Resolves an archive type from a MIME string.
     *
     * @param type MIME string to resolve
     * @return matching {@link ARCHIVE_TYPE}, or {@code null} if unsupported
     */
    public static ARCHIVE_TYPE getArchiveType(String type) {
      for (ARCHIVE_TYPE current : values) if (current.matchesMimeType(type)) return current;
      return null;
    }

    /**
     * Resolves an archive type from its persisted numeric identifier.
     *
     * @param type numeric identifier to resolve
     * @return matching {@link ARCHIVE_TYPE}, or {@code null} if unknown
     */
    public static ARCHIVE_TYPE getArchiveType(short type) {
      for (ARCHIVE_TYPE current : values) if (current.metadataID == type) return current;
      return null;
    }

    /**
     * Returns the default archive type used when callers do not specify one.
     *
     * @return default {@link ARCHIVE_TYPE}; currently {@link #TAR}
     */
    public static ARCHIVE_TYPE getDefault() {
      return TAR;
    }

    /**
     * Returns the primary MIME type associated with this archive type.
     *
     * @return non-null MIME string suitable for labeling responses
     */
    public String defaultMimeType() {
      int commaIndex = mimeTypes.indexOf(',');
      return commaIndex == -1 ? mimeTypes : mimeTypes.substring(0, commaIndex);
    }

    private boolean matchesMimeType(String type) {
      if (type == null) return false;
      StringTokenizer tokenizer = new StringTokenizer(mimeTypes, ",");
      while (tokenizer.hasMoreTokens()) {
        if (tokenizer.nextToken().equalsIgnoreCase(type)) {
          return true;
        }
      }
      return false;
    }
  }

  final long maxArchivedFileSize;

  // ArchiveHandler's
  final int maxArchiveHandlers;
  private final LRUMap<FreenetURI, ArchiveStoreContext> archiveHandlers;

  // Data cache
  /** Maximum number of cached ArchiveStoreItems */
  final int maxCachedElements;

  /** Maximum cached data in bytes */
  final long maxCachedData;

  /** Currently cached data in bytes */
  private long cachedData;

  /** Map from ArchiveKey to ArchiveStoreElement */
  private final LRUMap<ArchiveKey, ArchiveStoreItem> storedData;

  /** Bucket Factory */
  private final BucketFactory tempBucketFactory;

  /**
   * Creates a new manager with bounded handler and data caches.
   *
   * @param maxHandlers maximum number of cached handlers, limiting concurrently remembered
   *     containers
   * @param maxCachedData maximum total cache size in bytes (post-padding and overheads)
   * @param maxArchivedFileSize maximum allowed extracted size in bytes for a single archive member
   * @param maxCachedElements maximum number of cached file entries across all archives
   * @param tempBucketFactory factory used to create temporary buckets for extracted outputs
   */
  public ArchiveManager(
      int maxHandlers,
      long maxCachedData,
      long maxArchivedFileSize,
      int maxCachedElements,
      BucketFactory tempBucketFactory) {
    maxArchiveHandlers = maxHandlers;
    // Note: Performance - assuming there isn't much locality here, so it's faster to use the
    // FAST_COMPARATOR.
    // This may not be true if there are a lot of sites with many containers all inserted as
    // individual SSKs?
    archiveHandlers = LRUMap.createSafeMap(FreenetURI.FAST_COMPARATOR);
    this.maxCachedElements = maxCachedElements;
    this.maxCachedData = maxCachedData;
    storedData = new LRUMap<>();
    this.maxArchivedFileSize = maxArchivedFileSize;
    this.tempBucketFactory = tempBucketFactory;
  }

  /** Add an ArchiveHandler by key */
  private synchronized void putCached(FreenetURI key, ArchiveStoreContext zip) {
    if (LOG.isDebugEnabled()) LOG.debug("Archive handler cached: key={} handler={}", key, zip);
    archiveHandlers.push(key, zip);
    while (archiveHandlers.size() > maxArchiveHandlers) archiveHandlers.popKey(); // dump it
  }

  /** Get an ArchiveHandler by key */
  ArchiveStoreContext getCached(FreenetURI key) {
    if (LOG.isDebugEnabled()) LOG.debug("Archive handler lookup: key={}", key);
    ArchiveStoreContext handler = archiveHandlers.get(key);
    if (handler == null) return null;
    archiveHandlers.push(key, handler);
    return handler;
  }

  /**
   * Create an archive handler. This does not need to know how to fetch the key, because the methods
   * called later will ask. It will try to serve from a cache, but if that fails, it will re-fetch.
   *
   * @param key The key of the archive that we are extracting data from.
   * @param archiveType The archive type, defined in Metadata.
   * @return An archive handler.
   */
  synchronized ArchiveStoreContext makeContext(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE ctype,
      boolean returnNullIfNotFound) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("makeContext: compressor={}", ctype);
    }
    ArchiveStoreContext handler;
    handler = getCached(key);
    if (handler != null) return handler;
    if (returnNullIfNotFound) return null;
    handler = new ArchiveStoreContext(key, archiveType);
    putCached(key, handler);
    return handler;
  }

  /**
   * Creates a handler for interacting with a specific archive.
   *
   * <p>The returned handler consults the cache state when possible and performs extraction on
   * demand. The {@code persistent} flag may influence higher-level workflows but is not enforced
   * here.
   *
   * @param key archive key identifying the container to open; must not be {@code null}
   * @param archiveType archive format to expect when processing the stream
   * @param ctype optional compressor type for compressed containers; {@code null} for none
   * @param forceRefetch whether to bypass the cached handler state and rebuild a fresh view
   * @param persistent whether the resulting workflow participates in persistent client flows
   * @return a non-null handler for later archive operations
   */
  public ArchiveHandler makeHandler(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE ctype,
      boolean forceRefetch,
      boolean persistent) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("makeHandler: persistent={}", persistent);
    }
    return new ArchiveHandlerImpl(key, archiveType, ctype, forceRefetch);
  }

  /**
   * Returns a cached, previously extracted file from an archive if available.
   *
   * <p>This does not trigger a new extraction. When present, the returned {@link Bucket} is
   * readable and owned by the cache; callers should read or copy its contents and free resources
   * when done.
   *
   * @param key the archive key used at extraction time; must match the cached record
   * @param filename the exact member name within the archive, using normalized separators
   * @return a readable bucket for the cached file, or {@code null} when not cached
   * @throws ArchiveFailureException if a cached record exists but cannot be opened for reading
   */
  public Bucket getCached(FreenetURI key, String filename) throws ArchiveFailureException {
    if (LOG.isDebugEnabled())
      LOG.debug("Archive entry cache lookup: key={} name={}", key, filename);
    ArchiveKey k = new ArchiveKey(key, filename);
    ArchiveStoreItem asi;
    synchronized (this) {
      asi = storedData.get(k);
      if (asi == null) return null;
      // Promote to top of LRU
      storedData.push(k, asi);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Archive entry cache hit");
    return asi.getReaderBucket();
  }

  /**
   * Remove a file from the cache. Called after it has been removed from its ArchiveHandler.
   *
   * @param item The ArchiveStoreItem to remove.
   */
  synchronized void removeCachedItem(ArchiveStoreItem item) {
    long size = item.spaceUsed();
    storedData.removeKey(item.key);
    // Hard disk space limit = remove it here.
    // Soft disk space limit would be to remove it outside the lock.
    // Soft disk space limit = we go over the limit significantly when we
    // are overloaded.
    cachedData -= size;
    if (LOG.isDebugEnabled()) LOG.debug("Archive cache remove item: {}", item);
    item.close();
  }

  /**
   * Extract data to cache. Call synchronized on ctx.
   *
   * @param input source inputs describing the archive bytes and associated contexts
   * @param elementRequest requested element and callback details; the element may be {@code null}
   * @throws ArchiveFailureException If we could not extract the data, or it was too big, etc.
   * @throws ArchiveRestartException If the request needs to be restarted because the archive
   *     changed.
   */
  void extractToCache(ArchiveExtractionInput input, ArchiveElementRequest elementRequest)
      throws ArchiveFailureException, ArchiveRestartException {

    FreenetURI key = input.key;
    Bucket data = input.data;
    ArchiveContext archiveContext = input.archiveContext;
    ArchiveStoreContext ctx = input.storeContext;
    String element = elementRequest.element;

    MutableBoolean gotElement = element != null ? new MutableBoolean() : null;

    if (LOG.isDebugEnabled()) LOG.debug("Extracting archive: key={}", key);
    ctx.removeAllCachedItems(this); // flush cache anyway
    final long expectedSize = ctx.getLastSize();
    final long archiveSize = data.size();
    /*
     * Set if we need to throw a RestartedException rather than returning success, after we have
     * unpacked everything.
     */
    boolean throwAtExit = false;
    if ((expectedSize != -1) && (archiveSize != expectedSize)) {
      throwAtExit = true;
      ctx.setLastSize(archiveSize);
    }
    byte[] expectedHash = ctx.getLastHash();
    if (expectedHash != null) {
      byte[] realHash;
      try {
        realHash = BucketTools.hash(data);
      } catch (IOException e) {
        throw new ArchiveFailureException("Error reading archive data: " + e, e);
      }
      if (!Arrays.equals(realHash, expectedHash)) throwAtExit = true;
      ctx.setLastHash(realHash);
    }

    if (archiveSize > archiveContext.maxArchiveSize)
      throw new ArchiveFailureException(
          "Archive too big (" + archiveSize + " > " + archiveContext.maxArchiveSize + ")!");
    else if (archiveSize <= 0)
      throw new ArchiveFailureException("Archive too small! (" + archiveSize + ')');
    else if (LOG.isDebugEnabled())
      LOG.debug(
          "Archive container size (possibly compressed): bytes={} bucket={}", archiveSize, data);

    try {
      ArchiveExtractionState state =
          new ArchiveExtractionState(input, elementRequest, gotElement, throwAtExit, expectedSize);
      ExceptionWrapper wrapper = processByCompressor(state);
      checkWrapperException(wrapper);
    } catch (IOException ioe) {
      throw new ArchiveFailureException("An IOE occurred: " + ioe.getMessage(), ioe);
    }
  }

  private void checkWrapperException(ExceptionWrapper wrapper) throws ArchiveFailureException {
    if (wrapper == null) return;
    Exception e = wrapper.get();
    if (e != null)
      throw new ArchiveFailureException(
          "An exception occurred decompressing: " + e.getMessage(), e);
  }

  private ExceptionWrapper processByCompressor(ArchiveExtractionState state)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    ArchiveExtractionInput input = state.input;
    ARCHIVE_TYPE archiveType = input.archiveType;
    COMPRESSOR_TYPE ctype = input.compressorType;
    if ((ctype == null) || (ARCHIVE_TYPE.ZIP == archiveType)) {
      return handleNoCompressionOrZip(state);
    }
    if (ctype == COMPRESSOR_TYPE.BZIP2) {
      return handleBzip2(state);
    }
    if (ctype == COMPRESSOR_TYPE.GZIP) {
      return handleGzip(state);
    }
    if (ctype == COMPRESSOR_TYPE.LZMA_NEW) {
      return handleLzmaNew(state);
    }
    if (ctype == COMPRESSOR_TYPE.LZMA) {
      return handleLzma(state);
    }
    return null;
  }

  private ExceptionWrapper handleNoCompressionOrZip(ArchiveExtractionState state)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Archive stream: no compression");
    try (InputStream is = state.input.data.getInputStream()) {
      handleArchiveWithStream(state, is);
    }
    return null;
  }

  private ExceptionWrapper handleBzip2(ArchiveExtractionState state)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Archive stream: BZIP2 decompression");
    try (InputStream baseIs = state.input.data.getInputStream();
        InputStream is = new BZip2CompressorInputStream(baseIs)) {
      handleArchiveWithStream(state, is);
    }
    return null;
  }

  private ExceptionWrapper handleGzip(ArchiveExtractionState state)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Archive stream: GZIP decompression");
    try (InputStream baseIs = state.input.data.getInputStream();
        InputStream is = new GZIPInputStream(baseIs)) {
      handleArchiveWithStream(state, is);
    }
    return null;
  }

  private ExceptionWrapper handleLzmaNew(ArchiveExtractionState state)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    ExceptionWrapper wrapper = new ExceptionWrapper();
    try (PipedInputStream pis = new PipedInputStream()) {
      // Connect the pipe before handing the reader to the archive handler to avoid races where
      // the reader attempts to consume before the writer is attached ("Pipe not connected").
      final PipedOutputStream pos = new PipedOutputStream(pis);
      ArchiveExtractionInput input = state.input;
      ClientContext context = state.elementRequest.clientContext;
      context
          .getMainExecutor()
          .execute(
              () -> {
                try (InputStream is = input.data.getInputStream();
                    OutputStream os = new BufferedOutputStream(pos)) {
                  Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(
                      is, os, input.data.size(), state.expectedSize);
                } catch (IOException e) {
                  LOG.error("Failed to decompress archive: {}", e, e);
                  wrapper.set(e);
                }
              });
      handleArchiveWithStream(state, pis);
    }
    return wrapper;
  }

  private ExceptionWrapper handleLzma(ArchiveExtractionState state)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Archive stream: LZMA decompression");
    try (InputStream baseIs = state.input.data.getInputStream();
        InputStream is = new LzmaInputStream(baseIs)) {
      handleArchiveWithStream(state, is);
    }
    return null;
  }

  private void handleArchiveWithStream(ArchiveExtractionState state, InputStream is)
      throws ArchiveFailureException, ArchiveRestartException {
    switch (state.input.archiveType) {
      case ZIP -> handleZIPArchive(state, is);
      case TAR ->
          // COMPRESS-449 workaround, see https://freenet.mantishub.io/view.php?id=6921
          handleTARArchive(state, new SkipShieldingInputStream(is));
      default ->
          throw new ArchiveFailureException(
              "Unknown or unsupported archive algorithm " + state.input.archiveType);
    }
  }

  private void handleTARArchive(ArchiveExtractionState state, InputStream data)
      throws ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Scanning TAR archive entries");
    ArchiveExtractionInput input = state.input;
    ArchiveElementRequest elementRequest = state.elementRequest;
    FreenetURI key = input.key;
    String element = elementRequest.element;
    ArchiveExtractCallback callback = elementRequest.callback;
    MutableBoolean gotElement = state.gotElement;
    boolean throwAtExit = state.throwAtExit;
    ClientContext context = elementRequest.clientContext;
    try (TarArchiveInputStream tarIS = new TarArchiveInputStream(data)) {
      byte[] buf = new byte[32768];
      HashSet<String> names = new HashSet<>();
      ArchiveExpansionTracker expansionTracker =
          new ArchiveExpansionTracker(input.archiveContext.maxArchiveSize);
      ArchiveScanResult scanResult =
          scanTarEntries(state, tarIS, names, buf, expansionTracker, key);
      if (scanResult.abortedAfterSuccess()) {
        if (throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");
        return;
      }
      boolean gotMetadata = scanResult.gotMetadata();

      // If no metadata, generate some
      if (!gotMetadata) {
        generateMetadata(state, names);
        trimStoredData();
      }
      if (throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");

      if (!gotElement.booleanValue() && element != null) callback.notInArchive(context);

    } catch (IOException e) {
      throw new ArchiveFailureException("Error reading archive: " + e.getMessage(), e);
    }
  }

  private void handleZIPArchive(ArchiveExtractionState state, InputStream data)
      throws ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Scanning ZIP archive entries");
    ArchiveElementRequest elementRequest = state.elementRequest;
    ArchiveExtractCallback callback = elementRequest.callback;
    String element = elementRequest.element;
    MutableBoolean gotElement = state.gotElement;
    boolean throwAtExit = state.throwAtExit;
    ClientContext context = elementRequest.clientContext;
    try (ZipArchiveInputStream zis = new ZipArchiveInputStream(data)) {
      byte[] buf = new byte[32768];
      HashSet<String> names = new HashSet<>();
      ArchiveExpansionTracker expansionTracker =
          new ArchiveExpansionTracker(state.input.archiveContext.maxArchiveSize);
      ArchiveScanResult scanResult = scanZipEntries(state, zis, names, buf, expansionTracker);
      if (scanResult.abortedAfterSuccess()) {
        if (throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");
        return;
      }
      boolean gotMetadata = scanResult.gotMetadata();

      // If no metadata, generate some
      if (!gotMetadata) {
        generateMetadata(state, names);
        trimStoredData();
      }
      if (throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");

      if (!gotElement.booleanValue() && element != null) callback.notInArchive(context);

    } catch (IOException e) {
      throw new ArchiveFailureException("Error reading archive: " + e.getMessage(), e);
    }
  }

  private boolean handleTarEntry(
      ArchiveEntry entry,
      ArchiveExtractionState state,
      TarArchiveInputStream tarIS,
      Set<String> names,
      byte[] buf,
      ArchiveExpansionTracker expansionTracker,
      boolean failOnArchiveScanLimit)
      throws IOException, ArchiveFailureException, ArchiveScanLimitReachedException {
    FreenetURI key = state.input.key;
    if (entry.isDirectory()) {
      return false;
    }
    expansionTracker.onEntry(failOnArchiveScanLimit);
    String name = stripLeadingSlashes(entry.getName());
    if (isUnsafeEntryName(name)) {
      LOG.error("TAR: unsafe archive entry {} in archive {}", name, key);
      discardRemainingEntryData(tarIS, buf, expansionTracker, true, failOnArchiveScanLimit);
      return false;
    }
    if (names.contains(name)) {
      LOG.error("TAR: duplicate archive entry {} in archive {}", name, key);
      discardRemainingEntryData(tarIS, buf, expansionTracker, true, failOnArchiveScanLimit);
      return false;
    }
    long size = entry.getSize();
    return processArchiveEntry(name, size, tarIS, state, names, buf, expansionTracker);
  }

  private ArchiveScanResult scanTarEntries(
      ArchiveExtractionState state,
      TarArchiveInputStream tarIS,
      Set<String> names,
      byte[] buf,
      ArchiveExpansionTracker expansionTracker,
      FreenetURI key)
      throws IOException, ArchiveFailureException {
    boolean gotMetadata = false;
    for (ArchiveEntry entry = safeNextTarEntry(tarIS);
        entry != null;
        entry = safeNextTarEntry(tarIS)) {
      try {
        gotMetadata |=
            handleTarEntry(
                entry,
                state,
                tarIS,
                names,
                buf,
                expansionTracker,
                shouldFailOnArchiveScanLimit(state.gotElement));
      } catch (ArchiveScanLimitReachedException e) {
        LOG.warn(
            "Stopping TAR scan after requested element in archive {}: {}", key, e.getMessage());
        return new ArchiveScanResult(gotMetadata, true);
      }
    }
    return new ArchiveScanResult(gotMetadata, false);
  }

  private boolean handleZipEntry(
      ArchiveEntry entry,
      ArchiveExtractionState state,
      InputStream zis,
      Set<String> names,
      byte[] buf,
      ArchiveExpansionTracker expansionTracker)
      throws IOException, ArchiveFailureException, ArchiveScanLimitReachedException {
    ArchiveExtractionInput input = state.input;
    FreenetURI key = input.key;
    if (entry.isDirectory()) {
      return false;
    }
    String name = stripLeadingSlashes(entry.getName());
    if (isUnsafeEntryName(name)) {
      LOG.error("ZIP: unsafe archive entry {} in archive {}", name, key);
      discardRemainingEntryData(
          zis, buf, expansionTracker, true, shouldFailOnArchiveScanLimit(state.gotElement));
      return false;
    } else if (names.contains(name)) {
      LOG.error("ZIP: duplicate archive entry {} in archive {}", name, key);
      discardRemainingEntryData(
          zis, buf, expansionTracker, true, shouldFailOnArchiveScanLimit(state.gotElement));
      return false;
    } else {
      long size = getSize(entry);
      return processArchiveEntry(name, size, zis, state, names, buf, expansionTracker);
    }
  }

  private ArchiveScanResult scanZipEntries(
      ArchiveExtractionState state,
      ZipArchiveInputStream zis,
      Set<String> names,
      byte[] buf,
      ArchiveExpansionTracker expansionTracker)
      throws IOException, ArchiveFailureException {
    boolean gotMetadata = false;
    for (ArchiveEntry entry = zis.getNextEntry(); entry != null; entry = zis.getNextEntry()) {
      try {
        if (!entry.isDirectory()) {
          expansionTracker.onEntry(shouldFailOnArchiveScanLimit(state.gotElement));
        }
        gotMetadata |= handleZipEntry(entry, state, zis, names, buf, expansionTracker);
      } catch (ArchiveScanLimitReachedException e) {
        LOG.warn(
            "Stopping ZIP scan after requested element in archive {}: {}",
            state.input.key,
            e.getMessage());
        return new ArchiveScanResult(gotMetadata, true);
      }
    }
    return new ArchiveScanResult(gotMetadata, false);
  }

  private long getSize(ArchiveEntry entry) {
    long size = entry.getSize();
    if (size <= 0 && entry instanceof ZipArchiveEntry z) {
      // Fall back to compressed size when uncompressed size is unknown; still only a hint.
      long compressed = z.getCompressedSize();
      if (compressed > 0) size = compressed;
    }
    if (size <= 0) {
      // Provide a small positive hint so tiny entries can use RAM buckets and migrate if needed.
      // TempBucketFactory treats this as a hint and will migrate to disk on growth/pressure.
      size = Math.min(32L * 1024L, maxArchivedFileSize);
    }
    return size;
  }

  private boolean processArchiveEntry(
      String name,
      long size,
      InputStream in,
      ArchiveExtractionState state,
      Set<String> names,
      byte[] buf,
      ArchiveExpansionTracker expansionTracker)
      throws IOException, ArchiveFailureException, ArchiveScanLimitReachedException {
    ArchiveElementRequest elementRequest = state.elementRequest;
    String element = elementRequest.element;
    ArchiveExtractCallback callback = elementRequest.callback;
    MutableBoolean gotElement = state.gotElement;
    ClientContext context = elementRequest.clientContext;
    boolean isMetadata = METADATA_NAME.equals(name);
    boolean requestedElement = name.equals(element);
    boolean failOnArchiveScanLimit = shouldFailOnArchiveScanLimit(gotElement);
    boolean accountExpandedBytes = !requestedElement;
    if (size > maxArchivedFileSize && !name.equals(element)) {
      addErrorElement(
          state, name, ERR_FILE_TOO_BIG + size + ERR_LIMIT_SUFFIX + maxArchivedFileSize);
      discardRemainingEntryData(in, buf, expansionTracker, true, failOnArchiveScanLimit);
      return isMetadata;
    }

    long realLen = 0;
    Bucket output = tempBucketFactory.makeBucket(size);
    boolean keepOutput = false;
    try {
      boolean shouldFree = false;
      try (OutputStream out = output.getOutputStream()) {
        int readBytes;
        while ((readBytes = in.read(buf)) > 0) {
          if (accountExpandedBytes) {
            expansionTracker.onExpandedBytes(readBytes, failOnArchiveScanLimit);
          }
          out.write(buf, 0, readBytes);
          realLen += readBytes;
          if (realLen > maxArchivedFileSize) {
            addErrorElement(
                state,
                name,
                ERR_FILE_TOO_BIG + maxArchivedFileSize + ERR_LIMIT_SUFFIX + maxArchivedFileSize);
            shouldFree = true;
            break;
          }
        }
      }
      if (shouldFree) {
        discardRemainingEntryData(
            in, buf, expansionTracker, accountExpandedBytes, failOnArchiveScanLimit);
        return isMetadata;
      }
      long finalSize = (size > 0) ? size : realLen;
      if (finalSize <= maxArchivedFileSize) {
        keepOutput = true;
        addStoreElement(state, name, output);
        names.add(name);
        trimStoredData();
      } else {
        // We are here because they asked for this file.
        keepOutput = true;
        callback.gotBucket(output, context);
        gotElement.setTrue();
        addErrorElement(
            state, name, ERR_FILE_TOO_BIG + finalSize + ERR_LIMIT_SUFFIX + maxArchivedFileSize);
      }
      return isMetadata;
    } finally {
      if (!keepOutput) {
        output.free();
      }
    }
  }

  private void discardRemainingEntryData(
      InputStream in,
      byte[] buf,
      ArchiveExpansionTracker expansionTracker,
      boolean accountExpandedBytes,
      boolean failOnArchiveScanLimit)
      throws IOException, ArchiveFailureException, ArchiveScanLimitReachedException {
    int readBytes;
    while ((readBytes = in.read(buf)) > 0) {
      if (accountExpandedBytes) {
        expansionTracker.onExpandedBytes(readBytes, failOnArchiveScanLimit);
      }
    }
  }

  private static final class ArchiveExpansionTracker {
    private final long maxExpandedBytes;
    private int entryCount;
    private long expandedBytes;

    private ArchiveExpansionTracker(long maxExpandedBytes) {
      this.maxExpandedBytes = maxExpandedBytes;
    }

    private void onEntry(boolean failOnArchiveScanLimit)
        throws ArchiveFailureException, ArchiveScanLimitReachedException {
      entryCount++;
      if (entryCount > MAX_ARCHIVE_ENTRIES) {
        throwLimitExceeded(
            ERR_ARCHIVE_ENTRY_COUNT_PREFIX + entryCount + " > " + MAX_ARCHIVE_ENTRIES,
            failOnArchiveScanLimit);
      }
    }

    private void onExpandedBytes(long count, boolean failOnArchiveScanLimit)
        throws ArchiveFailureException, ArchiveScanLimitReachedException {
      if (count <= 0) {
        return;
      }
      if (expandedBytes > Long.MAX_VALUE - count) {
        throwLimitExceeded(
            ERR_ARCHIVE_EXPANDED_SIZE_PREFIX + "overflow while accounting extracted bytes",
            failOnArchiveScanLimit);
      }
      expandedBytes += count;
      if (expandedBytes > maxExpandedBytes) {
        throwLimitExceeded(
            ERR_ARCHIVE_EXPANDED_SIZE_PREFIX + expandedBytes + " > " + maxExpandedBytes,
            failOnArchiveScanLimit);
      }
    }

    private void throwLimitExceeded(String message, boolean failOnArchiveScanLimit)
        throws ArchiveFailureException, ArchiveScanLimitReachedException {
      if (failOnArchiveScanLimit) {
        throw new ArchiveFailureException(message);
      }
      throw new ArchiveScanLimitReachedException(message);
    }
  }

  private static boolean shouldFailOnArchiveScanLimit(MutableBoolean gotElement) {
    return gotElement == null || !gotElement.booleanValue();
  }

  private static final class ArchiveScanLimitReachedException extends Exception {
    @Serial private static final long serialVersionUID = 1L;

    private ArchiveScanLimitReachedException(String message) {
      super(message);
    }
  }

  private record ArchiveScanResult(boolean gotMetadata, boolean abortedAfterSuccess) {}

  private String stripLeadingSlashes(String name) {
    while (name.length() > 1 && name.charAt(0) == '/') name = name.substring(1);
    return name;
  }

  /**
   * Generates synthetic metadata for an archive that does not supply its own.
   *
   * <p>The method builds a directory tree from the collected member names and converts it into a
   * compact {@code Metadata} structure. The resulting binary form is stored under the conventional
   * {@link #METADATA_NAME} entry, enabling clients to inspect archive contents without scanning the
   * raw container.
   *
   * @param state extraction state carrying the cache context and callback wiring
   * @param names set of member names already discovered while scanning the archive
   * @throws ArchiveFailureException if metadata construction or bucket serialization fails
   */
  private void generateMetadata(ArchiveExtractionState state, Set<String> names)
      throws ArchiveFailureException {
    /* What we have to do is to:
     * - Construct a filesystem tree of the names.
     * - Turn each level of the tree into a Metadata object, including those below it, with
     * simple manifests and archive internal redirects.
     * - Turn the master Metadata object into binary metadata, with all its subsidiaries.
     * - Create a .metadata entry containing this data.
     */
    // Root directory.
    // String -> either itself, or another HashMap
    HashMap<String, Object> dir = new HashMap<>();
    for (String name : names) {
      addToDirectory(dir, name, "");
    }
    Metadata metadata = new Metadata(dir, "");
    int x = 0;
    Bucket bucket;
    while (true) {
      try {
        bucket = metadata.toBucket(tempBucketFactory);
        addStoreElement(state, METADATA_NAME, bucket);
        return;
      } catch (MetadataUnresolvedException e) {
        try {
          x = resolve(e, x, state);
        } catch (IOException e1) {
          throw new ArchiveFailureException("Failed to create metadata: " + e1, e1);
        }
      } catch (IOException e1) {
        throw new ArchiveFailureException("Failed to create metadata: " + e1, e1);
      }
    }
  }

  private int resolve(MetadataUnresolvedException e, int x, ArchiveExtractionState state)
      throws IOException {
    for (MetadataResolutionTarget m : e.mustResolve) {
      try {
        addStoreElement(state, ".metadata-" + x++, m.toBucket(tempBucketFactory));
      } catch (MetadataUnresolvedException _) {
        x = resolve(e, x, state);
      }
    }
    return x;
  }

  private void addToDirectory(Map<String, Object> dir, String name, String prefix)
      throws ArchiveFailureException {
    int x = name.indexOf('/');
    if (x < 0) {
      if (dir.containsKey(name)) {
        throw new ArchiveFailureException("Invalid archive: contains " + prefix + name + " twice");
      }
      dir.put(name, name);
    } else {
      String before = name.substring(0, x);
      String after;
      if (x == name.length() - 1) {
        // Last char
        after = "";
      } else after = name.substring(x + 1);
      Object o = dir.get(before);
      if (o == null) {
        o = new HashMap<String, Object>();
        dir.put(before, o);
      } else if (o instanceof String) {
        throw new ArchiveFailureException(
            "Invalid archive: contains " + name + " as both file and dir");
      }
      addToDirectory(Metadata.forceMap(o), after, prefix + before + '/');
    }
  }

  private static ArchiveEntry safeNextTarEntry(TarArchiveInputStream tarIS)
      throws ArchiveFailureException, IOException {
    try {
      return tarIS.getNextEntry();
    } catch (IllegalArgumentException e) {
      throw new ArchiveFailureException("Error reading archive: " + e.getMessage(), e);
    }
  }

  private static boolean isUnsafeEntryName(String rawName) {
    if (rawName == null || rawName.isEmpty()) {
      return true;
    }
    // Normalize separators for robust segment checks
    String name = rawName.replace('\\', '/');

    // Disallow Windows drive-absolute paths like "C:/..."
    if (name.length() >= 3
        && Character.isLetter(name.charAt(0))
        && name.charAt(1) == ':'
        && name.charAt(2) == '/') {
      return true;
    }

    // Disallow traversal via ".." path segments
    String[] segments = name.split("/+", -1);
    for (String seg : segments) {
      if ("..".equals(seg)) return true;
    }
    return false;
  }

  /**
   * Add an error element to the cache. This happens when a single file in the archive is invalid
   * (usually because it is too large).
   *
   * @param state extraction state carrying the cache context
   * @param name The name of the file within the archive.
   * @param error The error message to be included on the eventual exception thrown if anyone tries
   *     to extract the data for this element.
   */
  private void addErrorElement(ArchiveExtractionState state, String name, String error) {
    ArchiveExtractionInput input = state.input;
    ArchiveStoreContext ctx = input.storeContext;
    FreenetURI key = input.key;
    ErrorArchiveStoreItem element = new ErrorArchiveStoreItem(ctx, key, name, error, true);
    element.addToContext();
    if (LOG.isDebugEnabled())
      LOG.debug("Archive cache error item added: {} for {} {}", element, key, name);
    ArchiveStoreItem oldItem;
    synchronized (this) {
      oldItem = storedData.get(element.key);
      storedData.push(element.key, element);
      if (oldItem != null) {
        oldItem.close();
        cachedData -= oldItem.spaceUsed();
        if (LOG.isDebugEnabled()) LOG.debug("Archive cache evict after error insert: {}", oldItem);
      }
    }
  }

  /**
   * Add a store element.
   *
   * @param state extraction state carrying the cache context and callback wiring
   * @param name archive entry name to store
   * @param temp bucket holding the extracted data
   */
  private void addStoreElement(ArchiveExtractionState state, String name, Bucket temp) {
    ArchiveExtractionInput input = state.input;
    ArchiveElementRequest elementRequest = state.elementRequest;
    ArchiveStoreContext ctx = input.storeContext;
    FreenetURI key = input.key;
    MutableBoolean gotElement = state.gotElement;
    String callbackName = elementRequest.element;
    ArchiveExtractCallback callback = elementRequest.callback;
    ClientContext context = elementRequest.clientContext;
    RealArchiveStoreItem element = new RealArchiveStoreItem(ctx, key, name, temp);
    element.addToContext();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Archive cache store item added: {} ( {} {} size {} )",
          element,
          key,
          name,
          element.spaceUsed());
    ArchiveStoreItem oldItem;
    // Let it throw, if it does something is drastically wrong
    Bucket matchBucket = null;
    if (!gotElement.booleanValue() && name.equals(callbackName)) {
      matchBucket = element.getReaderBucket();
    }
    synchronized (this) {
      oldItem = storedData.get(element.key);
      storedData.push(element.key, element);
      cachedData += element.spaceUsed();
      if (oldItem != null) {
        cachedData -= oldItem.spaceUsed();
        if (LOG.isDebugEnabled()) LOG.debug("Archive cache evict after store insert: {}", oldItem);
        oldItem.close();
      }
    }
    if (matchBucket != null) {
      callback.gotBucket(matchBucket, context);
      gotElement.setTrue();
    }
  }

  /** Drop any stored data beyond the limit. Call synchronized on storedData. */
  private void trimStoredData() {
    synchronized (this) {
      while (true) {
        ArchiveStoreItem item;
        if (cachedData <= maxCachedData && storedData.size() <= maxCachedElements) return;
        if (storedData.isEmpty()) {
          // Race condition? cachedData out of sync?
          LOG.error(
              "storedData is empty but still over limit: cachedData={} / {}",
              cachedData,
              maxCachedData);
          return;
        }
        item = storedData.popValue();
        if (item == null) {
          // Defensive: LRUMap#popValue() can return null if empty or on invariant breach
          LOG.error("storedData.popValue() returned null while trimming; aborting trim");
          return;
        }
        long space = item.spaceUsed();
        cachedData -= space;
        // Hard limits = delete the file within lock, soft limits = delete outside of lock
        // Here we use a hard limit
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Dropping {} : cachedData={} of {} stored items : {} of {}",
              item,
              cachedData,
              maxCachedData,
              storedData.size(),
              maxCachedElements);
        item.close();
      }
    }
  }
}
