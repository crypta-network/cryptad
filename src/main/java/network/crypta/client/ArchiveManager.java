package network.crypta.client;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.ExceptionWrapper;
import network.crypta.support.LRUMap;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
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
 * size-limited on-disk cache of extracted members. Typical usage is: obtain a handler for a key and
 * archive type, request specific entries by name, and read the resulting buckets. Frequently
 * requested members remain available through an LRU-managed cache so repeated calls avoid
 * re-processing the full container.
 *
 * <p>Core responsibilities include streaming decompression, validating entry names to prevent path
 * traversal, enforcing per-entry size limits, and recording either the extracted data or a readable
 * error item. Extraction writes into temporary buckets supplied by a {@link BucketFactory}; small
 * outputs may stay in RAM depending on configured thresholds and migrate to disk as they grow or as
 * memory pressure increases.
 *
 * <p>Thread-safety: instances synchronize on themselves when mutating cache structures. When used
 * together with {@code ArchiveStoreContext}, always lock {@code ArchiveStoreContext} before {@code
 * ArchiveManager} to avoid deadlocks.
 */
public class ArchiveManager {
  private static final Logger LOG = LoggerFactory.getLogger(ArchiveManager.class);

  /**
   * Conventional name for generated metadata placed alongside extracted members.
   *
   * <p>When a container lacks explicit metadata, a synthetic description of its directory structure
   * may be produced under this filename so callers can introspect the archive without scanning it.
   */
  public static final String METADATA_NAME = ".metadata";

  private static final String ERR_FILE_TOO_BIG = "File too big: ";
  private static final String ERR_LIMIT_SUFFIX = " greater than current archived file size limit ";

  /**
   * Supported archive formats.
   *
   * <p>This enum is persisted. Renaming or removing members can break existing data.
   */
  public enum ARCHIVE_TYPE {
    /** ZIP archives; common MIME aliases are supported. */
    ZIP(
        (short) 0,
        new String[] {
          "application/zip", "application/x-zip"
        }), /* eventually get rid of ZIP support at some point */
    /** TAR archives; standard TAR MIME type is supported. */
    TAR((short) 1, new String[] {"application/x-tar"});

    /** Stable numeric identifier for this type used in serialized metadata and messages. */
    public final short metadataID;

    private final String[] mimeTypes;

    /** cached values(). Never modify or pass this array to outside code! */
    private static final ARCHIVE_TYPE[] values = values();

    /**
     * Creates a new enum member.
     *
     * @param metadataID stable, persisted identifier for this archive type
     * @param mimeTypes recognized MIME aliases, compared case-insensitively
     */
    ARCHIVE_TYPE(short metadataID, String[] mimeTypes) {
      this.metadataID = metadataID;
      this.mimeTypes = mimeTypes;
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
      for (ARCHIVE_TYPE current : values)
        for (String ctype : current.mimeTypes) if (ctype.equalsIgnoreCase(type)) return true;
      return false;
    }

    /**
     * Resolves an archive type from a MIME string.
     *
     * @param type MIME string to resolve
     * @return matching {@link ARCHIVE_TYPE}, or {@code null} if unsupported
     */
    public static ARCHIVE_TYPE getArchiveType(String type) {
      for (ARCHIVE_TYPE current : values)
        for (String ctype : current.mimeTypes) if (ctype.equalsIgnoreCase(type)) return current;
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
     * @return non-null MIME string suitable for labelling responses
     */
    public String defaultMimeType() {
      return mimeTypes[0];
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
    if (LOG.isDebugEnabled()) LOG.debug("Put cached AH for {} : {}", key, zip);
    archiveHandlers.push(key, zip);
    while (archiveHandlers.size() > maxArchiveHandlers) archiveHandlers.popKey(); // dump it
  }

  /** Get an ArchiveHandler by key */
  ArchiveStoreContext getCached(FreenetURI key) {
    if (LOG.isDebugEnabled()) LOG.debug("Get cached AH for {}", key);
    ArchiveStoreContext handler = archiveHandlers.get(key);
    if (handler == null) return null;
    archiveHandlers.push(key, handler);
    return handler;
  }

  /**
   * Create an archive handler. This does not need to know how to fetch the key, because the methods
   * called later will ask. It will try to serve from cache, but if that fails, will re-fetch.
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
   * <p>The returned handler consults cache state when possible and performs extraction on demand.
   * The {@code persistent} flag may influence higher-level workflows but is not enforced here.
   *
   * @param key archive key identifying the container to open; must not be {@code null}
   * @param archiveType archive format to expect when processing the stream
   * @param ctype optional compressor type for compressed containers; {@code null} for none
   * @param forceRefetch whether to bypass cached handler state and rebuild a fresh view
   * @param persistent whether the resulting workflow participates in persistent client flows
   * @return a non-null handler for subsequent archive operations
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
   * <p>This does not trigger new extraction. When present, the returned {@link Bucket} is readable
   * and owned by the cache; callers should read or copy its contents and free resources when done.
   *
   * @param key the archive key used at extraction time; must match the cached record
   * @param filename the exact member name within the archive, using normalized separators
   * @return a readable bucket for the cached file, or {@code null} when not cached
   * @throws ArchiveFailureException if a cached record exists but cannot be opened for reading
   */
  public Bucket getCached(FreenetURI key, String filename) throws ArchiveFailureException {
    if (LOG.isDebugEnabled()) LOG.debug("Fetch cached: {} {}", key, filename);
    ArchiveKey k = new ArchiveKey(key, filename);
    ArchiveStoreItem asi;
    synchronized (this) {
      asi = storedData.get(k);
      if (asi == null) return null;
      // Promote to top of LRU
      storedData.push(k, asi);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Found data");
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
    if (LOG.isDebugEnabled()) LOG.debug("removeCachedItem: {}", item);
    item.close();
  }

  /**
   * Extract data to cache. Call synchronized on ctx.
   *
   * @param key The key the data was fetched from.
   * @param archiveType The archive type. Must be Metadata.ARCHIVE_ZIP | Metadata.ARCHIVE_TAR.
   * @param data The actual data fetched.
   * @param archiveContext The context for the whole fetch process.
   * @param ctx The ArchiveStoreContext for this key.
   * @param element A particular element that the caller is especially interested in, or null.
   * @param callback A callback to be called if we find that element, or if we don't.
   * @throws ArchiveFailureException If we could not extract the data, or it was too big, etc.
   * @throws ArchiveRestartException If the request needs to be restarted because the archive
   *     changed.
   */
  void extractToCache(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE ctype,
      final Bucket data,
      ArchiveContext archiveContext,
      ArchiveStoreContext ctx,
      String element,
      ArchiveExtractCallback callback,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException {

    MutableBoolean gotElement = element != null ? new MutableBoolean() : null;

    if (LOG.isDebugEnabled()) LOG.debug("Extracting {}", key);
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
      LOG.debug("Container size (possibly compressed): {} for {}", archiveSize, data);

    try {
      ExceptionWrapper wrapper =
          processByCompressor(
              archiveType,
              ctype,
              data,
              ctx,
              key,
              element,
              callback,
              gotElement,
              throwAtExit,
              context,
              expectedSize);
      checkWrapperException(wrapper);
    } catch (IOException ioe) {
      throw new ArchiveFailureException("An IOE occured: " + ioe.getMessage(), ioe);
    }
  }

  private void checkWrapperException(ExceptionWrapper wrapper) throws ArchiveFailureException {
    if (wrapper == null) return;
    Exception e = wrapper.get();
    if (e != null)
      throw new ArchiveFailureException("An exception occured decompressing: " + e.getMessage(), e);
  }

  private ExceptionWrapper processByCompressor(
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE ctype,
      Bucket data,
      ArchiveStoreContext ctx,
      FreenetURI key,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context,
      long expectedSize)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if ((ctype == null) || (ARCHIVE_TYPE.ZIP == archiveType)) {
      return handleNoCompressionOrZip(
          archiveType, ctx, key, data, element, callback, gotElement, throwAtExit, context);
    }
    if (ctype == COMPRESSOR_TYPE.BZIP2) {
      return handleBzip2(
          archiveType, ctx, key, data, element, callback, gotElement, throwAtExit, context);
    }
    if (ctype == COMPRESSOR_TYPE.GZIP) {
      return handleGzip(
          archiveType, ctx, key, data, element, callback, gotElement, throwAtExit, context);
    }
    if (ctype == COMPRESSOR_TYPE.LZMA_NEW) {
      return handleLzmaNew(
          archiveType,
          ctx,
          key,
          data,
          element,
          callback,
          gotElement,
          throwAtExit,
          context,
          expectedSize);
    }
    if (ctype == COMPRESSOR_TYPE.LZMA) {
      return handleLzma(
          archiveType, ctx, key, data, element, callback, gotElement, throwAtExit, context);
    }
    return null;
  }

  private ExceptionWrapper handleNoCompressionOrZip(
      ARCHIVE_TYPE archiveType,
      ArchiveStoreContext ctx,
      FreenetURI key,
      Bucket data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("No compression");
    try (InputStream is = data.getInputStream()) {
      handleArchiveWithStream(
          archiveType, ctx, key, is, element, callback, gotElement, throwAtExit, context);
    }
    return null;
  }

  private ExceptionWrapper handleBzip2(
      ARCHIVE_TYPE archiveType,
      ArchiveStoreContext ctx,
      FreenetURI key,
      Bucket data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("dealing with BZIP2");
    try (InputStream baseIs = data.getInputStream();
        InputStream is = new BZip2CompressorInputStream(baseIs)) {
      handleArchiveWithStream(
          archiveType, ctx, key, is, element, callback, gotElement, throwAtExit, context);
    }
    return null;
  }

  private ExceptionWrapper handleGzip(
      ARCHIVE_TYPE archiveType,
      ArchiveStoreContext ctx,
      FreenetURI key,
      Bucket data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("dealing with GZIP");
    try (InputStream baseIs = data.getInputStream();
        InputStream is = new GZIPInputStream(baseIs)) {
      handleArchiveWithStream(
          archiveType, ctx, key, is, element, callback, gotElement, throwAtExit, context);
    }
    return null;
  }

  private ExceptionWrapper handleLzmaNew(
      ARCHIVE_TYPE archiveType,
      ArchiveStoreContext ctx,
      FreenetURI key,
      Bucket data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context,
      long expectedSize)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    ExceptionWrapper wrapper = new ExceptionWrapper();
    try (PipedInputStream pis = new PipedInputStream()) {
      // Connect the pipe before handing the reader to the archive handler to avoid races where
      // the reader attempts to consume before the writer is attached ("Pipe not connected").
      final PipedOutputStream pos = new PipedOutputStream(pis);
      context
          .getMainExecutor()
          .execute(
              () -> {
                try (InputStream is = data.getInputStream();
                    OutputStream os = new BufferedOutputStream(pos)) {
                  Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(is, os, data.size(), expectedSize);
                } catch (IOException e) {
                  LOG.error("Failed to decompress archive: {}", e, e);
                  wrapper.set(e);
                }
              });
      handleArchiveWithStream(
          archiveType, ctx, key, pis, element, callback, gotElement, throwAtExit, context);
    }
    return wrapper;
  }

  private ExceptionWrapper handleLzma(
      ARCHIVE_TYPE archiveType,
      ArchiveStoreContext ctx,
      FreenetURI key,
      Bucket data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws IOException, ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("dealing with LZMA");
    try (InputStream baseIs = data.getInputStream();
        InputStream is = new LzmaInputStream(baseIs)) {
      handleArchiveWithStream(
          archiveType, ctx, key, is, element, callback, gotElement, throwAtExit, context);
    }
    return null;
  }

  private void handleArchiveWithStream(
      ARCHIVE_TYPE archiveType,
      ArchiveStoreContext ctx,
      FreenetURI key,
      InputStream is,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException {
    switch (archiveType) {
      case ZIP ->
          handleZIPArchive(ctx, key, is, element, callback, gotElement, throwAtExit, context);
      case TAR ->
          // COMPRESS-449 workaround, see https://freenet.mantishub.io/view.php?id=6921
          handleTARArchive(
              ctx,
              key,
              new SkipShieldingInputStream(is),
              element,
              callback,
              gotElement,
              throwAtExit,
              context);
      default ->
          throw new ArchiveFailureException(
              "Unknown or unsupported archive algorithm " + archiveType);
    }
  }

  private void handleTARArchive(
      ArchiveStoreContext ctx,
      FreenetURI key,
      InputStream data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Handling a TAR Archive");
    try (TarArchiveInputStream tarIS = new TarArchiveInputStream(data)) {
      byte[] buf = new byte[32768];
      HashSet<String> names = new HashSet<>();
      boolean gotMetadata = false;
      for (ArchiveEntry entry = safeNextTarEntry(tarIS);
          entry != null;
          entry = safeNextTarEntry(tarIS)) {
        if (!entry.isDirectory()) {
          String name = stripLeadingSlashes(entry.getName());
          if (isUnsafeEntryName(name)) {
            LOG.error("Unsafe archive entry {} in archive {}", name, key);
          } else if (names.contains(name)) {
            LOG.error("Duplicate key {} in archive {}", name, key);
          } else {
            long size = entry.getSize();
            gotMetadata |=
                processArchiveEntry(
                    name,
                    size,
                    tarIS,
                    ctx,
                    key,
                    element,
                    callback,
                    gotElement,
                    names,
                    buf,
                    context);
          }
        }
      }

      // If no metadata, generate some
      if (!gotMetadata) {
        generateMetadata(ctx, key, names, gotElement, element, callback, context);
        trimStoredData();
      }
      if (throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");

      if ((!gotElement.booleanValue()) && element != null) callback.notInArchive(context);

    } catch (IOException e) {
      throw new ArchiveFailureException("Error reading archive: " + e.getMessage(), e);
    }
  }

  private void handleZIPArchive(
      ArchiveStoreContext ctx,
      FreenetURI key,
      InputStream data,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      boolean throwAtExit,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException {
    if (LOG.isDebugEnabled()) LOG.debug("Handling a ZIP Archive");
    try (ZipArchiveInputStream zis = new ZipArchiveInputStream(data)) {
      byte[] buf = new byte[32768];
      HashSet<String> names = new HashSet<>();
      boolean gotMetadata = false;
      for (ArchiveEntry entry = zis.getNextEntry(); entry != null; entry = zis.getNextEntry()) {
        gotMetadata |=
            handleZipEntry(
                entry, ctx, key, zis, element, callback, gotElement, names, buf, context);
      }

      // If no metadata, generate some
      if (!gotMetadata) {
        generateMetadata(ctx, key, names, gotElement, element, callback, context);
        trimStoredData();
      }
      if (throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");

      if ((!gotElement.booleanValue()) && element != null) callback.notInArchive(context);

    } catch (IOException e) {
      throw new ArchiveFailureException("Error reading archive: " + e.getMessage(), e);
    }
  }

  private boolean handleZipEntry(
      ArchiveEntry entry,
      ArchiveStoreContext ctx,
      FreenetURI key,
      InputStream zis,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      Set<String> names,
      byte[] buf,
      ClientContext context)
      throws IOException, ArchiveFailureException {
    if (entry.isDirectory()) {
      return false;
    }
    String name = stripLeadingSlashes(entry.getName());
    if (isUnsafeEntryName(name)) {
      LOG.error("Unsafe archive entry {} in archive {}", name, key);
      return false;
    } else if (names.contains(name)) {
      LOG.error("Duplicate key {} in archive {}", name, key);
      return false;
    } else {
      long size = getSize(entry);
      return processArchiveEntry(
          name, size, zis, ctx, key, element, callback, gotElement, names, buf, context);
    }
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
      ArchiveStoreContext ctx,
      FreenetURI key,
      String element,
      ArchiveExtractCallback callback,
      MutableBoolean gotElement,
      Set<String> names,
      byte[] buf,
      ClientContext context)
      throws IOException, ArchiveFailureException {
    boolean isMetadata = METADATA_NAME.equals(name);
    if (size > maxArchivedFileSize && !name.equals(element)) {
      addErrorElement(
          ctx, key, name, ERR_FILE_TOO_BIG + size + ERR_LIMIT_SUFFIX + maxArchivedFileSize);
      return isMetadata;
    }

    long realLen = 0;
    Bucket output = tempBucketFactory.makeBucket(size);
    boolean shouldFree = false;
    try (OutputStream out = output.getOutputStream()) {
      int readBytes;
      while ((readBytes = in.read(buf)) > 0) {
        out.write(buf, 0, readBytes);
        realLen += readBytes;
        if (realLen > maxArchivedFileSize) {
          addErrorElement(
              ctx,
              key,
              name,
              ERR_FILE_TOO_BIG + maxArchivedFileSize + ERR_LIMIT_SUFFIX + maxArchivedFileSize);
          shouldFree = true;
          break;
        }
      }
    }
    if (shouldFree) {
      output.free();
      return isMetadata;
    }
    long finalSize = (size > 0) ? size : realLen;
    if (finalSize <= maxArchivedFileSize) {
      addStoreElement(ctx, key, name, output, gotElement, element, callback, context);
      names.add(name);
      trimStoredData();
    } else {
      // We are here because they asked for this file.
      callback.gotBucket(output, context);
      gotElement.setTrue();
      addErrorElement(
          ctx, key, name, ERR_FILE_TOO_BIG + finalSize + ERR_LIMIT_SUFFIX + maxArchivedFileSize);
    }
    return isMetadata;
  }

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
   * @param ctx archive store context used to register the generated metadata in the local cache
   * @param key archive key from which the container was fetched; used for cache indexing
   * @param names set of member names already discovered while scanning the archive
   * @param gotElement flag that is updated when the requested element is satisfied via callback
   * @param element2 optional element name the caller is particularly interested in; when equal to
   *     {@link #METADATA_NAME} the {@code callback} is invoked with the generated bucket
   * @param callback callback notified when the requested element is produced by this method
   * @param context client context passed through to the callback
   * @throws ArchiveFailureException if metadata construction or bucket serialization fails
   */
  private void generateMetadata(
      ArchiveStoreContext ctx,
      FreenetURI key,
      Set<String> names,
      MutableBoolean gotElement,
      String element2,
      ArchiveExtractCallback callback,
      ClientContext context)
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
        addStoreElement(ctx, key, METADATA_NAME, bucket, gotElement, element2, callback, context);
        return;
      } catch (MetadataUnresolvedException e) {
        try {
          x = resolve(e, x, tempBucketFactory, ctx, key, gotElement, element2, callback, context);
        } catch (IOException e1) {
          throw new ArchiveFailureException("Failed to create metadata: " + e1, e1);
        }
      } catch (IOException e1) {
        throw new ArchiveFailureException("Failed to create metadata: " + e1, e1);
      }
    }
  }

  private int resolve(
      MetadataUnresolvedException e,
      int x,
      BucketFactory bf,
      ArchiveStoreContext ctx,
      FreenetURI key,
      MutableBoolean gotElement,
      String element2,
      ArchiveExtractCallback callback,
      ClientContext context)
      throws IOException, ArchiveFailureException {
    for (Metadata m : e.mustResolve) {
      try {
        addStoreElement(
            ctx,
            key,
            ".metadata-" + (x++),
            m.toBucket(bf),
            gotElement,
            element2,
            callback,
            context);
      } catch (MetadataUnresolvedException _) {
        x = resolve(e, x, bf, ctx, key, gotElement, element2, callback, context);
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
   * @param ctx The ArchiveStoreContext which must be notified about this element's creation.
   * @param key The key from which the archive was fetched.
   * @param name The name of the file within the archive.
   * @param error The error message to be included on the eventual exception thrown, if anyone tries
   *     to extract the data for this element.
   */
  private void addErrorElement(ArchiveStoreContext ctx, FreenetURI key, String name, String error) {
    ErrorArchiveStoreItem element = new ErrorArchiveStoreItem(ctx, key, name, error, true);
    element.addToContext();
    if (LOG.isDebugEnabled()) LOG.debug("Adding error element: {} for {} {}", element, key, name);
    ArchiveStoreItem oldItem;
    synchronized (this) {
      oldItem = storedData.get(element.key);
      storedData.push(element.key, element);
      if (oldItem != null) {
        oldItem.close();
        cachedData -= oldItem.spaceUsed();
        if (LOG.isDebugEnabled())
          LOG.debug("Dropping old store element from archive cache: {}", oldItem);
      }
    }
  }

  /**
   * Add a store element.
   *
   * @param callbackName If set, the name of the file for which we must call the callback if this
   *     file happens to match.
   * @param gotElement Flag indicating whether we've already found the file for the callback. If so
   *     we must not call it again.
   * @param callback Callback to be called if we do find it. We must getReaderBucket() before adding
   *     the data to the LRU, otherwise it may be deleted before it reaches the client.
   * @throws ArchiveFailureException If a failure occurred resulting in the data not being readable.
   *     Only happens if callback != null.
   */
  private void addStoreElement(
      ArchiveStoreContext ctx,
      FreenetURI key,
      String name,
      Bucket temp,
      MutableBoolean gotElement,
      String callbackName,
      ArchiveExtractCallback callback,
      ClientContext context)
      throws ArchiveFailureException {
    RealArchiveStoreItem element = new RealArchiveStoreItem(ctx, key, name, temp);
    element.addToContext();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Adding store element: {} ( {} {} size {} )", element, key, name, element.spaceUsed());
    ArchiveStoreItem oldItem;
    // Let it throw, if it does something is drastically wrong
    Bucket matchBucket = null;
    if ((!gotElement.booleanValue()) && name.equals(callbackName)) {
      matchBucket = element.getReaderBucket();
    }
    synchronized (this) {
      oldItem = storedData.get(element.key);
      storedData.push(element.key, element);
      cachedData += element.spaceUsed();
      if (oldItem != null) {
        cachedData -= oldItem.spaceUsed();
        if (LOG.isDebugEnabled())
          LOG.debug("Dropping old store element from archive cache: {}", oldItem);
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
        // Hard limits = delete file within lock, soft limits = delete outside of lock
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
