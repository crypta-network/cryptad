package network.crypta.node.updater;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.Version;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for components that subscribe to update keys, fetch new editions, and coordinate
 * post‑fetch processing.
 *
 * <p>This class encapsulates the common control flow used by both core and plugin updaters. It
 * subscribes to a USK, reacts to discovered editions, schedules and runs a {@code ClientGetter}
 * fetch, and then hands the result to subclass hooks for validation and deployment. Instances are
 * long‑lived and typically created once per updater type. They maintain internal state such as the
 * latest available and fetched versions, whether a fetch is currently in progress, and temporary
 * file paths used to persist fetched blobs.
 *
 * <p>Thread‑safety: the updater uses synchronized blocks to protect mutable fields that are shared
 * across callbacks (e.g., edition discovery, fetch success/failure). Subclasses should assume that
 * the abstract callbacks may be invoked from client layer threads and avoid blocking the ticker.
 * I/O is delegated to the client fetcher and to small, bounded parsing steps in this base class.
 * The class is mutable but designed to be driven by the node lifecycle.
 *
 * <ul>
 *   <li>Subscribes to a USK and tracks discovered editions.
 *   <li>Schedules fetches with suitable priorities and temporary file targets.
 *   <li>Provides hooks to parse manifests and process success after fetch completion.
 *   <li>Exposes helper accessors for blob files and progress reporting.
 * </ul>
 *
 * @see network.crypta.node.updater.PluginJarUpdater
 * @see network.crypta.node.updater.CoreUpdater
 */
public abstract class NodeUpdater implements ClientGetCallback, USKCallback, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(NodeUpdater.class);

  /** Maximum allowed manifest size to parse (1 MiB). */
  private static final long MAX_MANIFEST_SIZE = 1024L * 1024L;

  /** Maximum allowed compressed size of the manifest entry (1 MiB). */
  private static final long MAX_MANIFEST_COMPRESSED_SIZE = 1024L * 1024L;

  /** Maximum number of ZIP entries to scan while searching for the manifest. */
  private static final int MAX_ZIP_ENTRIES_SCANNED = 1024;

  /** Maximum number of compressed bytes to read from the ZIP stream overall. */
  private static final long MAX_ZIP_SCAN_BYTES = 16L * 1024L * 1024L; // 16 MiB

  private final FetchContext ctx;
  private ClientGetter cg;
  private FreenetURI uri;
  private final Ticker ticker;

  /**
   * Owning client core used to create fetch contexts, schedule requests, and access alerts and
   * persistence. The reference is stable and not reassigned after construction.
   */
  public final NodeClientCore core;

  /**
   * Hosting node that provides environment information and directory paths. Subclasses use it for
   * follow‑up actions after a successful fetch.
   */
  protected final Node node;

  /**
   * Coordinator that owns and orchestrates updater instances. It controls enablement, auto‑update
   * policies, and top‑level alerting behavior across the application.
   */
  public final NodeUpdateManager manager;

  private final int currentVersion;
  private int realAvailableVersion;
  private int availableVersion;
  private int fetchingVersion;

  /**
   * Most recently fetched edition number. Increases as newer editions are downloaded and is used to
   * determine whether further fetches are necessary.
   */
  protected int fetchedVersion;

  private int maxDeployVersion;
  private int minDeployVersion;
  private boolean isRunning;
  private boolean isFetching;
  private final String blobFilenamePrefix;

  /**
   * Temporary file used during the current fetch. On success, the file is renamed to a finalized
   * {@code .fblob}. Subclasses may read or delete it as part of deployment.
   */
  protected File tempBlobFile;

  /**
   * Returns a human‑readable name for the artifact handled by this updater.
   *
   * <p>The name appears in log messages and user alerts. Implementations typically return a plugin
   * identifier or a concise descriptor of the core manifest.
   *
   * @return a concise artifact name suitable for logs and UI; never {@code null}
   */
  public abstract String artifactName();

  NodeUpdater(
      NodeUpdateManager manager,
      FreenetURI updateUri,
      int current,
      int min,
      int max,
      String blobFilenamePrefix) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    this.manager = manager;
    this.node = manager.getNode();
    this.uri = updateUri.setSuggestedEdition(((long) Version.currentBuildNumber()) + 1);
    this.ticker = node.network().ticker();
    this.core = node.services().clientCore();
    this.currentVersion = current;
    this.availableVersion = -1;
    this.isRunning = true;
    this.cg = null;
    this.isFetching = false;
    this.blobFilenamePrefix = blobFilenamePrefix;
    this.maxDeployVersion = max;
    this.minDeployVersion = min;

    FetchContext tempContext = core.makeClient((short) 0, true, false).getFetchContext();
    tempContext.setAllowSplitfiles(true);
    tempContext.setDontEnterImplicitArchives(false);
    this.ctx = tempContext;
  }

  void start() {
    subscribe(() -> manager.blow("The auto-update URI isn't valid and can't be used", true));
  }

  private void subscribe(Runnable onError) {
    try {
      // because of UoM, this version is actually worth having as well
      USK myUsk = USK.create(this.uri.setSuggestedEdition(currentVersion));
      core.getUskManager().subscribe(myUsk, this, true, getRequestClient());
    } catch (MalformedURLException _) {
      LOG.error("The auto-update URI isn't valid and can't be used");
      onError.run();
    }
  }

  public RequestClient getRequestClient() {
    return this;
  }

  @Override
  public void onFoundEdition(USKFoundEdition foundEdition) {
    if (foundEdition.newKnownGood() && !foundEdition.newSlotToo()) return;
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (LOG.isDebugEnabled()) LOG.debug("Found edition {}", foundEdition.edition());
    int found;
    synchronized (this) {
      if (!isRunning) return;
      found = (int) foundEdition.key().suggestedEdition;

      realAvailableVersion = found;
      if (found > maxDeployVersion) {
        if (LOG.isWarnEnabled())
          LOG.warn(
              "Ignoring {} update edition {}: version too new (min {} max {})",
              artifactName(),
              foundEdition.edition(),
              minDeployVersion,
              maxDeployVersion);
        found = maxDeployVersion;
      }

      if (found <= availableVersion) return;
      if (LOG.isInfoEnabled()) LOG.info("Found {} update edition {}", artifactName(), found);
      LOG.debug(
          "Updating availableVersion from {} to {} and queueing an update",
          availableVersion,
          found);
      this.availableVersion = found;
    }
    finishOnFoundEdition(found);
  }

  private void finishOnFoundEdition(int found) {
    ticker.queueTimedJob(
        this::maybeUpdate, SECONDS.toMillis(60)); // leave some time in case we get later editions
    // LOCKING: Always take the NodeUpdater lock *BEFORE* the NodeUpdateManager lock
    if (found <= currentVersion) {
      LOG.info("Cancelling fetch for {}: not newer than current version {}", found, currentVersion);
      return;
    }
    onStartFetching();
    if (LOG.isDebugEnabled()) LOG.debug("Fetching {} update edition {}", artifactName(), found);
  }

  /**
   * Hook invoked just before a new fetch is scheduled and started.
   *
   * <p>Implementations can use this callback to update UI, reset flags, or perform lightweight
   * bookkeeping. The method must be fast and non‑blocking; heavy work should run after fetch
   * completion.
   */
  protected abstract void onStartFetching();

  /**
   * Attempts to start a fetch for the latest discovered edition.
   *
   * <p>The method skips when already fetching the same edition or when the edition is not newer. It
   * may cancel a stale fetch, prepare a new {@link ClientGetter}, and start it through the client
   * context. Repeated calls are safe; a new request starts only when state warrants.
   */
  public void maybeUpdate() {
    ClientGetter toStart = null;
    if (!manager.isEnabled()) return;
    if (manager.isBlown()) return;
    ClientGetter cancelled = null;
    synchronized (this) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "maybeUpdate: isFetching={}, isRunning={}, availableVersion={}",
            isFetching,
            isRunning,
            availableVersion);

      if (shouldSkipUpdateLocked()) return;

      if (shouldCancelPreviousFetchLocked()) {
        LOG.info("Cancelling previous fetch");
        cancelled = cg;
        cg = null;
      }

      fetchingVersion = availableVersion;
      logStartUpdateIfNeeded(availableVersion);

      try {
        toStart = prepareClientGetterIfNeeded(availableVersion);
        isFetching = true;
      } catch (Exception e) {
        LOG.error("Error while starting the fetching: {}", e, e);
        isFetching = false;
      }
    }

    if (toStart != null)
      try {
        node.services().clientCore().getClientContext().start(toStart);
      } catch (FetchException e) {
        LOG.error("Error while starting the fetching: {}", e, e);
        synchronized (this) {
          isFetching = false;
        }
      } catch (PersistenceDisabledException _) {
        // Impossible
      }
    if (cancelled != null) cancelled.cancel(core.getClientContext());
  }

  private boolean shouldSkipUpdateLocked() {
    if (!isRunning) return true;
    if (isFetching && availableVersion == fetchingVersion) return true;
    return availableVersion <= fetchedVersion;
  }

  private boolean shouldCancelPreviousFetchLocked() {
    return fetchingVersion < minDeployVersion || fetchingVersion == currentVersion;
  }

  private void logStartUpdateIfNeeded(int version) {
    if (version > currentVersion) {
      LOG.info("Starting the update process ({})", version);
      LOG.info("Starting the update process: found the update ({}) now fetching it.", version);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Starting the update process ({})", version);
  }

  private ClientGetter prepareClientGetterIfNeeded(int version) throws IOException {
    if ((cg == null) || cg.isCancelled()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Scheduling request for {}", this.uri.setSuggestedEdition(version));
      if (version > currentVersion && LOG.isInfoEnabled())
        LOG.info("Starting {} fetch for {}", artifactName(), version);
      tempBlobFile =
          File.createTempFile(
              blobFilenamePrefix + version + "-",
              ".fblob.tmp",
              manager.getNode().services().clientCore().getPersistentTempDir());
      FreenetURI uskUri = this.uri.setSuggestedEdition(version);
      uskUri = uskUri.sskForUSK();
      cg =
          new ClientGetter(
              this,
              uskUri,
              ctx,
              RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
              null,
              new BinaryBlobWriter(new FileBucket(tempBlobFile, false, false, false, false)),
              null);
      return cg;
    } else {
      if (LOG.isInfoEnabled())
        LOG.info(
            "Already fetching {} fetch for {} want {}",
            artifactName(),
            fetchingVersion,
            availableVersion);
      return null;
    }
  }

  final File getBlobFile(int availableVersion) {
    return new File(
        node.services().clientCore().getPersistentTempDir(),
        blobFilenamePrefix + availableVersion + ".fblob");
  }

  @SuppressWarnings("unused")
  RandomAccessBucket getBlobBucket(int availableVersion) {
    File f = getBlobFile(availableVersion);
    return new FileBucket(f, true, false, false, false);
  }

  @Override
  public void onSuccess(FetchResult result, ClientGetter state) {
    onSuccess(result, tempBlobFile, fetchingVersion);
  }

  void onSuccess(FetchResult result, File tempBlobFile, int fetchedVersion) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    File blobFile;
    synchronized (this) {
      if (shouldSkipAlreadyFetched(fetchedVersion)) {
        cleanupAlreadyFetched(result, tempBlobFile);
        return;
      }
      if (isEmptyResult(result)) {
        try {
          Files.delete(tempBlobFile.toPath());
        } catch (IOException ex) {
          LOG.warn("Unable to delete temp blob {}", tempBlobFile, ex);
        }
        LOG.error("Cannot update: result either null or empty for {}", availableVersion);
        // Try again immediately; no need to inspect Bucket here
        node.network().ticker().queueTimedJob(this::maybeUpdate, 0);
        return;
      }
      blobFile = tryFinalizeBlobFile(tempBlobFile, fetchedVersion);
      this.fetchedVersion = fetchedVersion;
      if (LOG.isInfoEnabled()) LOG.info("Found {} version {}", artifactName(), fetchedVersion);
      if (fetchedVersion > currentVersion)
        LOG.info(
            "Found version {}, setting up a new UpdatedVersionAvailableUserAlert", fetchedVersion);
      maybeParseManifest(result, fetchedVersion);
      this.cg = null;
    }
    processSuccess(fetchedVersion, result, blobFile);
  }

  private boolean shouldSkipAlreadyFetched(int fetchedVersion) {
    return fetchedVersion <= this.fetchedVersion;
  }

  private void cleanupAlreadyFetched(FetchResult result, File tmp) {
    try {
      Files.delete(tmp.toPath());
    } catch (IOException ex) {
      LOG.warn("Unable to delete temp file {}", tmp, ex);
    }
    if (result != null) {
      Bucket toFree = result.asBucket();
      if (toFree != null) {
        try (var _ = toFree) {
          if (LOG.isDebugEnabled()) LOG.debug("Releasing fetched result bucket");
        }
      }
    }
  }

  private boolean isEmptyResult(FetchResult result) {
    return result == null || result.size() == 0;
  }

  private File tryFinalizeBlobFile(File tmp, int fetchedVersion) {
    File blobFile = getBlobFile(fetchedVersion);
    if (!tmp.renameTo(blobFile)) {
      try {
        Files.delete(blobFile.toPath());
      } catch (IOException ex) {
        LOG.warn("Unable to delete blob file {} before rename", blobFile, ex);
      }
      if (!tmp.renameTo(blobFile)) {
        if (blobFile.exists() && tmp.exists() && blobFile.length() == tmp.length()) {
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Can't rename {} over {} for {} - probably not a big deal though as the files are"
                    + " the same size",
                tmp,
                blobFile,
                fetchedVersion);
        } else {
          LOG.error(
              "Not able to rename binary blob for node updater: {} -> {} - may not be able to"
                  + " tell other peers about this build",
              tmp,
              blobFile);
          blobFile = null;
        }
      }
    }
    return blobFile;
  }

  /**
   * Called after a fetch has completed successfully to perform post‑processing.
   *
   * <p>Implementations typically validate compatibility, persist or rename files, update alerts,
   * and schedule deployment. The call happens after internal state has been updated to reflect the
   * new {@code fetchedVersion}.
   *
   * @param fetched the fetched edition number that completed successfully; strictly positive
   * @param result the fetch result containing the fetched bytes and associated metadata
   * @param blobFile the finalized on‑disk blob, or {@code null} when the rename failed
   */
  protected abstract void processSuccess(int fetched, FetchResult result, File blobFile);

  /**
   * Parses metadata from the freshly fetched result while internal locks are held.
   *
   * <p>The base class does not interpret manifest contents. Subclasses may extract version
   * requirements or other indicators from the fetched data. Implementations should limit work to
   * fast parsing and avoid blocking.
   *
   * @param result the fresh fetch result to inspect; must reference the just‑fetched bytes
   * @param build the edition number associated with {@code result}; used for logging and gating
   */
  protected abstract void maybeParseManifest(FetchResult result, int build);

  /**
   * Parses the JAR manifest from the finalized on‑disk blob.
   *
   * <p>This fallback path is used when a subclass needs to read the manifest after the blob has
   * been finalized on disk. The implementation enforces bounded parsing and delegates each line to
   * {@link #parseManifestLine(String)}.
   */
  protected void parseManifest() {
    // Fallback: parse from the finalized on-disk blob if available, enforcing size cap.
    File jarFile = getBlobFile();
    try (InputStream is = Files.newInputStream(jarFile.toPath())) {
      parseManifestBounded(is);
    } catch (IOException _) {
      LOG.error("IOException trying to read manifest on update");
    } catch (Exception t) {
      LOG.error("Failed to parse update manifest: {}", t, t);
    }
  }

  /**
   * Parses the JAR manifest directly from the freshly fetched bytes.
   *
   * <p>This is preferred over reading from disk because it remains robust when the temporary file
   * cannot be renamed to its final location. Parsing is bounded for safety.
   *
   * @param result a non‑empty {@link FetchResult} containing the fetched JAR bytes
   */
  @SuppressWarnings({"resource", "java:S2095"})
  protected void parseManifest(FetchResult result) {
    if (result == null || result.size() == 0) return;
    Bucket bucket = result.asBucket();
    if (bucket == null) return;
    // Borrow the bucket for reading only; do NOT close/free it here because
    // PluginJarUpdater keeps the FetchResult around to deploy the JAR later.
    try (InputStream is = bucket.getInputStream()) {
      parseManifestBounded(is);
    } catch (IOException _) {
      LOG.error("IOException trying to read manifest from fetched result on update");
    } catch (Exception t) {
      LOG.error("Failed to parse update manifest from fetched result: {}", t, t);
    }
  }

  /**
   * Reads {@code META-INF/MANIFEST.MF} from a ZIP/JAR input stream with strict bounds.
   *
   * <p>The method limits the total number of scanned entries, caps compressed and uncompressed
   * sizes, and stops reading once the manifest has been processed. Parsed lines are dispatched to
   * {@link #parseManifestLine(String)} for interpretation.
   *
   * @param raw the input stream positioned at the start of a ZIP/JAR archive; not closed here
   * @throws IOException if an I/O error occurs while reading from the stream
   */
  private void parseManifestBounded(InputStream raw) throws IOException {
    InputStream bounded = new BoundedInputStream(raw, MAX_ZIP_SCAN_BYTES);
    try (ZipInputStream zis = new ZipInputStream(bounded)) {
      ZipEntry entry;
      int scanned = 0;
      while ((entry = zis.getNextEntry()) != null) {
        if (++scanned > MAX_ZIP_ENTRIES_SCANNED) {
          LOG.error("Too many ZIP entries scanned (>{}); aborting parse", MAX_ZIP_ENTRIES_SCANNED);
          return;
        }
        if (isManifestEntry(entry.getName())) {
          byte[] data = readManifestBytes(zis, entry);
          if (data.length == 0) {
            zis.closeEntry();
            return; // size cap exceeded or IO error already logged
          }
          dispatchManifestLines(data);
          zis.closeEntry();
          return; // Done after parsing manifest
        }
      }
    }
  }

  /**
   * Wraps an {@link InputStream} and limits the total number of bytes that can be read. Once the
   * limit is reached, subsequent reads return {@code -1} (EOF). This protects callers against zip
   * bombs and other excessive input sizes when reading untrusted data.
   */
  private static final class BoundedInputStream extends java.io.FilterInputStream {
    private long remaining;

    BoundedInputStream(InputStream in, long limit) {
      super(in);
      this.remaining = Math.max(0L, limit);
    }

    @Override
    public int read() throws IOException {
      if (remaining <= 0) return -1;
      int b = super.read();
      if (b != -1) remaining--;
      return b;
    }

    @Override
    public int read(byte @org.jetbrains.annotations.NotNull [] b, int off, int len)
        throws IOException {
      if (remaining <= 0) return -1;
      int toRead = (int) Math.min(len, remaining);
      int r = super.read(b, off, toRead);
      if (r > 0) remaining -= r;
      return r;
    }

    @Override
    public long skip(long n) throws IOException {
      long toSkip = Math.min(n, remaining);
      long skipped = super.skip(toSkip);
      if (skipped > 0) remaining -= skipped;
      return skipped;
    }
  }

  /**
   * Returns whether the supplied ZIP entry name refers to the manifest file.
   *
   * @param name entry name as returned by the ZIP stream; case‑insensitive comparison is used
   * @return {@code true} if the entry is the manifest; otherwise {@code false}
   */
  private static boolean isManifestEntry(String name) {
    return "META-INF/MANIFEST.MF".equalsIgnoreCase(name);
  }

  /**
   * Reads the manifest entry into memory enforcing compressed and uncompressed size caps.
   *
   * @param zis the zip input stream positioned at the manifest entry
   * @param entry the manifest entry with metadata such as declared sizes
   * @return a non‑{@code null} byte array containing the manifest contents, or an empty array when
   *     caps are exceeded
   * @throws IOException if reading from the underlying stream fails
   */
  private byte[] readManifestBytes(ZipInputStream zis, ZipEntry entry) throws IOException {
    long declared = entry.getSize();
    if (declared > MAX_MANIFEST_SIZE) {
      LOG.error(
          "Manifest too large ({} bytes > {} cap); aborting parse", declared, MAX_MANIFEST_SIZE);
      return new byte[0];
    }
    long compressed = entry.getCompressedSize();
    if (compressed > MAX_MANIFEST_COMPRESSED_SIZE) {
      LOG.error(
          "Compressed manifest too large ({} bytes > {} cap); aborting parse",
          compressed,
          MAX_MANIFEST_COMPRESSED_SIZE);
      return new byte[0];
    }
    byte[] buf = new byte[8192];
    long total = 0L;
    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
    int r;
    while ((r = zis.read(buf)) != -1) {
      total += r;
      if (total > MAX_MANIFEST_SIZE) {
        LOG.error("Manifest exceeds size cap (>{} bytes); aborting parse", MAX_MANIFEST_SIZE);
        return new byte[0];
      }
      bos.write(buf, 0, r);
    }
    return bos.toByteArray();
  }

  /**
   * Splits the provided manifest bytes into UTF‑8 lines and dispatches them to {@link
   * #parseManifestLine(String)}.
   *
   * @param data the manifest contents encoded as UTF‑8; may be empty to indicate prior failure
   * @throws IOException if the bytes cannot be decoded or the reader fails
   */
  private void dispatchManifestLines(byte[] data) throws IOException {
    try (BufferedReader br =
        new BufferedReader(
            new InputStreamReader(new ByteArrayInputStream(data), StandardCharsets.UTF_8))) {
      String line;
      while ((line = br.readLine()) != null) {
        parseManifestLine(line);
      }
    }
  }

  // Legacy dependencies.properties parsing hooks removed.

  /**
   * Interprets a single manifest line parsed by {@link #parseManifest()} or {@link
   * #parseManifest(FetchResult)}.
   *
   * <p>The base implementation is a no‑op. Subclasses override to capture values relevant to their
   * compatibility or deployment logic. The {@code line} does not include a trailing newline.
   *
   * @param line a single raw manifest line to interpret; never {@code null}
   */
  protected void parseManifestLine(String line) {
    // Do nothing by default; subclasses override if they need to parse manifest entries.
  }

  @Override
  public void onFailure(FetchException e) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (!isRunning) return;
    FetchExceptionMode errorCode = e.getMode();
    try {
      Files.delete(tempBlobFile.toPath());
    } catch (IOException ex) {
      LOG.warn("Unable to delete temp blob {} on failure", tempBlobFile, ex);
    }

    if (LOG.isDebugEnabled()) LOG.debug("onFailure({},{})", e, cg);
    synchronized (this) {
      this.cg = null;
      isFetching = false;
    }
    if (errorCode == FetchExceptionMode.CANCELLED || !e.isFatal()) {
      LOG.info("Rescheduling new request");
      ticker.queueTimedJob(this::maybeUpdate, 0);
    } else {
      LOG.error("Canceling fetch : {}", e.getMessage());
      LOG.error("Unexpected error fetching update: {}", e.getMessage());
      // Fatal error: wait for the next version; do not reschedule now.
    }
  }

  /** Called before {@link #kill()} to mark the updater as stopping. Avoids taking locks. */
  public void preKill() {
    isRunning = false;
  }

  /** Cancels any active fetch and unsubscribes from the USK. Safe to call multiple times. */
  void kill() {
    try {
      ClientGetter c;
      synchronized (this) {
        isRunning = false;
        USK myUsk = USK.create(this.uri.setSuggestedEdition(currentVersion));
        core.getUskManager().unsubscribe(myUsk, this);
        c = cg;
        cg = null;
      }
      c.cancel(core.getClientContext());
    } catch (Exception e) {
      LOG.debug("Cannot kill NodeUpdater", e);
    }
  }

  /**
   * Returns the USK {@link FreenetURI} used to discover update editions for this updater.
   *
   * @return the immutable update key associated with this updater instance
   */
  @SuppressWarnings("unused")
  public FreenetURI getUpdateKey() {
    return uri;
  }

  /**
   * Reports whether a fetched edition newer than the current version is available for deployment.
   *
   * @return {@code true} when a newer fetched version exists; otherwise {@code false}
   */
  public synchronized boolean canUpdateNow() {
    return fetchedVersion > currentVersion;
  }

  /**
   * Called when the fetch URI has changed. No major locks are held by the caller.
   *
   * @param newUri the new update key; its doc name is preserved when the argument omits one
   */
  public void onChangeURI(FreenetURI newUri) {
    String previousDocName;
    synchronized (this) {
      previousDocName = (this.uri != null) ? this.uri.getDocName() : null;
    }
    kill(); // unsubscribes from the old uri
    FreenetURI nextUri =
        (previousDocName != null && (newUri.getDocName() == null || newUri.getDocName().isEmpty()))
            ? newUri.setDocName(previousDocName)
            : newUri;
    synchronized (this) {
      this.uri = nextUri.setSuggestedEdition(((long) Version.currentBuildNumber()) + 1);
      availableVersion = -1;
      realAvailableVersion = -1;
      fetchingVersion = -1;
      fetchedVersion = currentVersion;
      isFetching = false;
      isRunning = true;
    }
    subscribe(() -> {});
    maybeUpdate();
  }

  /**
   * Returns the most recently fetched edition number.
   *
   * @return the last successfully fetched edition, or the current version when none were fetched
   */
  public int getFetchedVersion() {
    return fetchedVersion;
  }

  /**
   * Indicates whether a fetch for a newer edition is currently in progress.
   *
   * @return {@code true} if a fetch is active for a newer edition; otherwise {@code false}
   */
  public boolean isFetching() {
    return availableVersion > fetchedVersion && availableVersion > currentVersion;
  }

  /**
   * Returns the edition number currently being fetched, or the latest available edition.
   *
   * @return an edition number used for progress reporting; never less than the current version
   */
  public int fetchingVersion() {
    // We will not deploy currentVersion...
    if (fetchingVersion <= currentVersion) return availableVersion;
    else return fetchingVersion;
  }

  /**
   * Returns the size in bytes of the finalized blob corresponding to the fetched version.
   *
   * @return a non‑negative size of the blob on disk; {@code 0} when the file is missing
   */
  @SuppressWarnings("unused")
  public long getBlobSize() {
    return getBlobFile(getFetchedVersion()).length();
  }

  /**
   * Returns the path to the finalized blob file for the fetched version.
   *
   * @return a {@link File} pointing at the {@code .fblob} for the fetched edition
   */
  public File getBlobFile() {
    return getBlobFile(getFetchedVersion());
  }

  /** {@inheritDoc} */
  @Override
  public short getPollingPriorityNormal() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  /** {@inheritDoc} */
  @Override
  public short getPollingPriorityProgress() {
    return RequestStarter.INTERACTIVE_PRIORITY_CLASS;
  }

  /** {@inheritDoc} */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * Called by {@link NodeUpdateManager} to update the minimum and maximum deployable versions.
   *
   * <p>This method is invoked when a new core JAR has been downloaded so that the node avoids
   * installing incompatible combinations of main and extension artifacts. If the new bounds make a
   * previously out‑of‑range edition acceptable, a fetch may be scheduled.
   *
   * @param requiredExt the lower bound (inclusive) for acceptable editions; negative values mean
   *     “unchanged”
   * @param recommendedExt the upper bound (inclusive) for acceptable editions; negative values mean
   *     “unchanged”
   */
  @SuppressWarnings("unused")
  public void setMinMax(int requiredExt, int recommendedExt) {
    int callFinishedFound = -1;
    synchronized (this) {
      if (recommendedExt > -1) {
        maxDeployVersion = recommendedExt;
      }
      if (requiredExt > -1) {
        minDeployVersion = requiredExt;
        if (realAvailableVersion != availableVersion
            && availableVersion < requiredExt
            && realAvailableVersion >= requiredExt) {
          // We found a revision but didn't fetch it because it wasn't within the range for the old
          // jar.
          // The new one requires it, however.
          LOG.info(
              "Previously out-of-range edition {} is now needed by the new jar; scheduling fetch.",
              realAvailableVersion);
          callFinishedFound = availableVersion = realAvailableVersion;
        } else if (availableVersion < requiredExt) {
          // Including if it hasn't been found at all
          // Just try it ...
          callFinishedFound = availableVersion = requiredExt;
          LOG.info(
              "Need minimum edition {} for new jar, found {}; scheduling fetch.",
              requiredExt,
              availableVersion);
        }
      }
    }
    if (callFinishedFound > -1) finishOnFoundEdition(callFinishedFound);
  }

  @Override
  public boolean realTimeFlag() {
    return false;
  }

  @Override
  public void onResume(ClientContext context) {
    // Do nothing. Not persistent.
  }
}
