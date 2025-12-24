package network.crypta.client.async;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.Metadata.SimpleManifestComposer;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.BaseManifestPutter.PutHandler;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ResumeFailedException;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts a set of files as a single archive with an embedded {@code .metadata} manifest and hands
 * it off to {@link SingleFileInserter} for the actual network insertion.
 *
 * <p>This class is a thin coordinator that builds a container (either {@code .tar} or {@code .zip})
 * containing the provided content plus the metadata entries required by the manifest/redirect
 * layer. The resulting archive is converted into a single {@link InsertBlock} and then delegated to
 * a {@link SingleFileInserter}. Typical usage is to construct a {@code ContainerInserter} with a
 * manifest-like map (values of {@link Metadata}, {@link ManifestElement}, or nested {@link
 * java.util.Map}) and then schedule it. Persistence is handled via Java serialization; on resume we
 * reattach transient runtime state where applicable.
 *
 * <p>Concurrency: instances are not thread-safe. Callers should synchronize externally if multiple
 * threads may invoke lifecycle methods. Mutability: configuration is fixed at construction time;
 * internal progress state advances as the inserter prepares the archive and transitions ownership
 * to the created {@link SingleFileInserter}. Failure paths close streams and report via the
 * provided callback.
 *
 * <ul>
 *   <li>Builds {@code .metadata} and any additional unresolved metadata parts.
 *   <li>Packages data and metadata into a TAR or ZIP archive.
 *   <li>Delegates insertion to {@link SingleFileInserter} and reports transitions.
 * </ul>
 *
 * @see SingleFileInserter
 * @see Metadata
 * @see ManifestElement
 * @author saces
 */
public class ContainerInserter implements ClientPutState, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(ContainerInserter.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Options used to configure a {@link ContainerInserter}. Reduces constructor parameter count and
   * captures flags that influence archive creation and insertion behavior.
   *
   * <p>Instances of this class are serializable. The {@link #token} is marked {@code transient}
   * because it is an application-supplied correlation object that may not be serializable and is
   * not required to restore insertion state.
   */
  public static final class Options implements Serializable {
    @Serial private static final long serialVersionUID = 1L;

    /**
     * When {@code true}, disables content compression. For {@link ARCHIVE_TYPE#ZIP} this is forced
     * to {@code true} regardless of the requested value so entries are stored uncompressed.
     */
    public final boolean dontCompress;

    /**
     * When {@code true}, perform the metadata preparation flow only and report results without
     * starting the actual network insertion. Useful for dry-run or inspection scenarios.
     */
    public final boolean reportMetadataOnly;

    /**
     * Application correlation token passed through callbacks. It is never serialized; callers own
     * its lifecycle and may supply any object (including {@code null}).
     */
    public final transient Object token;

    /** Archive type to create for the container (e.g., TAR or ZIP). */
    public final ARCHIVE_TYPE archiveType;

    /**
     * Optional explicit encryption key material. When non-{@code null}, it overrides derived keys
     * in downstream inserters. Ownership is not transferred and the array is not defensively
     * copied.
     */
    public final byte[] forceCryptoKey;

    /**
     * Crypto algorithm identifier consumed by downstream inserters. Acceptable values depend on the
     * network configuration; unknown values will cause insertion to fail early.
     */
    public final byte cryptoAlgorithm;

    /**
     * Enables real-time insertion behavior when {@code true}. This can reduce latency at the cost
     * of increased resource use depending on the insertion context.
     */
    public final boolean realTimeFlag;

    /**
     * Constructs an {@link Options} bundle describing how the container and downstream insertion
     * should behave.
     *
     * @param dontCompress set to {@code true} to disable compression of the container contents; ZIP
     *     containers are stored uncompressed regardless of this flag
     * @param reportMetadataOnly set to {@code true} to prepare metadata and report it without
     *     starting the network insertion; used for dry-run and diagnostics
     * @param token arbitrary application token forwarded to callbacks; never serialized and may be
     *     {@code null}
     * @param archiveType the archive format to build for the container; typically TAR or ZIP
     * @param forceCryptoKey optional explicit encryption key material; when non-{@code null},
     *     overrides derived keys in downstream components
     * @param cryptoAlgorithm algorithm identifier understood by downstream inserters; invalid
     *     values will cause the insertion to fail
     * @param realTimeFlag when {@code true}, requests lower-latency, real-time insertion behavior
     */
    public Options(
        boolean dontCompress,
        boolean reportMetadataOnly,
        Object token,
        ARCHIVE_TYPE archiveType,
        byte[] forceCryptoKey,
        byte cryptoAlgorithm,
        boolean realTimeFlag) {
      this.dontCompress = dontCompress;
      this.reportMetadataOnly = reportMetadataOnly;
      this.token = token;
      this.archiveType = archiveType;
      this.forceCryptoKey = forceCryptoKey;
      this.cryptoAlgorithm = cryptoAlgorithm;
      this.realTimeFlag = realTimeFlag;
    }
  }

  private record ContainerElement(Bucket data, String targetInArchive) {}

  /** Items to include in the container archive; populated during metadata resolution. */
  private transient ArrayList<ContainerElement> containerItems;

  /** Owning client putter that created and coordinates this inserter. */
  private final BaseClientPutter parent;

  /** Callback used to report failures, resumes, and state transitions. */
  private final PutCompletionCallback cb;

  /** Indicates that {@link #cancel(ClientContext)} has been invoked. */
  private boolean cancelled;

  /** True once a terminal state has been reached and callbacks have been issued. */
  private boolean finished;

  /** Whether backing buckets should be persistent across restarts. */
  private final boolean persistent;

  /**
   * Original manifest-like map used to build {@code .metadata} entries. See
   * ContainerBuilder._rootDir.
   */
  private final Map<String, Object> origMetadata;

  /** Archive format to build ({@link ARCHIVE_TYPE#TAR} or {@link ARCHIVE_TYPE#ZIP}). */
  private final ARCHIVE_TYPE archiveType;

  /** Target URI that will be used as the base for the inserted content. */
  private final FreenetURI targetURI;

  /** Application token forwarded to downstream components and callbacks. */
  private final Object token;

  /** Insertion context providing configuration and factories needed at runtime. */
  private final InsertContext ctx;

  /** If set, prepares metadata and stops before starting the network insertion. */
  private final boolean reportMetadataOnly;

  /** When {@code true}, disables compression for the generated archive. */
  private final boolean dontCompress;

  /** Optional explicit encryption key; {@code null} to use default/derived keys. */
  final byte[] forceCryptoKey;

  /** Crypto algorithm identifier used by downstream inserters. */
  final byte cryptoAlgorithm;

  /** Requests real-time insertion behavior when {@code true}. */
  private final boolean realTimeFlag;

  /**
   * Creates a new {@link ContainerInserter} that will package the provided manifest-like map and
   * data into an archive and delegate its insertion to a {@link SingleFileInserter}.
   *
   * <p>The constructor records the configuration and performs no I/O. Call {@link #schedule} to
   * build the metadata, package the archive, and initiate the downstream insertion. The {@code
   * metadata2} map may contain nested maps, {@link Metadata} instances, or {@link ManifestElement}
   * entries, which are converted into {@code .metadata} and redirected paths within the container.
   *
   * @param parent2 parent putter that owns this inserter and provides persistence scope
   * @param cb2 completion callback invoked for transitions, failures, and resume notifications; may
   *     be the same instance as {@code parent2}
   * @param metadata2 manifest structure (mutable map) describing the tree to embed; values can be
   *     nested maps, {@link Metadata}, or {@link ManifestElement}
   * @param targetURI2 target URI; callers should provide a cloned, persistent instance suitable for
   *     serialization
   * @param ctx2 insert context supplying bucket factories and operational settings
   * @param options additional options configuring compression, report-only mode, crypto, and token
   */
  public ContainerInserter(
      BaseClientPutter parent2,
      PutCompletionCallback cb2,
      Map<String, Object> metadata2,
      FreenetURI targetURI2,
      InsertContext ctx2,
      Options options) {
    parent = parent2;
    cb = cb2;
    hashCode = super.hashCode();
    persistent = parent.persistent();
    origMetadata = Metadata.forceMap(metadata2);
    archiveType = options.archiveType;
    targetURI = targetURI2;
    token = options.token;
    ctx = ctx2;
    dontCompress = options.dontCompress;
    reportMetadataOnly = options.reportMetadataOnly;
    containerItems = new ArrayList<>();
    this.forceCryptoKey = options.forceCryptoKey;
    this.cryptoAlgorithm = options.cryptoAlgorithm;
    this.realTimeFlag = options.realTimeFlag;
  }

  /**
   * Cancels the insertion before delegation to the downstream inserter or during preparation.
   *
   * <p>After cancellation, a failure is reported to the callback using {@link
   * InsertExceptionMode#CANCELLED}. This method is idempotent and thread-safe.
   *
   * @param context client context used for callback notification
   */
  @Override
  public void cancel(ClientContext context) {
    synchronized (this) {
      if (cancelled) return;
      cancelled = true;
    }
    // Must call onFailure so get removeFrom()'ed
    cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
  }

  /** Returns the owning {@link BaseClientPutter}. */
  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  /** Returns the application-supplied correlation token, which may be {@code null}. */
  @Override
  public Object getToken() {
    return token;
  }

  /**
   * Schedules the preparation and delegation of the container insertion.
   *
   * <p>Creates the {@code .metadata} manifest, packages data and metadata into the configured
   * archive type, and then constructs a {@link SingleFileInserter}. The downstream inserter is
   * returned via {@link PutCompletionCallback#onTransition} and scheduled immediately.
   *
   * @param context insertion context used to obtain buckets and configuration
   * @throws InsertException when preparation fails (e.g., bucket errors or metadata resolution)
   */
  @Override
  public void schedule(ClientContext context) throws InsertException {
    start(context);
  }

  private void start(ClientContext context) {
    if (LOG.isTraceEnabled()) LOG.trace("Attempt to start a container inserter");

    makeMetadata(context);

    synchronized (this) {
      if (finished) return;
    }

    InsertBlock block;
    try {
      RandomAccessBucket outputBucket = context.getBucketFactory(persistent).makeBucket(-1);
      String mimeType;
      try (OutputStream os = new BufferedOutputStream(outputBucket.getOutputStream())) {
        mimeType = (archiveType == ARCHIVE_TYPE.TAR ? createTarBucket(os) : createZipBucket(os));
        // create*Bucket closes os through try-with-resources
      }
      if (LOG.isDebugEnabled()) LOG.debug("Archive size is {}", outputBucket.size());

      if (LOG.isDebugEnabled()) LOG.debug("We are using {}", archiveType);

      // Now we have to insert the Archive we have generated.

      // Can we just insert it, and not bother with a redirect to it?
      // Thereby exploiting implicit manifest support, which will pick up on .metadata??
      // We ought to be able to !!
      block = new InsertBlock(outputBucket, new ClientMetadata(mimeType), targetURI);
    } catch (IOException e) {
      fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
      return;
    }

    SingleFileInserter sfi = buildSingleFileInserter(block);
    if (LOG.isDebugEnabled()) LOG.debug("Inserting container: {} for {}", sfi, this);
    cb.onTransition(this, sfi, context);
    try {
      sfi.schedule(context);
    } catch (InsertException e) {
      fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
    }
  }

  /**
   * Builds the {@link SingleFileInserter} for the prepared archive {@link InsertBlock}.
   *
   * <p>Computes the effective compression flag for the archive type and returns a fully configured
   * inserter. The returned instance is not scheduled; the caller is responsible for lifecycle
   * management (logging, transition callback, and scheduling).
   */
  private SingleFileInserter buildSingleFileInserter(InsertBlock block) {
    boolean dc = dontCompress;
    if (!dontCompress) {
      dc = (archiveType == ARCHIVE_TYPE.ZIP);
    }

    // Treat it as a splitfile for purposes of determining reinsert count.
    return new SingleFileInserter(
        parent,
        cb,
        block,
        false,
        ctx,
        realTimeFlag,
        dc,
        reportMetadataOnly,
        token,
        archiveType,
        true,
        null,
        true,
        persistent,
        0,
        0,
        null,
        cryptoAlgorithm,
        forceCryptoKey,
        -1);
  }

  private void makeMetadata(ClientContext context) {

    Bucket bucket;
    int x = 0;

    Metadata md = makeManifest(origMetadata, "");

    while (true) {
      try {
        bucket = md.toBucket(context.getBucketFactory(persistent));
        containerItems.add(new ContainerElement(bucket, ".metadata"));
        return;
      } catch (MetadataUnresolvedException e) {
        try {
          x = resolve(e, x, context);
        } catch (IOException _) {
          fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
          return;
        }
      } catch (IOException e) {
        fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
        return;
      }
    }
  }

  private int resolve(MetadataUnresolvedException e, int x, ClientContext context)
      throws IOException {
    Metadata[] metas = e.mustResolve;
    for (Metadata m : metas) {
      try {
        Bucket bucket = m.toBucket(context.getBucketFactory(persistent));
        String nameInArchive = ".metadata-" + (x++);
        containerItems.add(new ContainerElement(bucket, nameInArchive));
        m.resolve(nameInArchive);
      } catch (MetadataUnresolvedException _) {
        x = resolve(e, x, context);
      }
    }
    return x;
  }

  private void fail(InsertException e, ClientContext context) {
    // Cancel all, then call the callback
    synchronized (this) {
      if (finished) return;
      finished = true;
    }
    cb.onFailure(e, this, context);
  }

  // A persistent hashCode is helpful in debugging, and also means we can put
  // these objects into sets etc. when we need to.

  /** Stable hash code captured at construction time to aid persistence and debugging. */
  private final int hashCode;

  /**
   * Returns the stable hash code captured at construction. The value does not change during the
   * lifetime of the instance so it can be used in sets or as a persistent identifier.
   */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Identity-based equality. Two {@code ContainerInserter} instances are equal only when they are
   * the same object reference.
   *
   * @param obj another object reference to compare
   * @return {@code true} if and only if {@code this == obj}
   */
  @Override
  public boolean equals(Object obj) {
    return this == obj;
  }

  /** * OutputStream os will be close()d if this method returns successfully. */
  private String createTarBucket(OutputStream os) throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Create a TAR Bucket");

    try (TarArchiveOutputStream tarOS = new TarArchiveOutputStream(os)) {
      tarOS.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
      TarArchiveEntry ze;

      for (ContainerElement ph : containerItems) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Putting into tar: {} data length {} name {}",
              ph,
              ph.data.size(),
              ph.targetInArchive);
        ze = new TarArchiveEntry(ph.targetInArchive);
        ze.setModTime(0);
        long size = ph.data.size();
        ze.setSize(size);
        tarOS.putArchiveEntry(ze);
        BucketTools.copyTo(ph.data, tarOS, size);
        tarOS.closeArchiveEntry();
      }
    }

    return ARCHIVE_TYPE.TAR.defaultMimeType();
  }

  private String createZipBucket(OutputStream os) throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Create a ZIP Bucket");

    try (ZipOutputStream zos = new ZipOutputStream(os)) {
      ZipEntry ze;

      for (ContainerElement ph : containerItems) {
        ze = new ZipEntry(ph.targetInArchive);
        ze.setTime(0);
        zos.putNextEntry(ze);
        BucketTools.copyTo(ph.data, zos, ph.data.size());
        zos.closeEntry();
      }
    }

    return ARCHIVE_TYPE.ZIP.defaultMimeType();
  }

  private Metadata makeManifest(Map<String, Object> manifestElements, String archivePrefix) {
    SimpleManifestComposer smc = new Metadata.SimpleManifestComposer();
    for (Map.Entry<String, Object> me : manifestElements.entrySet()) {
      addEntryToComposer(smc, me.getKey(), me.getValue(), archivePrefix);
    }
    return smc.getMetadata();
  }

  private void addEntryToComposer(
      SimpleManifestComposer smc, String name, Object value, String archivePrefix) {
    if (value instanceof Map<?, ?>) {
      Map<String, Object> hm = Metadata.forceMap(value);
      if (LOG.isTraceEnabled()) LOG.trace("Sub map for {} : {} elements", name, hm.size());
      smc.addItem(name, makeManifest(hm, archivePrefix + name + '/'));
      return;
    }
    if (value instanceof Metadata metadata) {
      smc.addItem(name, metadata);
      return;
    }
    ManifestElement element = (ManifestElement) value;
    String mimeType = element.getMimeType();
    ClientMetadata cm =
        (mimeType == null || mimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE))
            ? null
            : new ClientMetadata(mimeType);
    Metadata m;
    if (element.targetURI != null) {
      m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, element.targetURI, cm);
    } else {
      containerItems.add(new ContainerElement(element.getData(), archivePrefix + name));
      m =
          new Metadata(
              DocumentType.ARCHIVE_INTERNAL_REDIRECT,
              null,
              null,
              archivePrefix + element.fullName,
              cm);
    }
    smc.addItem(name, m);
  }

  private transient boolean resumed = false;

  @Override
  public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    if (cb != null && cb != parent) cb.onResume(context);
    if (containerItems != null) {
      for (ContainerElement e : containerItems) {
        if (e.data != null) e.data.onResume(context);
      }
    }
    resumeMetadata(origMetadata, context);
    // Do not call start(). start() immediately transitions to another state.
  }

  /**
   * Recursively calls {@code onResume} on all resumable elements inside the manifest-like map.
   *
   * <p>The method walks nested maps, {@link ManifestElement} values, and {@link Metadata} entries
   * (which are ignored because they hold no resumable state), and invokes {@link
   * PutHandler#onResume} where present. Unknown value types cause an {@link
   * IllegalArgumentException}.
   *
   * @param map manifest-like map containing nested maps, {@link Metadata}, {@link ManifestElement},
   *     or {@link PutHandler} instances
   * @param context resume context propagated to resumable elements
   * @throws ResumeFailedException if any element signals that resuming state failed
   */
  public static void resumeMetadata(Map<String, Object> map, ClientContext context)
      throws ResumeFailedException {
    for (Object o : map.values()) {
      switch (o) {
        case Map<?, ?> sub -> resumeMetadata(Metadata.forceMap(sub), context);
        case ManifestElement e -> e.onResume(context);
        case Metadata ignored -> {
          // Ignore
        }
        case PutHandler handler -> handler.onResume(context);
        case null, default -> throw new IllegalArgumentException("Unknown manifest element: " + o);
      }
    }
  }

  /** Called during shutdown; this implementation performs no action. */
  @Override
  public void onShutdown(ClientContext context) {
    // Ignore.
  }

  /* ===== Java serialization support ===== */

  /**
   * Custom Java serialization hook. Writes the default serial form; transient fields are skipped
   * and reinitialized during {@link #readObject}.
   *
   * @param out stream to which the object state is written; must be open and writable
   * @throws IOException if an I/O error occurs while writing the serial form
   */
  @Serial
  private void writeObject(java.io.ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
  }

  /**
   * Custom Java deserialization hook. Reads the default serial form and restores transient runtime
   * fields to a safe initial state for later resume.
   *
   * @param in stream from which the object state is read; must be open and readable
   * @throws IOException if an I/O error occurs while reading the serial form
   * @throws ClassNotFoundException if a class required to restore the state cannot be found
   */
  @Serial
  private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (containerItems == null) containerItems = new ArrayList<>();
  }
}
