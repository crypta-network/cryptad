package network.crypta.client;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.async.BaseManifestPutter;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.DefaultManifestPutter;
import network.crypta.client.async.ManifestPutterParams;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.EventLogger;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestScheduler;
import network.crypta.node.RequestStarter;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PersistentFileTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Default high-level client implementation for simple fetch and insert operations.
 *
 * <p>This implementation wraps the asynchronous client primitives ({@link ClientGetter} and {@link
 * ClientPutter}) exposed by the node and provides convenient, mostly synchronous entry points. Each
 * operation constructs an immutable request context ({@link FetchContext} or {@link
 * InsertContext}), starts the underlying job on the node, and then waits for completion via a small
 * waiter helper. Callers can also use the callback-based methods for fully asynchronous flows when
 * integrating with their own scheduling or UI.
 *
 * <p>Typical usage is to create a single instance per caller or session and then:
 *
 * <ul>
 *   <li>Fetch content by URI using {@link #fetch(FreenetURI)} or its overloads.
 *   <li>Insert content using one of the {@code insert(...)} overloads or {@link
 *       #insertManifest(FreenetURI, java.util.Map, String)} for directory-like structures.
 *   <li>Adjust size limits with {@link #setMaxLength(long)} and {@link
 *       #setMaxIntermediateLength(long)} prior to building contexts.
 * </ul>
 *
 * <p>Instances keep small amounts of mutable configuration (for example, the current maximum
 * lengths). Reads are thread-safe, but if multiple threads mutate configuration concurrently,
 * external coordination is recommended. Returned contexts and results are independent per call and
 * can be used without retaining a reference to this client.
 *
 * @see HighLevelSimpleClient
 * @see FetchContext
 * @see InsertContext
 */
public class HighLevelSimpleClientImpl implements HighLevelSimpleClient, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(HighLevelSimpleClientImpl.class);

  private final short priorityClass;
  private final BucketFactory bucketFactory;
  private final BucketFactory persistentBucketFactory;
  private final PersistentFileTracker persistentFileTracker;
  private final NodeClientCore core;

  /** One CEP for all requests and inserts */
  private final ClientEventProducer eventProducer;

  private long curMaxLength;
  private long curMaxTempLength;
  private final int curMaxMetadataLength;
  private final RandomSource random;
  private final boolean realTimeFlag;
  static final int MAX_RECURSION = 10;
  static final int MAX_ARCHIVE_RESTARTS = 2;
  static final int MAX_ARCHIVE_LEVELS = 10;
  static final boolean DONT_ENTER_IMPLICIT_ARCHIVES = true;

  // COOLDOWN_RETRIES-1 so we don't have to wait on the cooldown queue; HLSC is designed
  // for interactive requests mostly.
  /** Number of retries allowed per block in a splitfile. */
  static final int SPLITFILE_BLOCK_RETRIES = Math.min(3, RequestScheduler.COOLDOWN_RETRIES - 1);

  /** Number of retries allowed on non-splitfile fetches. */
  static final int NON_SPLITFILE_RETRIES = Math.min(3, RequestScheduler.COOLDOWN_RETRIES - 1);

  static final int USK_RETRIES = RequestScheduler.COOLDOWN_RETRIES - 1;

  /** Whether to fetch splitfiles. Don't turn this off! */
  static final boolean FETCH_SPLITFILES = true;

  /**
   * Whether to follow redirects etc. If false, we only fetch a plain block of data. Don't turn this
   * off either!
   */
  static final boolean FOLLOW_REDIRECTS = true;

  /**
   * If set, only check the local datastore, don't send an actual request out. Don't turn this off
   * either.
   */
  static final boolean LOCAL_REQUESTS_ONLY = false;

  /** By default, write to the client cache. Turn this off if you are fetching big stuff. */
  static final boolean CAN_WRITE_CLIENT_CACHE = true;

  /** By default, don't write local inserts to the client cache. */
  static final boolean CAN_WRITE_CLIENT_CACHE_INSERTS = false;

  /** Number of retries on inserts */
  static final int INSERT_RETRIES = 10;

  /** Number of RNFs on insert that make a success, or -1 on large networks */
  static final int CONSECUTIVE_RNFS_ASSUME_SUCCESS = 2;

  // going by memory usage only; 4kB per stripe
  static final int MAX_SPLITFILE_BLOCKS_PER_SEGMENT = 256;
  static final int MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT = 256;

  // For scaling purposes, 128 data 128 check blocks i.e. one check block per data block.
  /**
   * Target data blocks per segment when scaling splitfiles.
   *
   * <p>The value expresses the intended number of data stripes in a segment before forward error
   * correction is applied. It is used by splitfile builders to estimate memory and I/O footprint
   * and to select a balanced data/check split. Consumers should treat this as a tuning constant
   * rather than a strict limit.
   */
  public static final int SPLITFILE_SCALING_BLOCKS_PER_SEGMENT = 128;

  /* The number of data blocks in a segment depends on how many segments there are.
   * FECCodec.standardOnionCheckBlocks will automatically reduce check blocks to compensate for more than half data blocks. */
  /**
   * Maximum data blocks per segment when writing splitfiles.
   *
   * <p>This is an upper bound used by encoders when laying out segments on disk or on the wire. It
   * may be reduced automatically by the codec depending on the overall file size and the number of
   * segments. Counts are in blocks, not bytes.
   */
  public static final int SPLITFILE_BLOCKS_PER_SEGMENT = 136;

  /**
   * Maximum parity/check blocks per segment when writing splitfiles.
   *
   * <p>The encoder may lower the number of check blocks to keep a sane data/check ratio for large
   * files. Values are expressed as block counts and are chosen to balance redundancy and memory
   * footprint.
   */
  public static final int SPLITFILE_CHECK_BLOCKS_PER_SEGMENT = 128;

  /**
   * Extra insert attempts for small single-block inserts.
   *
   * <p>When inserting a single block, an implementation may perform additional redundant inserts to
   * increase the probability of success under transient failures. This value specifies the number
   * of additional insert attempts beyond the minimum required writes.
   */
  public static final int EXTRA_INSERTS_SINGLE_BLOCK = 2;

  /**
   * Extra insert attempts for splitfile headers.
   *
   * <p>Headers are critical to reconstruct a splitfile. Implementations may repeat header inserts a
   * small number of times to guard against rare loss; this constant defines that redundancy factor
   * for header chunks only.
   */
  public static final int EXTRA_INSERTS_SPLITFILE_HEADER = 2;

  /*Whether to filter fetched content*/
  static final boolean FILTER_DATA = false;

  /**
   * Creates a new client bound to the provided node and factories.
   *
   * <p>The constructor wires the event producer used for both fetch and insert operations, captures
   * the default size limits, and remembers the priority class to apply when a call does not specify
   * an explicit priority.
   *
   * @param node node-facing client core used to schedule and run requests; must not be {@code
   *     null}.
   * @param bf bucket factory for transient user-supplied data; used to build request payloads and
   *     metadata.
   * @param r random source used for generating keys and nonces; the instance is not required to be
   *     cryptographically secure but should provide good entropy.
   * @param priorityClass scheduler priority class for operations started by this client when a
   *     method does not override it; lower-level schedulers interpret the value.
   * @param forceDontIgnoreTooManyPathComponents retained for compatibility; currently does not
   *     alter behavior and may be logged for diagnostics.
   * @param realTimeFlag whether requests should be treated as latency-sensitive by eligible
   *     subsystems; does not change API semantics.
   */
  public HighLevelSimpleClientImpl(
      NodeClientCore node,
      BucketFactory bf,
      RandomSource r,
      short priorityClass,
      boolean forceDontIgnoreTooManyPathComponents,
      boolean realTimeFlag) {
    this.core = node;
    this.priorityClass = priorityClass;
    bucketFactory = bf;
    this.persistentFileTracker = node.getPersistentTempBucketFactory();
    random = r;
    this.eventProducer = new SimpleEventProducer();
    if (LOG.isDebugEnabled()) {
      LOG.debug("forceDontIgnoreTooManyPathComponents={}", forceDontIgnoreTooManyPathComponents);
    }
    eventProducer.addEventListener(new EventLogger(Level.DEBUG, false));
    curMaxLength = Long.MAX_VALUE;
    curMaxTempLength = Long.MAX_VALUE;
    curMaxMetadataLength = 1024 * 1024;
    this.persistentBucketFactory = node.getPersistentTempBucketFactory();
    this.realTimeFlag = realTimeFlag;
  }

  /**
   * Copy constructor that duplicates configuration from another instance.
   *
   * <p>New instances reuse factories and limits from the source but have their own event producer
   * and listener list. The copy does not share mutable configuration objects with the original
   * beyond the references already held by the original client.
   *
   * @param hlsc the existing client to copy configuration from; must not be {@code null}.
   */
  public HighLevelSimpleClientImpl(HighLevelSimpleClientImpl hlsc) {
    this.eventProducer = new SimpleEventProducer();
    this.priorityClass = hlsc.priorityClass;
    this.bucketFactory = hlsc.bucketFactory;
    this.persistentBucketFactory = hlsc.persistentBucketFactory;
    this.persistentFileTracker = hlsc.persistentFileTracker;
    this.core = hlsc.core;
    this.curMaxLength = hlsc.curMaxLength;
    this.curMaxMetadataLength = hlsc.curMaxMetadataLength;
    this.curMaxTempLength = hlsc.curMaxTempLength;
    this.random = hlsc.random;
    this.realTimeFlag = hlsc.realTimeFlag;
  }

  @Override
  public HighLevelSimpleClient copy() {
    return new HighLevelSimpleClientImpl(this);
  }

  @Override
  public void setMaxLength(long maxLength) {
    curMaxLength = maxLength;
  }

  @Override
  public void setMaxIntermediateLength(long maxIntermediateLength) {
    curMaxTempLength = maxIntermediateLength;
  }

  /** Fetch a key. Either returns the data, or throws an exception. */
  @Override
  public FetchResult fetch(FreenetURI uri) throws FetchException {
    if (uri == null) throw new NullPointerException();
    FetchContext context = getFetchContext();
    FetchWaiter fw = new FetchWaiter(this);
    ClientGetter get = new ClientGetter(fw, uri, context, priorityClass, null, null, null);
    try {
      core.getClientContext().start(get);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return fw.waitForCompletion();
  }

  /** Fetch a key. Either returns the data, or throws an exception. */
  @Override
  public FetchResult fetchFromMetadata(Bucket initialMetadata) throws FetchException {
    if (initialMetadata == null) throw new NullPointerException();
    FetchContext context = getFetchContext();
    FetchWaiter fw = new FetchWaiter(this);
    ClientGetter get =
        new ClientGetter(
            fw, FreenetURI.EMPTY_CHK_URI, context, priorityClass, null, null, initialMetadata);
    try {
      core.getClientContext().start(get);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return fw.waitForCompletion();
  }

  @Override
  public FetchResult fetch(FreenetURI uri, long overrideMaxSize) throws FetchException {
    return fetch(uri, overrideMaxSize, this);
  }

  @Override
  public FetchResult fetch(FreenetURI uri, long overrideMaxSize, RequestClient clientContext)
      throws FetchException {
    if (uri == null) throw new NullPointerException();
    FetchWaiter fw = new FetchWaiter(clientContext);
    FetchContext context = getFetchContext(overrideMaxSize);
    ClientGetter get = new ClientGetter(fw, uri, context, priorityClass, null, null, null);
    try {
      core.getClientContext().start(get);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return fw.waitForCompletion();
  }

  @Override
  public ClientGetter fetch(FreenetURI uri, ClientGetCallback callback, FetchContext fctx)
      throws FetchException {
    return fetch(uri, callback, fctx, priorityClass);
  }

  @Override
  public ClientGetter fetch(
      FreenetURI uri, long maxSize, ClientGetCallback callback, FetchContext fctx, short prio)
      throws FetchException {
    if (maxSize > 0) {
      fctx.setMaxOutputLength(maxSize);
      fctx.setMaxTempLength(maxSize);
    }

    return fetch(uri, callback, fctx, prio);
  }

  @Override
  public ClientGetter fetch(
      FreenetURI uri, ClientGetCallback callback, FetchContext fctx, short prio)
      throws FetchException {
    if (uri == null) throw new NullPointerException();
    ClientGetter get = new ClientGetter(callback, uri, fctx, prio, null, null, null);
    try {
      core.getClientContext().start(get);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return get;
  }

  @Override
  public ClientGetter fetchFromMetadata(
      Bucket initialMetadata, ClientGetCallback callback, FetchContext fctx, short prio)
      throws FetchException {
    if (initialMetadata == null) throw new NullPointerException();
    ClientGetter get =
        new ClientGetter(
            callback, FreenetURI.EMPTY_CHK_URI, fctx, prio, null, null, initialMetadata);
    try {
      core.getClientContext().start(get);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return get;
  }

  @Override
  public FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint)
      throws InsertException {
    return insert(insert, getCHKOnly, filenameHint, priorityClass);
  }

  @Override
  public FreenetURI insert(
      InsertBlock insert, boolean getCHKOnly, String filenameHint, short priority)
      throws InsertException {
    return insert(insert, getCHKOnly, filenameHint, false, priority);
  }

  /**
   * Inserts data with optional CHK-only computation using a fresh {@link InsertContext}.
   *
   * <p>This overload is convenient when callers do not need to customize the {@link InsertContext}.
   * When {@code getCHKOnly} is true, the method computes the content hash key and returns it
   * without storing the data in the network. Otherwise, it starts an insert and waits for
   * completion.
   *
   * @param insert encapsulates the data {@link Bucket}, desired URI (when applicable), and client
   *     metadata; must not be {@code null}.
   * @param getCHKOnly when {@code true}, return the computed CHK without performing a network
   *     insert; when {@code false}, store the content.
   * @param filenameHint human-readable filename to associate with the payload; used only as a hint
   *     for UIs and metadata.
   * @param isMetadata whether the payload should be treated as metadata rather than user content;
   *     affects how some tools interpret the object.
   * @param priority scheduler priority class to apply when queuing the request; callers typically
   *     pass {@link #priorityClass}.
   * @return a {@link FreenetURI} referencing the inserted data (or the computed CHK when {@code
   *     getCHKOnly} is true); never {@code null} when the operation succeeds.
   * @throws InsertException if the insert fails or the request cannot be scheduled; the exception
   *     contains a mode indicating the failure category.
   */
  public FreenetURI insert(
      InsertBlock insert,
      boolean getCHKOnly,
      String filenameHint,
      boolean isMetadata,
      short priority)
      throws InsertException {
    InsertContext context = getInsertContext(true);
    context.setGetCHKOnly(getCHKOnly);
    return insert(insert, filenameHint, isMetadata, priority, context);
  }

  @Override
  public FreenetURI insert(
      InsertBlock insert, String filenameHint, short priority, InsertContext ctx)
      throws InsertException {
    return insert(insert, filenameHint, false, priority, ctx);
  }

  /**
   * Inserts data using the provided {@link InsertContext} and defaulting {@code isMetadata} to
   * {@code false}.
   *
   * <p>Use this overload when you need to adjust retries, block sizing, compression, or cache
   * behavior via the context, but do not need to mark the payload as metadata.
   *
   * @param insert encapsulates the data and any desired target URI; must not be {@code null}.
   * @param filenameHint optional label recorded alongside the payload; may be {@code null}.
   * @param isMetadata whether the payload represents metadata rather than user content. When set to
   *     {@code true}, the insert marks the object accordingly.
   * @param priority scheduler priority class to apply; larger deployments may enforce class ranges.
   * @param ctx fully populated insert context controlling retries and layout; must not be {@code
   *     null}.
   * @return the resulting {@link FreenetURI} once the insert completes successfully; never {@code
   *     null}.
   * @throws InsertException if the insert cannot be completed.
   */
  public FreenetURI insert(
      InsertBlock insert,
      String filenameHint,
      boolean isMetadata,
      short priority,
      InsertContext ctx)
      throws InsertException {
    return insert(insert, filenameHint, isMetadata, priority, ctx, null);
  }

  /**
   * Low-level insert with full control over metadata flag and optional crypto key.
   *
   * <p>This is the most flexible overload. It forwards all parameters to the underlying {@link
   * ClientPutter} and waits synchronously for completion via a {@code PutWaiter}.
   *
   * @param insert encapsulates the data and optional target; must not be {@code null}.
   * @param filenameHint human-readable name stored as metadata; may be {@code null}.
   * @param isMetadata whether the payload represents metadata rather than user content.
   * @param priority scheduler priority class to apply when queuing the request.
   * @param ctx insert context controlling retries, caching, and compression; must not be {@code
   *     null}.
   * @param forceCryptoKey optional symmetric key material that, when provided, forces a particular
   *     crypto key for the insert; may be {@code null}.
   * @return a {@link FreenetURI} for the stored content if the insert succeeds; never {@code null}
   *     on success.
   * @throws InsertException if the insert fails or cannot be scheduled.
   */
  public FreenetURI insert(
      InsertBlock insert,
      String filenameHint,
      boolean isMetadata,
      short priority,
      InsertContext ctx,
      byte[] forceCryptoKey)
      throws InsertException {
    PutWaiter pw = new PutWaiter(this);
    ClientPutter put =
        new ClientPutter(
            new ClientPutterRequest(
                pw,
                insert.getData(),
                insert.desiredURI,
                insert.clientMetadata,
                ctx,
                priority,
                isMetadata),
            new ClientPutterOptions(filenameHint, false, forceCryptoKey, -1));
    try {
      core.getClientContext().start(put);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return pw.waitForCompletion();
  }

  @Override
  public ClientPutter insert(
      InsertBlock insert,
      String filenameHint,
      boolean isMetadata,
      InsertContext ctx,
      ClientPutCallback cb)
      throws InsertException {
    return insert(insert, filenameHint, isMetadata, ctx, cb, priorityClass);
  }

  @Override
  public ClientPutter insert(
      InsertBlock insert,
      String filenameHint,
      boolean isMetadata,
      InsertContext ctx,
      ClientPutCallback cb,
      short priority)
      throws InsertException {
    ClientPutter put =
        new ClientPutter(
            new ClientPutterRequest(
                cb,
                insert.getData(),
                insert.desiredURI,
                insert.clientMetadata,
                ctx,
                priority,
                isMetadata),
            new ClientPutterOptions(filenameHint, false, null, -1));
    try {
      core.getClientContext().start(put);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return put;
  }

  /**
   * Inserts a simple redirect that points {@code insertURI} to {@code targetURI}.
   *
   * <p>The redirect is represented as lightweight metadata and written as a single object. This is
   * useful when publishing a stable SSK that forwards to a versioned CHK.
   *
   * @param insertURI location under which the redirect will be published; must not be {@code null}.
   * @param targetURI destination URI that clients should resolve to; must not be {@code null}.
   * @return a {@link FreenetURI} referring to the stored redirect object.
   * @throws InsertException if the redirect cannot be encoded or scheduled for insert.
   */
  @Override
  public FreenetURI insertRedirect(FreenetURI insertURI, FreenetURI targetURI)
      throws InsertException {
    Metadata m =
        new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI, new ClientMetadata());
    RandomAccessBucket b;
    try {
      b = m.toBucket(bucketFactory);
    } catch (IOException | MetadataUnresolvedException e) {
      throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
    }

    InsertBlock block = new InsertBlock(b, null, insertURI);
    FreenetURI uri = insert(block, false, null, true, priorityClass);
    block.free();
    return uri;
  }

  /**
   * Inserts a directory-like manifest mapping names to content buckets.
   *
   * <p>Each entry in {@code bucketsByName} may be a {@link Bucket} or another mapping that the
   * manifest putter understands. The resulting URI points to a structure that clients can traverse
   * using the provided names.
   *
   * @param insertURI root location where the manifest will be published; must not be {@code null}.
   * @param bucketsByName mapping from display name to content; entries must be valid for the {@link
   *     DefaultManifestPutter}.
   * @param defaultName default object name to resolve when no specific path is given; may be {@code
   *     null}.
   * @return the {@link FreenetURI} of the created manifest object.
   * @throws InsertException if validation fails or the job cannot be queued.
   */
  @Override
  public FreenetURI insertManifest(
      FreenetURI insertURI, Map<String, Object> bucketsByName, String defaultName)
      throws InsertException {
    return insertManifest(insertURI, bucketsByName, defaultName, priorityClass);
  }

  @Override
  public FreenetURI insertManifest(
      FreenetURI insertURI,
      Map<String, Object> bucketsByName,
      String defaultName,
      short priorityClass)
      throws InsertException {
    return insertManifest(insertURI, bucketsByName, defaultName, priorityClass, null);
  }

  @Override
  public FreenetURI insertManifest(
      FreenetURI insertURI,
      Map<String, Object> bucketsByName,
      String defaultName,
      short priorityClass,
      byte[] forceCryptoKey)
      throws InsertException {
    PutWaiter pw = new PutWaiter(this);
    DefaultManifestPutter putter;
    try {
      putter =
          new DefaultManifestPutter(
              new ManifestPutterParams(
                  pw,
                  BaseManifestPutter.bucketsByNameToManifestEntries(bucketsByName),
                  priorityClass,
                  insertURI,
                  defaultName,
                  getInsertContext(true),
                  forceCryptoKey,
                  core.getClientContext()),
              false);
    } catch (TooManyFilesInsertException _) {
      throw new InsertException(InsertExceptionMode.TOO_MANY_FILES);
    }
    try {
      core.getClientContext().start(putter);
    } catch (PersistenceDisabledException _) {
      // Impossible
    }
    return pw.waitForCompletion();
  }

  /**
   * Registers a listener for high-level client events.
   *
   * <p>Listeners receive progress and status updates emitted by the {@link ClientEventProducer}
   * shared by this client. Registration is additive and idempotent for the same instance.
   *
   * @param listener the listener to add; must not be {@code null}.
   */
  @Override
  public void addEventHook(ClientEventListener listener) {
    eventProducer.addEventListener(listener);
  }

  @Override
  public FetchContext getFetchContext() {
    return getFetchContext(-1);
  }

  @Override
  public FetchContext getFetchContext(long overrideMaxSize) {
    return getFetchContext(-1, null);
  }

  @Override
  public FetchContext getFetchContext(long overrideMaxSize, String schemeHostAndPort) {
    long maxLength = curMaxLength;
    long maxTempLength = curMaxTempLength;
    if (overrideMaxSize >= 0) {
      maxLength = overrideMaxSize;
      maxTempLength = overrideMaxSize;
    }
    FetchContextOptions options =
        FetchContextOptions.builder()
            .limits(maxLength, maxTempLength, curMaxMetadataLength)
            .archiveLimits(
                MAX_RECURSION,
                MAX_ARCHIVE_RESTARTS,
                MAX_ARCHIVE_LEVELS,
                DONT_ENTER_IMPLICIT_ARCHIVES)
            .retryLimits(SPLITFILE_BLOCK_RETRIES, NON_SPLITFILE_RETRIES, USK_RETRIES)
            .splitfileLimits(
                FETCH_SPLITFILES,
                MAX_SPLITFILE_BLOCKS_PER_SEGMENT,
                MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT)
            .behavior(FOLLOW_REDIRECTS, LOCAL_REQUESTS_ONLY, FILTER_DATA)
            .clientOptions(eventProducer, false, CAN_WRITE_CLIENT_CACHE)
            .filterOverrides(null, null, schemeHostAndPort)
            .build();
    return new FetchContext(options);
  }

  /**
   * Builds a {@link FetchContext} with defaults suitable for most interactive reads.
   *
   * <p>The returned context carries sensible retry counts and enables splitfile support and
   * redirect following. The maximum output and temporary sizes are taken from the parameters.
   *
   * @param maxLength maximum allowed size of the fetched payload in bytes; negative disables the
   *     limit.
   * @param maxTempLength maximum temporary storage in bytes for intermediate structures; negative
   *     disables the limit.
   * @param eventProducer producer used to publish client events to listeners; may be shared.
   * @return a new {@link FetchContext} instance initialized with this class's defaults.
   */
  public static FetchContext makeDefaultFetchContext(
      long maxLength, long maxTempLength, SimpleEventProducer eventProducer) {
    FetchContextOptions options =
        FetchContextOptions.builder()
            .limits(maxLength, maxTempLength, 1024 * 1024)
            .archiveLimits(
                MAX_RECURSION,
                MAX_ARCHIVE_RESTARTS,
                MAX_ARCHIVE_LEVELS,
                DONT_ENTER_IMPLICIT_ARCHIVES)
            .retryLimits(SPLITFILE_BLOCK_RETRIES, NON_SPLITFILE_RETRIES, USK_RETRIES)
            .splitfileLimits(
                FETCH_SPLITFILES,
                MAX_SPLITFILE_BLOCKS_PER_SEGMENT,
                MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT)
            .behavior(FOLLOW_REDIRECTS, LOCAL_REQUESTS_ONLY, FILTER_DATA)
            .clientOptions(eventProducer, false, CAN_WRITE_CLIENT_CACHE)
            .filterOverrides(null, null, null)
            .build();
    return new FetchContext(options);
  }

  @Override
  public InsertContext getInsertContext(boolean forceNonPersistent) {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(INSERT_RETRIES, CONSECUTIVE_RNFS_ASSUME_SUCCESS)
            .splitfileSegmentLimits(
                SPLITFILE_BLOCKS_PER_SEGMENT, SPLITFILE_CHECK_BLOCKS_PER_SEGMENT)
            .clientOptions(
                eventProducer,
                CAN_WRITE_CLIENT_CACHE_INSERTS,
                Node.FORK_ON_CACHEABLE_DEFAULT,
                false)
            .compressorDescriptor(Compressor.DEFAULT_COMPRESSORDESCRIPTOR)
            .redundancy(EXTRA_INSERTS_SINGLE_BLOCK, EXTRA_INSERTS_SPLITFILE_HEADER)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_DEFAULT)
            .build());
  }

  /**
   * Builds a {@link InsertContext} configured with this class's default policy.
   *
   * <p>The resulting context sets retry counts, splitfile sizing, cache behavior, and compression
   * defaults appropriate for general-purpose inserts. Callers may further customize the returned
   * instance before passing it to an {@code insert(...)} method.
   *
   * @param bucketFactory factory that may be used by downstream components; present for symmetry,
   *     not always consumed by context construction.
   * @param eventProducer producer that will receive insert-related events; may be shared across
   *     clients.
   * @return a new {@link InsertContext} ready for use in an insert operation.
   */
  public static InsertContext makeDefaultInsertContext(
      BucketFactory bucketFactory, SimpleEventProducer eventProducer) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "makeDefaultInsertContext invoked (bucketFactory passed={})", bucketFactory != null);
    }
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(INSERT_RETRIES, CONSECUTIVE_RNFS_ASSUME_SUCCESS)
            .splitfileSegmentLimits(
                SPLITFILE_BLOCKS_PER_SEGMENT, SPLITFILE_CHECK_BLOCKS_PER_SEGMENT)
            .clientOptions(
                eventProducer,
                CAN_WRITE_CLIENT_CACHE_INSERTS,
                Node.FORK_ON_CACHEABLE_DEFAULT,
                false)
            .compressorDescriptor(Compressor.DEFAULT_COMPRESSORDESCRIPTOR)
            .redundancy(EXTRA_INSERTS_SINGLE_BLOCK, EXTRA_INSERTS_SPLITFILE_HEADER)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_DEFAULT)
            .build());
  }

  /**
   * Generates a fresh SSK insert/browse key pair.
   *
   * <p>The key pair is suitable for publishing mutable content under a stable identity. The
   * optional {@code docName} is incorporated into the key derivation to produce a convenient
   * namespace separation for callers that maintain multiple documents.
   *
   * @param docName an application-chosen label incorporated into the key; may be {@code null} or
   *     empty for no label.
   * @return a two-element array: index {@code 0} is the insert-capable URI, index {@code 1} is the
   *     corresponding read/browse URI.
   */
  @Override
  public FreenetURI[] generateKeyPair(String docName) {
    InsertableClientSSK key = InsertableClientSSK.createRandom(random, docName);
    return new FreenetURI[] {key.getInsertURI(), key.getURI()};
  }

  private final ClientGetCallback nullCallback = new NullClientCallback(this);

  /**
   * Starts a low-priority fetch that is cancelled automatically after a timeout.
   *
   * <p>Prefetching is best-effort: the request is enqueued with a prefetch priority and cancelled
   * after {@code timeout} milliseconds. When it completes before the timeout, data may be present
   * in caches to speed up the eventual foreground fetch.
   *
   * @param uri the content URI to warm; must not be {@code null}.
   * @param timeout maximum time to keep the background request alive, in milliseconds.
   * @param maxSize maximum allowed size of the payload in bytes; negative disables the limit.
   * @param allowedTypes optional set of MIME types to admit; {@code null} or empty means any.
   */
  @Override
  public void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes) {
    prefetch(uri, timeout, maxSize, allowedTypes, RequestStarter.PREFETCH_PRIORITY_CLASS);
  }

  /**
   * Starts a low-priority fetch with an explicit scheduler priority.
   *
   * <p>See {@link #prefetch(FreenetURI, long, long, Set)} for general behavior. This overload
   * allows callers to choose a specific priority class.
   *
   * @param uri the content URI to warm; must not be {@code null}.
   * @param timeout maximum time to keep the background request alive, in milliseconds.
   * @param maxSize maximum allowed size of the payload in bytes; negative disables the limit.
   * @param allowedTypes optional set of MIME types to admit; {@code null} or empty means any.
   * @param prio scheduler priority class to apply when queuing the prefetch.
   */
  @Override
  public void prefetch(
      FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes, short prio) {
    FetchContext ctx = getFetchContext(maxSize);
    ctx.setAllowedMIMETypes(allowedTypes);
    final ClientGetter get =
        new ClientGetter(nullCallback, uri, ctx, prio, new NullBucket(), null, null);
    core.getNode()
        .network()
        .ticker()
        .queueTimedJob(() -> get.cancel(core.getClientContext()), timeout);
    try {
      core.getClientContext().start(get);
    } catch (FetchException | PersistenceDisabledException _) {
      // Ignore or impossible; both cases require no handling here.
    }
  }

  @Override
  public boolean persistent() {
    return false;
  }

  @Override
  public boolean realTimeFlag() {
    return realTimeFlag;
  }
}
