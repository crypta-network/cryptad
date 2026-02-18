package network.crypta.client.async;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.RequestIdentifier;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.node.DatabaseKey;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarterGroup;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.DelayedFree;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.PrependLengthOutputStream;
import network.crypta.support.io.StorageFormatException;
import network.crypta.support.io.TempBucketFactory;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Persistence coordinator for client requests (downloads and uploads).
 *
 * <p>This class orchestrates durable storage and recovery of client request state using a layered
 * approach designed for robustness and predictable I/O: (1) splitfile persistence stores payload
 * and segment status in a random-access buffer; (2) Java serialization records the set of active
 * requests and their metadata to {@code client.dat}; and (3) a compact binary fallback captures the
 * minimum information required to restart complex requests. For simple splitfile downloads, the
 * splitfile layer alone is enough to resume.
 *
 * <p>The design prioritizes resilience to partial writes and intermittent corruption while keeping
 * disk seeking low during high-throughput operations. Global scheduling structures (selectors,
 * Bloom filters) are rebuilt in memory during startup; only essential invariants are persisted.
 * Files are rotated with {@code .bak} variants; when corruption is detected the loader aborts the
 * current variant and proceeds to the next to maximize recovery.
 *
 * <ul>
 *   <li>Responsibilities: checkpoint active requests, rotate files, restore and (if needed) restart
 *       requests.
 *   <li>Threading: inherits periodic checkpointing from {@link PersistentJobRunnerImpl}; most
 *       lifecyle methods synchronize on an internal monitor to maintain invariants.
 *   <li>Trade-offs: favors durability and orderly recovery over minimal metadata size.
 * </ul>
 *
 * <p>SCHEMA MIGRATION: evolving {@link java.io.Serializable} types may require restarts and can
 * cause some uploads to be lost if binary compatibility is broken.
 */
public class ClientLayerPersister extends PersistentJobRunnerImpl {
  private static final Logger LOG = LoggerFactory.getLogger(ClientLayerPersister.class);

  static final long INTERVAL = MINUTES.toMillis(10);
  private final Node node; // Needed for bandwidth stats putter
  private final NodeClientCore clientCore;
  private final PersistentTempBucketFactory persistentTempFactory;

  /**
   * Needed for temporary storage when writing objects. Some of them might be big, e.g., site
   * inserts.
   */
  private final TempBucketFactory tempBucketFactory;

  private final PersistentStatsPutter bandwidthStatsPutter;
  private byte[] salt;
  private boolean newSalt;
  private final ChecksumChecker checker;

  // Can be set later ...
  private Bucket writeToBucket;
  private File writeToFilename;
  private File writeToBackupFilename;
  private File deleteAfterSuccessfulWrite;
  private File otherDeleteAfterSuccessfulWrite;
  private File dir;
  private String baseName;

  private static final long MAGIC = 0xd332925f3caf4aedL;
  private static final int VERSION = 1;
  private static final String EXT_CRYPT = ".crypt";
  private static final String EXT_BAK = ".bak";
  private static final SecureRandom FALLBACK_SECURE_RNG = new SecureRandom();

  /**
   * Constructs a persistence coordinator for client requests and wires supporting services.
   *
   * <p>The instance schedules periodic checkpoints via the provided executor/ticker, reads/writes
   * persistence files, and collaborates with the core and bucket factories to manage temporary
   * storage. The checksum checker defaults to CRC to validate segments on the load and skip corrupt
   * entries. The object is inert until {@link #setFilesAndLoad(File, String, boolean, boolean,
   * DatabaseKey, RequestStarterGroup)} assigns target files and triggers the initial load.
   *
   * @param executor executor used for periodic checkpoint jobs and any deferred work required to
   *     advance persistence without blocking callers; must execute tasks reliably and promptly.
   * @param ticker time source used to schedule checkpoints; should dispatch callbacks on the
   *     provided {@code executor} to preserve ordering and avoid thread proliferation.
   * @param node parent node instance used for I/O statistics and contextual operations during
   *     checkpointing and recovery; expected to outlive this persister.
   * @param core client core used as the authoritative source of persistent requests to save and as
   *     the target for resuming or restarting requests after a successful load.
   * @param persistentTempFactory factory that tracks delayed frees and provides buckets scheduled
   *     for post-checkpoint cleanup; only its lifecycle hooks are invoked during saves/loads.
   * @param tempBucketFactory factory for short-lived buckets used to stage checksummed
   *     serialization payloads and similar intermediate data during read/write operations.
   * @param stats collector to merge and persist bandwidth and related statistics alongside the
   *     request set so the UI can reflect activity across restarts.
   */
  public ClientLayerPersister(
      PriorityAwareExecutor executor,
      Ticker ticker,
      Node node,
      NodeClientCore core,
      PersistentTempBucketFactory persistentTempFactory,
      TempBucketFactory tempBucketFactory,
      PersistentStatsPutter stats) {
    super(executor, ticker, INTERVAL);
    this.node = node;
    this.clientCore = core;
    this.persistentTempFactory = persistentTempFactory;
    this.tempBucketFactory = tempBucketFactory;
    this.checker = new CRCChecksumChecker();
    this.bandwidthStatsPutter = stats;
  }

  /**
   * Constructs a persistence coordinator using a new bandwidth stats collector.
   *
   * <p>This overload creates a dedicated {@link PersistentStatsPutter} instance so callers do not
   * need to supply one explicitly.
   */
  public ClientLayerPersister(
      PriorityAwareExecutor executor,
      Ticker ticker,
      Node node,
      NodeClientCore core,
      PersistentTempBucketFactory persistentTempFactory,
      TempBucketFactory tempBucketFactory) {
    this(
        executor,
        ticker,
        node,
        core,
        persistentTempFactory,
        tempBucketFactory,
        new PersistentStatsPutter());
  }

  private void loadAllVariants(
      PartialLoad loaded,
      File dir,
      String baseName,
      DatabaseKey encryptionKey,
      boolean noSerialize,
      RequestStarterGroup requestStarters) {
    File clientDat = new File(dir, baseName);
    File clientDatCrypt = new File(dir, baseName + EXT_CRYPT);
    File clientDatBak = new File(dir, baseName + EXT_BAK);
    File clientDatBakCrypt = new File(dir, baseName + EXT_BAK + EXT_CRYPT);

    if (clientDat.exists()) {
      innerLoad(loaded, makeBucket(dir, baseName, false, null), noSerialize, requestStarters);
    }
    if (clientDatCrypt.exists() && loaded.needsMore()) {
      innerLoad(
          loaded, makeBucket(dir, baseName, false, encryptionKey), noSerialize, requestStarters);
    }
    if (clientDatBak.exists()) {
      innerLoad(loaded, makeBucket(dir, baseName, true, null), noSerialize, requestStarters);
    }
    if (clientDatBakCrypt.exists() && loaded.needsMore()) {
      innerLoad(
          loaded, makeBucket(dir, baseName, true, encryptionKey), noSerialize, requestStarters);
    }
  }

  private boolean resumeLoadedRequests(PartialLoad loaded) {
    ResumeCounters counters = new ResumeCounters();
    for (PartiallyLoadedRequest partial : loaded.partiallyLoadedRequests.values()) {
      if (partial.request == null) continue;
      ResumeOutcome outcome = resumeOne(partial);
      counters.accept(outcome);
    }
    counters.logSummary();
    return counters.failedSerialize;
  }

  private record ResumeOutcome(RequestLoadStatus status, boolean serializeFailed) {}

  private static final class ResumeCounters {
    int success;
    int restoredRestarted;
    int restoredFully;
    int failed;
    boolean failedSerialize;

    void accept(ResumeOutcome outcome) {
      if (outcome == null) return;
      switch (outcome.status) {
        case LOADED -> success++;
        case RESTORED_FULLY -> restoredFully++;
        case RESTORED_RESTARTED -> restoredRestarted++;
        case FAILED -> failed++;
      }
      if (outcome.serializeFailed) failedSerialize = true;
    }

    void logSummary() {
      if (success > 0) LOG.info("Resumed {} requests ...", success);
      if (restoredFully > 0)
        LOG.info("Restored {} requests (in spite of data corruption)", restoredFully);
      if (restoredRestarted > 0)
        LOG.info("Restarted {} requests (due to data corruption)", restoredRestarted);
      if (failed > 0) LOG.warn("Failed to restore {} requests due to data corruption", failed);
    }
  }

  private ResumeOutcome resumeOne(PartiallyLoadedRequest partial) {
    ClientRequest req = partial.request;
    try {
      req.onResume(getClientContext());
      if (partial.status == RequestLoadStatus.RESTORED_FULLY
          || partial.status == RequestLoadStatus.RESTORED_RESTARTED) {
        req.start(getClientContext());
      }
      return new ResumeOutcome(partial.status, false);
    } catch (Exception t) {
      boolean serializeFailed = partial.status == RequestLoadStatus.LOADED;
      LOG.error("Unable to resume request {} after loading it: {}", req, t, t);
      try {
        req.cancel(getClientContext());
      } catch (Exception t1) {
        LOG.error("Unable to terminate {} after failure: {}", req, t1, t1);
      }
      return new ResumeOutcome(RequestLoadStatus.FAILED, serializeFailed);
    }
  }

  /**
   * Assigns persistence targets and performs an initial load of previously saved requests.
   *
   * <p>This method configures the file set (plain/encrypted, primary/backup) under {@code dir},
   * attempts to load all variants in a recovery-friendly order, and initializes the salt used for
   * checksums. When {@code writeEncrypted} is {@code true}, a non-null {@code encryptionKey} is
   * required. When {@code noWrite} is {@code true}, all existing variants are deleted and future
   * checkpoints are disabled for the lifetime of the instance.
   *
   * <p>On load, corrupted variants are skipped and backups are probed to maximize recovery. After a
   * successful load, the method schedules an early checkpoint so the later state is captured
   * quickly.
   *
   * <pre>{@code
   * // Example: load and enable encrypted persistence
   * persister.setFilesAndLoad(dir, "client.dat", true, false, key, requestStarters);
   * }</pre>
   *
   * @param dir base directory that holds {@code client.dat} and its {@code .bak}/{@code .crypt}
   *     variants; must exist and be readable/writable by the running process.
   * @param baseName filename to use as the base (e.g., {@code "client.dat"}); suffixes are appended
   *     automatically for backups and encryption.
   * @param writeEncrypted whether to write future checkpoints using the provided {@code
   *     encryptionKey}; when {@code true} the unencrypted variants are rotated/cleaned as needed.
   * @param noWrite when {@code true}, disables all future writes and removes any existing variants
   *     from disk to operate without persistence (useful for high-security or test scenarios).
   * @param encryptionKey database key used to encrypt/decrypt the on-disk files when {@code
   *     writeEncrypted} is {@code true}; must be non-null in that case.
   * @param requestStarters coordinator used to apply the recovered salt and to restart or resume
   *     requests after a successful load; receives status updates during recovery.
   * @throws MasterKeysWrongPasswordException when encrypted files are present but {@code
   *     encryptionKey} is not supplied or cannot unlock them.
   */
  public void setFilesAndLoad(
      File dir,
      String baseName,
      boolean writeEncrypted,
      boolean noWrite,
      DatabaseKey encryptionKey,
      RequestStarterGroup requestStarters)
      throws MasterKeysWrongPasswordException {
    if (noWrite) super.disableWrite();
    synchronized (serializeCheckpoints) {
      this.dir = dir;
      this.baseName = baseName;
      if (noWrite) {
        writeToBucket = null;
        writeToFilename = null;
        writeToBackupFilename = null;
        deleteFile(dir, baseName, false, false);
        deleteFile(dir, baseName, false, true);
        deleteFile(dir, baseName, true, false);
        deleteFile(dir, baseName, true, true);
        onStarted(true);
        if (salt == null) {
          salt = new byte[32];
          fillRandom(salt);
          requestStarters.setGlobalSalt(salt);
        }
      } else if (!hasLoaded()) {
        // Some serialization failures cause us to fail only at the point of scheduling the request.
        // So if that happens, we need to retry with serialization turned off.
        // The requests that loaded fine already will not be affected as we check for duplicates.
        if (innerSetFilesAndLoad(
            false, dir, baseName, writeEncrypted, encryptionKey, requestStarters)) {
          LOG.error(
              "Some requests failed to restart after serializing. Trying to recover/restart ...");
          innerSetFilesAndLoad(true, dir, baseName, writeEncrypted, encryptionKey, requestStarters);
        }
        onStarted(false);
      } else {
        innerSetFilesOnly(dir, baseName, writeEncrypted, encryptionKey);
        onStarted(false);
      }
    }
  }

  private void deleteFile(File dir, String baseName, boolean backup, boolean encrypted) {
    File f = makeFilename(dir, baseName, backup, encrypted);
    try {
      FileUtil.secureDelete(f);
    } catch (IOException _) {
      try {
        Files.deleteIfExists(f.toPath());
      } catch (IOException _) {
        LOG.warn(
            "Failed to delete {} when setting maximum security level. There may be traces on disk"
                + " of your previous download queue.",
            f);
      }
    }
  }

  private void innerSetFilesOnly(
      File dir, String baseName, boolean writeEncrypted, DatabaseKey encryptionKey)
      throws MasterKeysWrongPasswordException {
    if (writeEncrypted && encryptionKey == null) throw new MasterKeysWrongPasswordException();
    File oldWriteToFilename = writeToFilename;
    writeToBucket = makeBucket(dir, baseName, false, writeEncrypted ? encryptionKey : null);
    writeToFilename = makeFilename(dir, baseName, false, writeEncrypted);
    writeToBackupFilename = makeFilename(dir, baseName, true, writeEncrypted);
    if (writeToFilename.equals(oldWriteToFilename)) return;
    LOG.info("Will save downloads to {}", writeToFilename);
    deleteAfterSuccessfulWrite = makeFilename(dir, baseName, false, !writeEncrypted);
    otherDeleteAfterSuccessfulWrite = makeFilename(dir, baseName, true, !writeEncrypted);
    // Force a checkpoint ASAP; this also avoids any possible locking issues.
    queueNormalOrDrop(_ -> true);
  }

  private boolean innerSetFilesAndLoad(
      boolean noSerialize,
      File dir,
      String baseName,
      boolean writeEncrypted,
      DatabaseKey encryptionKey,
      RequestStarterGroup requestStarters)
      throws MasterKeysWrongPasswordException {
    if (writeEncrypted && encryptionKey == null) throw new MasterKeysWrongPasswordException();
    File clientDat = new File(dir, baseName);
    File clientDatCrypt = new File(dir, baseName + EXT_CRYPT);
    File clientDatBak = new File(dir, baseName + EXT_BAK);
    File clientDatBakCrypt = new File(dir, baseName + EXT_BAK + EXT_CRYPT);
    if (encryptionKey == null && (clientDatCrypt.exists() || clientDatBakCrypt.exists()))
      throw new MasterKeysWrongPasswordException();
    PartialLoad loaded = new PartialLoad();
    loadAllVariants(loaded, dir, baseName, encryptionKey, noSerialize, requestStarters);

    deleteAfterSuccessfulWrite = writeEncrypted ? clientDat : clientDatCrypt;
    otherDeleteAfterSuccessfulWrite = writeEncrypted ? clientDatBak : clientDatBakCrypt;

    writeToBucket = makeBucket(dir, baseName, false, writeEncrypted ? encryptionKey : null);
    writeToFilename = makeFilename(dir, baseName, false, writeEncrypted);
    writeToBackupFilename = makeFilename(dir, baseName, true, writeEncrypted);

    if (loaded.doneSomething()) {
      maybeInitSalt(loaded, noSerialize, requestStarters);
      return resumeLoadedRequests(loaded);
    } else {
      // Starting without restoring any previous persistent state.
      LOG.info("Starting request persistence layer without resuming ...");
      salt = new byte[32];
      fillRandom(salt);
      requestStarters.setGlobalSalt(salt);
      onStarted(false);
      return false;
    }
  }

  private void maybeInitSalt(
      PartialLoad loaded, boolean noSerialize, RequestStarterGroup requestStarters) {
    if (noSerialize) return;
    onLoading();
    if (loaded.getSalt() == null) {
      salt = new byte[32];
      fillRandom(salt);
      LOG.error("Checksum failed for salt value");
      LOG.warn(
          "Salt value corrupted; downloads will need to regenerate Bloom filters which may cause"
              + " some delay and disk/CPU usage...");
      newSalt = true;
      // Propagate the regenerated salt to the schedulers to avoid mismatch
      // with the zero-filled salt applied during failed read.
      requestStarters.setGlobalSalt(salt);
    } else {
      salt = loaded.salt;
    }
  }

  private void fillRandom(byte[] buf) {
    try {
      ClientContext ctx = getClientContext();
      if (ctx != null && ctx.random != null) {
        ctx.random.nextBytes(buf);
        return;
      }
    } catch (Exception _) {
      // fall through to default RNG
    }
    FALLBACK_SECURE_RNG.nextBytes(buf);
  }

  /**
   * Create a Bucket for client.dat[.bak][.crypt].
   *
   * @param dir The parent directory.
   * @param baseName The base name, usually "client.dat".
   * @param backup True if we want the .bak file.
   * @param encryptionKey Non-null if we want an encrypted file.
   */
  private Bucket makeBucket(File dir, String baseName, boolean backup, DatabaseKey encryptionKey) {
    File filename = makeFilename(dir, baseName, backup, encryptionKey != null);
    Bucket bucket = new FileBucket(filename, false, false, false, false);
    if (encryptionKey != null) bucket = encryptionKey.createEncryptedBucketForClientLayer(bucket);
    return bucket;
  }

  private File makeFilename(File parent, String baseName, boolean backup, boolean encrypted) {
    return new File(parent, baseName + (backup ? EXT_BAK : "") + (encrypted ? EXT_CRYPT : ""));
  }

  private enum RequestLoadStatus {
    // In order of preference, the best first.
    LOADED,
    RESTORED_FULLY,
    RESTORED_RESTARTED,
    FAILED
  }

  private record PartiallyLoadedRequest(ClientRequest request, RequestLoadStatus status) {}

  private static class PartialLoad {
    private final Map<RequestIdentifier, PartiallyLoadedRequest> partiallyLoadedRequests =
        new HashMap<>();

    private byte[] salt;

    private boolean somethingFailed;

    private boolean doneSomething;

    /**
     * Add a partially loaded request.
     *
     * @param reqID The request identifier. Must be non-null; caller should regenerate it if
     *     necessary.
     */
    void addPartiallyLoadedRequest(
        RequestIdentifier reqID, ClientRequest request, RequestLoadStatus status) {
      if (reqID == null) {
        if (request == null) {
          somethingFailed = true;
          return;
        } else {
          reqID = request.getRequestIdentifier();
        }
      }
      PartiallyLoadedRequest old = partiallyLoadedRequests.get(reqID);
      if (old == null || old.status.compareTo(status) > 0) {
        partiallyLoadedRequests.put(reqID, new PartiallyLoadedRequest(request, status));
        if (!(status == RequestLoadStatus.LOADED || status == RequestLoadStatus.RESTORED_FULLY))
          somethingFailed = true;
        doneSomething = true;
      }
    }

    public boolean needsMore() {
      return somethingFailed || !doneSomething;
    }

    public void setSomethingFailed() {
      somethingFailed = true;
    }

    public void setSalt(byte[] loadedSalt) {
      if (salt == null) salt = loadedSalt;
      doneSomething = true;
    }

    public byte[] getSalt() {
      return salt;
    }

    public boolean doneSomething() {
      return doneSomething;
    }
  }

  private void innerLoad(
      PartialLoad loaded, Bucket bucket, boolean noSerialize, RequestStarterGroup requestStarters) {
    long length = bucket.size();
    try (InputStream fis = bucket.getInputStream()) {
      doLoadFromStream(
          loaded,
          fis,
          length,
          !noSerialize && !loaded.doneSomething(),
          requestStarters,
          noSerialize,
          bucket);
    } catch (IOException e) {
      // Mark this variant as failed so callers continue probing other backups/variants.
      loaded.setSomethingFailed();
      LOG.warn("I/O error reading persistence bucket {}: {}", bucket, e.toString());
    }
  }

  private void doLoadFromStream(
      PartialLoad loaded,
      InputStream fis,
      long length,
      boolean latest,
      RequestStarterGroup requestStarters,
      boolean noSerialize,
      Bucket bucket) {
    try {
      innerLoad(loaded, fis, length, latest, requestStarters, noSerialize);
    } catch (Exception t) {
      LOG.error("Failed to deserialize persistent requests from {}: {}", bucket, t, t);
      loaded.setSomethingFailed();
    }
  }

  private void innerLoad(
      PartialLoad loaded,
      InputStream fis,
      long length,
      boolean latest,
      RequestStarterGroup requestStarters,
      boolean noSerialize)
      throws IOException {
    ObjectInputStream ois = new ObjectInputStream(fis);
    long magic = ois.readLong();
    if (magic != MAGIC) throw new IOException("Bad magic");
    int version = ois.readInt();
    if (version != VERSION) throw new IOException("Bad version");
    readAndApplySalt(ois, loaded, requestStarters);
    int requestCount = ois.readInt();
    for (int i = 0; i < requestCount; i++) {
      processSingleRequest(ois, length, noSerialize, loaded);
    }
    if (latest) {
      try {
        // Only read stats/buckets from the latest version (client.dat not client.dat.bak).
        readStatsAndBuckets(ois, length);
      } catch (Exception t) {
        LOG.error("Failed to restore stats and delete old temp files: {}", t, t);
      }
    }
    ois.close();
  }

  private void readAndApplySalt(
      ObjectInputStream ois, PartialLoad loaded, RequestStarterGroup requestStarters)
      throws IOException {
    byte[] loadedSalt = new byte[32];
    try {
      checker.readAndChecksum(ois, loadedSalt, 0, loadedSalt.length);
      loaded.setSalt(loadedSalt);
    } catch (ChecksumFailedException _) {
      LOG.error("Unable to read global salt (checksum failed)");
    }
    requestStarters.setGlobalSalt(loadedSalt);
  }

  private void processSingleRequest(
      ObjectInputStream ois, long length, boolean noSerialize, PartialLoad loaded)
      throws IOException {
    RequestIdentifier reqID = readRequestIdentifier(ois);
    if (alreadyPresent(reqID, ois, length)) return;

    ClientRequest request = maybeReadSerialized(ois, length, noSerialize, reqID, loaded);
    if (request == null || LOG.isDebugEnabled()) {
      maybeRecoverFromRecoveryData(ois, length, reqID, loaded, request);
    } else {
      skipChecksummedObject(ois, length);
    }
  }

  private boolean alreadyPresent(RequestIdentifier reqID, ObjectInputStream ois, long length)
      throws IOException {
    if (reqID != null && getClientContext().persistentRoot.hasRequest(reqID)) {
      LOG.warn("Not reading request because already have it");
      skipChecksummedObject(ois, length); // Request itself
      skipChecksummedObject(ois, length); // Recovery data
      return true;
    }
    return false;
  }

  private ClientRequest maybeReadSerialized(
      ObjectInputStream ois,
      long length,
      boolean noSerialize,
      RequestIdentifier reqID,
      PartialLoad loaded)
      throws IOException {
    if (noSerialize) {
      // Advance past the serialized request; any IOException propagates to trigger fallback.
      skipChecksummedObject(ois, length);
      return null;
    }
    try {
      ClientRequest request = (ClientRequest) readChecksummedObject(ois, length);
      if (request != null && reqID != null) {
        if (!reqID.sameIdentifier(request.getRequestIdentifier())) {
          LOG.error("Request does not match request identifier, discarding");
          return null;
        } else {
          loaded.addPartiallyLoadedRequest(reqID, request, RequestLoadStatus.LOADED);
        }
      }
      return request;
    } catch (ChecksumFailedException _) {
      LOG.error("Failed to load serialized request (checksum failed)");
      return null;
    } catch (Exception t) {
      LOG.error("Failed to decode serialized request: {}", t, t);
      return null;
    }
  }

  @SuppressWarnings("UnusedReturnValue")
  private ClientRequest maybeRecoverFromRecoveryData(
      ObjectInputStream ois,
      long length,
      RequestIdentifier reqID,
      PartialLoad loaded,
      ClientRequest current) {
    try {
      ClientRequest restored = readRequestFromRecoveryData(ois, length, reqID);
      if (current == null && restored != null) {
        boolean loadedFully = restored.fullyResumed();
        loaded.addPartiallyLoadedRequest(
            reqID,
            restored,
            loadedFully ? RequestLoadStatus.RESTORED_FULLY : RequestLoadStatus.RESTORED_RESTARTED);
        return restored;
      }
    } catch (ChecksumFailedException _) {
      if (current == null) {
        LOG.error("Recovery data checksum mismatch while rebuilding request");
        loaded.addPartiallyLoadedRequest(reqID, null, RequestLoadStatus.FAILED);
      } else {
        LOG.error("Test recovery checksum mismatch for {}", reqID);
      }
    } catch (StorageFormatException e) {
      if (current == null) {
        LOG.error("Recovery data storage format error while rebuilding request: {}", e, e);
        loaded.addPartiallyLoadedRequest(reqID, null, RequestLoadStatus.FAILED);
      } else {
        LOG.error("Test recovery storage format error for {}: {}", reqID, e, e);
      }
    } catch (IOException e) {
      LOG.error("I/O error while reading recovery data to rebuild request: {}", e, e);
      if (current == null) loaded.addPartiallyLoadedRequest(reqID, null, RequestLoadStatus.FAILED);
    }
    return current;
  }

  private void readStatsAndBuckets(ObjectInputStream ois, long length)
      throws IOException, ClassNotFoundException {
    PersistentStatsPutter storedStatsPutter = (PersistentStatsPutter) ois.readObject();
    this.bandwidthStatsPutter.addFrom(storedStatsPutter);
    int count = ois.readInt();
    DelayedFree[] buckets = new DelayedFree[count];
    for (int i = 0; i < count; i++) {
      try {
        buckets[i] = (DelayedFree) readChecksummedObject(ois, length);
      } catch (ChecksumFailedException _) {
        LOG.warn("Failed to load a bucket to free");
      }
    }
    persistentTempFactory.finishDelayedFree(buckets);
  }

  @Override
  protected void innerCheckpoint(boolean shutdown) {
    save(shutdown);
  }

  /**
   * Writes the current persistent request set to the configured file, optionally as part of
   * shutdown.
   *
   * <p>On entry, if the target file already exists, it is first rotated to the backup location. The
   * save writes a header (magic, version), the checksum salt, request entries, and ancillary stats
   * and cleanup lists. On success, any queued deletions of now-stale variants are attempted. This
   * method is idempotent with respect to the in-memory state and may be invoked by the
   * checkpointing infrastructure at any time after files are configured.
   *
   * @param shutdown whether the node is shutting down; when {@code true}, requests are given an
   *     opportunity to flush internal state before serialization to improve resumability.
   */
  protected void save(boolean shutdown) {
    if (writeToFilename == null) return;
    if (writeToFilename.exists()) {
      FileUtil.moveTo(writeToFilename, writeToBackupFilename);
    }
    if (innerSave(shutdown)) {
      if (deleteAfterSuccessfulWrite != null) {
        try {
          Files.deleteIfExists(deleteAfterSuccessfulWrite.toPath());
        } catch (IOException e) {
          LOG.warn(
              "Failed to delete stale variant {} after successful write: {}",
              deleteAfterSuccessfulWrite,
              e.toString());
        }
        deleteAfterSuccessfulWrite = null;
      }
      if (otherDeleteAfterSuccessfulWrite != null) {
        try {
          Files.deleteIfExists(otherDeleteAfterSuccessfulWrite.toPath());
        } catch (IOException e) {
          LOG.warn(
              "Failed to delete stale backup variant {} after successful write: {}",
              otherDeleteAfterSuccessfulWrite,
              e.toString());
        }
        otherDeleteAfterSuccessfulWrite = null;
      }
    }
  }

  private boolean innerSave(boolean shutdown) {
    DelayedFree[] buckets = persistentTempFactory.grabBucketsToFree();
    try (OutputStream fos = writeToBucket.getOutputStream();
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeLong(MAGIC);
      oos.writeInt(VERSION);
      checker.writeAndChecksum(oos, salt);
      ClientRequest[] requests = getRequests();
      if (shutdown) {
        for (ClientRequest req : requests) {
          if (req == null) continue;
          callOnShutdown(req);
        }
      }
      oos.writeInt(requests.length);
      for (ClientRequest req : requests) {
        // Write the request identifier so we can skip reading the request if we already have it.
        writeRequestIdentifier(oos, req.getRequestIdentifier());
        // Write the actual request.
        writeChecksummedObject(oos, req, req.toString());
        // Write recovery data. This is just enough to restart the request from scratch,
        // but may support continuing the request in simple cases, e.g., if a fetch is now
        // just a single splitfile.
        writeRecoveryData(oos, req);
      }
      bandwidthStatsPutter.updateData(node);
      oos.writeObject(bandwidthStatsPutter);
      if (buckets == null) {
        oos.writeInt(0);
      } else {
        oos.writeInt(buckets.length);
        for (DelayedFree bucket : buckets) writeChecksummedObject(oos, bucket, null);
      }
      LOG.info("Saved {} requests to {}", requests.length, writeToFilename);
      persistentTempFactory.finishDelayedFree(buckets);
      return true;
    } catch (IOException e) {
      LOG.error("Failed to write persistent requests: {}", e, e);
      return false;
    }
  }

  private void callOnShutdown(ClientRequest req) {
    try {
      req.onShutdown(getClientContext());
    } catch (Exception t) {
      LOG.error("Caught while calling shutdown callback on {}: {}", req, t, t);
    }
  }

  private void writeRecoveryData(ObjectOutputStream os, ClientRequest req) throws IOException {
    PrependLengthOutputStream oos = checker.checksumWriterWithLengthNoClose(os, tempBucketFactory);
    try (DataOutputStream dos = new DataOutputStream(new NonClosingOutputStream(oos))) {
      req.getClientDetail(dos, checker);
    } catch (Exception e) {
      LOG.error("Unable to write recovery data stream for {}: {}", req, e, e);
      if (oos != null) oos.abort();
    } finally {
      if (oos != null) oos.close();
    }
  }

  private ClientRequest readRequestFromRecoveryData(
      ObjectInputStream is, long totalLength, RequestIdentifier reqID)
      throws IOException, ChecksumFailedException, StorageFormatException {
    InputStream tmp = checker.checksumReaderWithLength(is, this.tempBucketFactory, totalLength);
    try (DataInputStream dis = new DataInputStream(tmp)) {
      ClientRequest request = ClientRequest.restartFrom(dis, reqID, getClientContext(), checker);
      tmp = null;
      return request;
    } catch (Exception t) {
      LOG.error("Serialization failed while reading recovery data: {}", t, t);
      return null;
    } finally {
      if (tmp != null) tmp.close();
    }
  }

  private void writeChecksummedObject(ObjectOutputStream os, Object req, String name)
      throws IOException {
    PrependLengthOutputStream oos = checker.checksumWriterWithLengthNoClose(os, tempBucketFactory);
    try (ObjectOutputStream innerOOS = new ObjectOutputStream(new NonClosingOutputStream(oos))) {
      innerOOS.writeObject(req);
    } catch (Exception e) {
      LOG.error("Unable to write check-summed object for {}: {}", name, e, e);
      if (oos != null) oos.abort();
    } finally {
      if (oos != null) oos.close();
    }
  }

  /**
   * OutputStream wrapper that prevents closing the underlying stream when the outer resource is
   * closed. Used to preserve abort-before-close semantics while leveraging try-with-resources.
   */
  private static class NonClosingOutputStream extends java.io.FilterOutputStream {
    NonClosingOutputStream(OutputStream out) {
      super(out);
    }

    @Override
    public void close() throws IOException {
      // Do not close the underlying stream; only flush to propagate buffered bytes.
      out.flush();
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) throws IOException {
      out.write(b, off, len);
    }
  }

  private Object readChecksummedObject(ObjectInputStream is, long totalLength)
      throws IOException, ChecksumFailedException {
    InputStream ois = checker.checksumReaderWithLength(is, this.tempBucketFactory, totalLength);
    try (ObjectInputStream oo = new ObjectInputStream(ois)) {
      Object ret = oo.readObject();
      ois = null;
      return ret;
    } catch (Exception t) {
      LOG.error("Serialization failed while reading check-summed object: {}", t, t);
      return null;
    } finally {
      if (ois != null) ois.close();
    }
  }

  private void skipChecksummedObject(ObjectInputStream is, long totalLength) throws IOException {
    long length = is.readLong();
    if (length > totalLength) throw new IOException("Too long: " + length + " > " + totalLength);
    FileUtil.skipFully(is, length + checker.checksumLength());
  }

  private ClientRequest[] getRequests() {
    return clientCore.getPersistentRequests();
  }

  @Override
  public boolean newSalt() {
    return newSalt;
  }

  private RequestIdentifier readRequestIdentifier(DataInput is) throws IOException {
    short length = is.readShort();
    if (length <= 0) return null;
    byte[] buf = new byte[length];
    try {
      checker.readAndChecksum(is, buf, 0, length);
    } catch (ChecksumFailedException _) {
      LOG.error(
          "Checksum failed reading RequestIdentifier. This is not serious but means we will have to"
              + " read the next request even if we don't need it.");
      return null;
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    try {
      return new RequestIdentifier(dis);
    } catch (IOException e) {
      LOG.error(
          "Failed to parse RequestIdentifier in spite of valid checksum (probably a bug): {}",
          e,
          e);
      return null;
    }
  }

  private void writeRequestIdentifier(DataOutput os, RequestIdentifier req) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    OutputStream oos = checker.checksumWriter(baos);
    DataOutputStream dos = new DataOutputStream(oos);
    req.writeTo(dos);
    dos.close();
    byte[] buf = baos.toByteArray();
    os.writeShort(buf.length - checker.checksumLength());
    os.write(buf);
  }

  /**
   * Returns the main persistence file currently configured for writes.
   *
   * @return absolute file path to the primary variant (plain or encrypted), or {@code null} if
   *     writes are currently disabled via {@link #disableWrite()} or not yet configured.
   */
  public synchronized File getWriteFilename() {
    return writeToFilename;
  }

  /**
   * Returns the persistent bandwidth statistics collector.
   *
   * <p>The returned instance accumulates bandwidth and uptime data across restarts when the client
   * persistence layer is enabled.
   */
  public PersistentStatsPutter getBandwidthStatsPutter() {
    return bandwidthStatsPutter;
  }

  /**
   * Forces an immediate stop of background persistence and removes all on-disk variants.
   *
   * <p>This is a best-effort cleanup helper intended for emergency/error scenarios. It cancels any
   * in-flight save, waits for write activity to quiesce, and then deletes the primary, backup, and
   * encrypted variants under the configured directory.
   */
  public void panic() {
    killAndWaitForNotWriting();
    deleteAllFiles();
  }

  /**
   * Deletes all known variants of the persistence files.
   *
   * <p>Removes plain, encrypted, and backup forms of {@code baseName} under {@code dir}. The method
   * is synchronized on the checkpoint monitor to avoid races with ongoing save operations and is
   * safe to call multiple times.
   */
  public void deleteAllFiles() {
    synchronized (serializeCheckpoints) {
      deleteFile(dir, baseName, false, false);
      deleteFile(dir, baseName, false, true);
      deleteFile(dir, baseName, true, false);
      deleteFile(dir, baseName, true, true);
    }
  }

  @Override
  public void disableWrite() {
    synchronized (serializeCheckpoints) {
      writeToFilename = null;
      writeToBackupFilename = null;
      writeToBucket = null;
    }
    super.disableWrite();
  }
}
