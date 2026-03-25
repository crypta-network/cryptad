package network.crypta.node;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.runtime.alerts.DroppedOldPeersUserAlert;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Coordinates persistence of peer references for {@link PeerManager}.
 *
 * <p>This helper encapsulates the disk I/O for reading peer reference files on startup and
 * periodically writing updated snapshots for darknet, opennet, and old opennet peers. It is created
 * and owned by {@link PeerManager}; callers schedule work or mark peers dirty, while the class
 * handles serialization, backup rotation, and best-effort recovery when files are missing or
 * partially corrupt. Cached snapshots of the last written state prevent redundant writes and reduce
 * churn on the filesystem.
 *
 * <p>Concurrency: callers may invoke write/mark methods from different threads. This class uses
 * lightweight synchronization and volatile flags to coordinate state, while actual I/O happens on
 * the ticker or executor threads provided by {@link Node}. It does not expose external
 * thread-safety guarantees beyond those internal guards.
 *
 * <ul>
 *   <li>Read peer reference files, with backup fallback and error reporting.
 *   <li>Write snapshots with optional backup rotation and atomic replacement.
 *   <li>Track old opennet peers separately for reconnection attempts.
 * </ul>
 */
class PeerPersistence {
  /** Logger for persistence I/O, parsing, and recovery diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(PeerPersistence.class);

  /** Read-log prefix used by {@link #buildReadMessage(File, OpennetManager, boolean, boolean)}. */
  private static final String READ_PREFIX = "Read ";

  /** Number of backup generations retained for opennet peer files. */
  private static final int BACKUPS_OPENNET = 1;

  /** Number of backup generations retained for darknet peer files. */
  private static final int BACKUPS_DARKNET = 10;

  /** Minimum delay between scheduled non-urgent peer writes, in milliseconds. */
  private static final long MIN_WRITEPEERS_DELAY = MINUTES.toMillis(5);

  /** Defensive fallback used when old-opennet peers are unexpectedly absent. */
  private static final OpennetPeerNode[] EMPTY_OLD_OPENNET_PEERS = new OpennetPeerNode[0];

  /** Owning node, used for scheduling, alerts, and access to opennet services. */
  private final Node node;

  /** Peer manager that owns the peer roster and accepts newly parsed peers. */
  private final PeerManager peerManager;

  /** Guards access to filenames and cached serialized snapshots during writes. */
  private final Object writePeersSync = new Object();

  /** Serializes file-system writes and backup rotations. */
  private final Object writePeerFileSync = new Object();

  /** Dirty flag for pending darknet writes, set by requests and cleared on writing. */
  private volatile boolean shouldWritePeersDarknet = false;

  /** Dirty flag for pending opennet writes, set by requests and cleared on writing. */
  private volatile boolean shouldWritePeersOpennet = false;

  /** Current filename for the darknet peers file, or {@code null} until known. */
  private String darkFilename;

  /** Current filename for the opennet peers file, or {@code null} until known. */
  private String openFilename;

  /** Current filename for the old-opennet peers file, or {@code null} until known. */
  private String oldOpennetPeersFilename;

  // Note: Potential improvement: use a dedicated stable hash (not hashCode()).
  // Note: Potential improvement: strip non-essential metadata; keep peer locations only.
  /** Serialized snapshot of the last written darknet peers, for change detection. */
  private String darknetPeersStringCache = null;

  /** Serialized snapshot of the last written opennet peers, for change detection. */
  private String opennetPeersStringCache = null;

  /** Serialized snapshot of the last written old-opennet peers, for change detection. */
  private String oldOpennetPeersStringCache = null;

  /** Periodic write runnable that writes peers and re-schedules itself. */
  private final Runnable writePeersRunnable = this::writePeersAndReschedule;

  private void writePeersAndReschedule() {
    try {
      writePeersNow();
    } finally {
      scheduleWritePeersNextRun();
    }
  }

  /**
   * Create a new persistence helper bound to a node and its peer manager.
   *
   * <p>The instance is lightweight and does not perform I/O until scheduled. Callers typically
   * invoke {@link #scheduleInitialWrite()} during startup and {@link #flushOnShutdown()} during
   * shutdown to ensure files are flushed. This class assumes the provided components remain valid
   * for the life of the node and does not attempt to outlive them.
   *
   * @param node owning node used for scheduling, alerts, and opennet access; must not be {@code
   *     null}
   * @param peerManager peer manager that owns the peer roster; must not be {@code null}
   */
  PeerPersistence(Node node, PeerManager peerManager) {
    this.node = node;
    this.peerManager = peerManager;
  }

  /**
   * Schedule the periodic peer persistence job to run immediately.
   *
   * <p>This is normally invoked during startup once the node has completed construction. The
   * runnable performs a best-effort writing if peers are marked dirty, then re-schedules itself
   * using {@link #scheduleWritePeersNextRun()} so the periodic cycle continues.
   */
  void scheduleInitialWrite() {
    node.network().ticker().queueTimedJob(writePeersRunnable, 0);
  }

  /**
   * Flush peer files during shutdown to avoid waiting for the periodic writing interval.
   *
   * <p>This marks both darknet and opennet peer lists as dirty and then writes them synchronously
   * on the current thread. The writing is best-effort: failures are logged but do not abort
   * shutdown.
   */
  void flushOnShutdown() {
    markWriteDarknet();
    markWriteOpennet();
    writePeersNow();
  }

  /**
   * Attempt to read a file full of noderefs. Try the file as named first, then the .bak if it is
   * empty or otherwise doesn't work. WARNING: Only call this AFTER the Node constructor has
   * completed! Methods may be called on Node!
   *
   * <p>The method attempts the primary file first and then tries to back up files in order,
   * stopping at the first successful parse. If entries are unparseable or too old, they are skipped
   * and the original file is copied to a {@code .broken} file for inspection. When reading old
   * opennet peers, entries are routed to the opennet manager instead of the routing table. This
   * method does not throw; all failures are logged and treated as a non-fatal startup condition.
   *
   * @param filename path to the peers file; backups are derived from this name
   * @param crypto cryptographic identity for peers being loaded; must not be {@code null}
   * @param opennet opennet manager used for opennet peers; may be {@code null} if not opennet
   * @param isOpennet whether the file contains opennet peers instead of darknet peers
   * @param oldOpennetPeers when {@code true}, treat entries as old peers for reconnection attempts
   */
  void tryReadPeers(
      String filename,
      NodeCrypto crypto,
      OpennetManager opennet,
      boolean isOpennet,
      boolean oldOpennetPeers) {
    recordPeerFilename(filename, isOpennet, oldOpennetPeers);
    int maxBackups = isOpennet ? BACKUPS_OPENNET : BACKUPS_DARKNET;
    for (int i = 0; i <= maxBackups; i++) {
      File peersFile = getBackupFilename(filename, i);
      // Try to read the node list from the disk
      if (peersFile.exists() && readPeers(peersFile, crypto, opennet, oldOpennetPeers)) {
        if (LOG.isInfoEnabled()) {
          LOG.info(buildReadMessage(peersFile, opennet, isOpennet, oldOpennetPeers));
        }
        return;
      }
    }
    logMissingPeers(isOpennet);
    // The other cases are less important.
  }

  /**
   * Mark a peer list write request so the next periodic run persists it.
   *
   * <p>This is a low-priority, coalesced update. The flag is checked on the periodic runnable; if
   * multiple calls arrive before the next tick, only one writing occurs. Use {@link
   * #writePeersUrgent(boolean)} for immediate persistence on a high-priority executor thread.
   *
   * @param opennet {@code true} to mark opennet peers; {@code false} for darknet peers
   */
  void writePeers(boolean opennet) {
    if (opennet) markWriteOpennet();
    else markWriteDarknet();
  }

  /**
   * Write peers immediately on a high-priority executor thread.
   *
   * <p>This bypasses the periodic delay and triggers an immediate writing with backup rotation. The
   * writing is still serialized with other disk writes to avoid concurrent file operations.
   *
   * @param opennet {@code true} to write opennet peers; {@code false} for darknet peers
   */
  void writePeersUrgent(boolean opennet) {
    if (opennet) writePeersOpennetUrgent();
    else writePeersDarknetUrgent();
  }

  /**
   * Schedule the next periodic peer writing after the configured delay.
   *
   * <p>This keeps the persistence loop running even if the previous writing encountered errors. The
   * delay is fixed and expressed in milliseconds by {@link #MIN_WRITEPEERS_DELAY}.
   */
  private void scheduleWritePeersNextRun() {
    node.network().ticker().queueTimedJob(writePeersRunnable, MIN_WRITEPEERS_DELAY);
  }

  /**
   * Write any pending peer lists immediately without rotating backups.
   *
   * <p>This method performs the periodic, non-urgent writing path. It clears dirty flags and writes
   * only if the cached snapshot differs from the current serialized state.
   */
  private void writePeersNow() {
    // Non-urgent periodic write does not rotate backups.
    writePeersDarknetNow(false);
    writePeersOpennetNow(false);
  }

  /**
   * Record the current peer filename for later write operations.
   *
   * @param filename path to the peer file to remember for future writes
   * @param isOpennet {@code true} if the filename is for opennet peers
   * @param oldOpennetPeers {@code true} when the filename is for old opennet peers
   */
  private void recordPeerFilename(String filename, boolean isOpennet, boolean oldOpennetPeers) {
    synchronized (writePeersSync) {
      if (!oldOpennetPeers) {
        if (isOpennet) {
          openFilename = filename;
        } else {
          darkFilename = filename;
        }
      }
    }
  }

  /**
   * Build a human-readable message describing the most recent peer read.
   *
   * @param peersFile file that was read successfully
   * @param opennet opennet manager for old-peers count, or {@code null} when absent
   * @param isOpennet {@code true} if the file contained opennet peers
   * @param oldOpennetPeers {@code true} if the file contained old opennet peers
   * @return a formatted log message describing the peer counts and source file
   */
  private String buildReadMessage(
      File peersFile, OpennetManager opennet, boolean isOpennet, boolean oldOpennetPeers) {
    if (oldOpennetPeers) {
      int oldPeers = opennet == null ? 0 : opennet.countOldOpennetPeers();
      return READ_PREFIX + oldPeers + " old-opennet-peers from " + peersFile;
    }
    if (isOpennet) {
      return READ_PREFIX + getOpennetPeerCount() + " opennet peers from " + peersFile;
    }
    return READ_PREFIX + getDarknetPeerCount() + " darknet peers from " + peersFile;
  }

  /**
   * Log when expected peer files are missing during startup.
   *
   * @param isOpennet {@code true} if the missing file is for opennet peers
   */
  private void logMissingPeers(boolean isOpennet) {
    if (!isOpennet) {
      LOG.info("No darknet peers file found.");
    }
  }

  /**
   * Return the current opennet peer count based on the roster snapshot.
   *
   * @return number of opennet peers currently known to the roster
   */
  private int getOpennetPeerCount() {
    PeerRoster roster = peerManager.roster();
    return roster == null ? 0 : roster.getOpennetPeers().length;
  }

  /**
   * Return the current darknet peer count based on the roster snapshot.
   *
   * @return number of darknet peers currently known to the roster
   */
  private int getDarknetPeerCount() {
    PeerRoster roster = peerManager.roster();
    return roster == null ? 0 : roster.getDarknetPeers().length;
  }

  /**
   * Write darknet peers immediately if they have been marked dirty.
   *
   * @param rotateBackups whether to rotate backup files instead of overwriting the primary file
   */
  private void writePeersDarknetNow(boolean rotateBackups) {
    if (shouldWritePeersDarknet) {
      shouldWritePeersDarknet = false;
      writePeersInnerDarknet(rotateBackups);
    }
  }

  /**
   * Write opennet peers immediately if they have been marked dirty.
   *
   * @param rotateBackups whether to rotate backup files instead of overwriting the primary file
   */
  private void writePeersOpennetNow(boolean rotateBackups) {
    if (shouldWritePeersOpennet) {
      shouldWritePeersOpennet = false;
      writePeersInnerOpennet(rotateBackups);
    }
  }

  /**
   * Dispatch an urgent opennet writing on the executor with high priority.
   *
   * <p>This path rotates backups and runs outside the ticker to reduce latency.
   */
  private void writePeersOpennetUrgent() {
    node.network()
        .executor()
        .execute(
            new PrioRunnable() {
              @Override
              public void run() {
                writePeersOpennetNow(true);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
              }
            });
  }

  /**
   * Dispatch an urgent darknet writing on the executor with high priority.
   *
   * <p>This path rotates backups and runs outside the ticker to reduce latency.
   */
  private void writePeersDarknetUrgent() {
    node.network()
        .executor()
        .execute(
            new PrioRunnable() {
              @Override
              public void run() {
                writePeersDarknetNow(true);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
              }
            });
  }

  /** Mark the darknet peers as dirty so the next writing persists them. */
  private void markWriteDarknet() {
    shouldWritePeersDarknet = true;
  }

  /** Mark the opennet peers as dirty so the next writing persists them. */
  private void markWriteOpennet() {
    shouldWritePeersOpennet = true;
  }

  /**
   * Serialize current darknet peers to an ordered field set string.
   *
   * @return serialized representation of darknet peers, possibly empty but never {@code null}
   */
  private String getDarknetPeersString() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = peerManager.myPeers();
    for (PeerNode pn : peers) {
      if (pn instanceof DarknetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }
    return sb.toString();
  }

  /**
   * Serialize current opennet peers to an ordered field set string.
   *
   * @return serialized representation of opennet peers, possibly empty but never {@code null}
   */
  private String getOpennetPeersString() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = peerManager.myPeers();
    for (PeerNode pn : peers) {
      if (pn instanceof OpennetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }
    return sb.toString();
  }

  /**
   * Serialize the current old opennet peers to an ordered field set string.
   *
   * @param om opennet manager providing the old-peer collection; must not be {@code null}
   * @return serialized representation of old opennet peers, possibly empty but never {@code null}
   */
  private String getOldOpennetPeersString(OpennetManager om) {
    StringBuilder sb = new StringBuilder();
    OpennetPeerNode[] oldPeers =
        Objects.requireNonNullElse(om.getOldPeers(), EMPTY_OLD_OPENNET_PEERS);
    for (OpennetPeerNode pn : oldPeers) {
      sb.append(pn.exportDiskFieldSet().toOrderedString());
    }
    return sb.toString();
  }

  /**
   * Write the darknet peers file if the serialized snapshot changed.
   *
   * @param rotateBackups whether to rotate backup files instead of overwriting the primary file
   */
  private void writePeersInnerDarknet(boolean rotateBackups) {
    String newDarknetPeersString;
    synchronized (writePeersSync) {
      newDarknetPeersString = darkFilename != null ? getDarknetPeersString() : null;
    }
    synchronized (writePeerFileSync) {
      if (newDarknetPeersString != null && !newDarknetPeersString.equals(darknetPeersStringCache)) {
        darknetPeersStringCache = newDarknetPeersString;
        writePeersInner(darkFilename, darknetPeersStringCache, BACKUPS_DARKNET, rotateBackups);
      }
    }
  }

  /**
   * Write opennet and old-opennet peer files if their snapshots changed.
   *
   * @param rotateBackups whether to rotate backup files instead of overwriting the primary file
   */
  private void writePeersInnerOpennet(boolean rotateBackups) {
    String newOpennetPeersString = null;
    String newOldOpennetPeersString = null;
    synchronized (writePeersSync) {
      OpennetManager om = node.network().opennet();
      if (om != null) {
        if (openFilename != null) newOpennetPeersString = getOpennetPeersString();
        oldOpennetPeersFilename = om.getOldPeersFilename();
        newOldOpennetPeersString = getOldOpennetPeersString(om);
      }
    }
    synchronized (writePeerFileSync) {
      if (newOpennetPeersString != null && !newOpennetPeersString.equals(opennetPeersStringCache)) {
        opennetPeersStringCache = newOpennetPeersString;
        writePeersInner(openFilename, opennetPeersStringCache, BACKUPS_OPENNET, rotateBackups);
      }
      if (newOldOpennetPeersString != null
          && oldOpennetPeersFilename != null
          && !newOldOpennetPeersString.equals(oldOpennetPeersStringCache)) {
        oldOpennetPeersStringCache = newOldOpennetPeersString;
        writePeersInner(
            oldOpennetPeersFilename, oldOpennetPeersStringCache, BACKUPS_OPENNET, rotateBackups);
      }
    }
  }

  /**
   * Write a serialized peers file to disk.
   *
   * <p>The writing uses a temporary file, flushes and syncs it, then either rotates backups or
   * replaces the primary file. This method is synchronized to prevent concurrent writes from
   * interleaving or corrupting the backup chain. Errors are logged, and the previous file is left
   * intact when possible.
   *
   * @param filename target filename to write, not {@code null}
   * @param sb serialized peers content, in UTF-8, not {@code null}
   * @param maxBackups number of backup generations to retain; must be at least 1
   * @param rotateBackups if {@code true}, rotate backups; otherwise overwrite the primary file
   */
  private void writePeersInner(String filename, String sb, int maxBackups, boolean rotateBackups) {
    assert (maxBackups >= 1);
    synchronized (writePeerFileSync) {
      File f;
      File full = new File(filename).getAbsoluteFile();
      try {
        f = File.createTempFile(full.getName() + ".", ".tmp", full.getParentFile());
      } catch (IOException e2) {
        LOG.error("Cannot write peers to disk: temp file creation error={}", e2, e2);
        return;
      }

      try (FileOutputStream fos = new FileOutputStream(f);
          OutputStreamWriter w = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
        w.write(sb);
        w.flush();
        fos.getFD().sync();
      } catch (FileNotFoundException e2) {
        LOG.error("Cannot write peers to disk: cannot create {} (error={})", f, e2, e2);
        safeDeleteIfExists(f);
        return;
      } catch (IOException e) {
        LOG.error("I/O error writing peers file: {}", e, e);
        safeDeleteIfExists(f);
        // don't overwrite the old file!
        return;
      }

      try {
        if (rotateBackups) {
          rotateBackupFiles(filename, maxBackups, f);
        } else {
          FileUtil.moveTo(f, getBackupFilename(filename, 0));
        }
      } finally {
        safeDeleteIfExists(f);
      }
    }
  }

  /**
   * Rotate backup files and install the new peers file as the latest generation.
   *
   * @param filename base filename used to compute backup paths
   * @param maxBackups maximum number of backup generations to keep
   * @param newFile temporary file containing the new peers content
   */
  private void rotateBackupFiles(String filename, int maxBackups, File newFile) {
    File prevFile = null;
    for (int i = maxBackups; i >= 0; i--) {
      File thisFile = getBackupFilename(filename, i);
      if (prevFile == null) {
        safeDeleteIfExists(thisFile);
      } else if (thisFile.exists()) {
        FileUtil.moveTo(thisFile, prevFile);
      }
      prevFile = thisFile;
    }
    if (prevFile == null) prevFile = getBackupFilename(filename, 0);
    FileUtil.moveTo(newFile, prevFile);
  }

  /**
   * Resolve the backup filename for a given generation index.
   *
   * @param filename base filename for peers
   * @param i backup index, where {@code 0} is the primary and {@code 1} is {@code .bak}
   * @return the resolved backup file path for the given index
   */
  private File getBackupFilename(String filename, int i) {
    if (i == 0) return new File(filename);
    if (i == 1) return new File(filename + ".bak");
    return new File(filename + ".bak." + i);
  }

  /**
   * Read and parse peers from a file, returning whether the read was fully successful.
   *
   * <p>If parsing fails for some entries, a copy of the original file is written to a {@code
   * .broken} suffix for later inspection. Old opennet peers are routed to the opennet manager,
   * while darknet peers are added directly to the peer manager. Exceptions are logged and treated
   * as non-fatal, so startup can continue.
   *
   * @param peersFile file to read and parse
   * @param crypto cryptographic identity used to validate parsed peers
   * @param opennet opennet manager, required when parsing opennet peers
   * @param oldOpennetPeers {@code true} when parsing old opennet peers instead of active peers
   * @return {@code true} if all entries were parsed and applied successfully
   */
  @SuppressWarnings("java:S1181")
  private boolean readPeers(
      File peersFile, NodeCrypto crypto, OpennetManager opennet, boolean oldOpennetPeers) {
    boolean someBroken;
    File brokenPeersFile = new File(peersFile.getPath() + ".broken");
    DroppedOldPeersUserAlert droppedOldPeers = new DroppedOldPeersUserAlert(brokenPeersFile);
    List<SimpleFieldSet> peerEntries = new ArrayList<>();
    // read the peers file
    try (FileInputStream fis = new FileInputStream(peersFile);
        InputStreamReader ris = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(ris)) {
      readPeerFieldSets(br, peerEntries);
    } catch (FileNotFoundException _) {
      LOG.info("Peers file not found: {}", peersFile);
      return false;
    } catch (IOException e3) {
      LOG.error("Read error {} on {}", e3, peersFile, e3);
    }

    List<PeerNode> createdNodes =
        createPeerNodesFromEntries(peerEntries, crypto, opennet, droppedOldPeers);
    // Consider the file "broken" if we could not create all peers (parse errors or too-old entries)
    someBroken = (createdNodes.size() != peerEntries.size());
    applyCreatedNodes(createdNodes, opennet, oldOpennetPeers);
    if (someBroken) {
      try {
        safeDeleteIfExists(brokenPeersFile);
        try (FileOutputStream fos = new FileOutputStream(brokenPeersFile);
            FileInputStream fis = new FileInputStream(peersFile)) {
          FileUtil.copy(fis, fos, -1);
        }
        LOG.warn("Broken peers file copied to {}", brokenPeersFile);
      } catch (IOException _) {
        LOG.warn("Unable to copy broken peers file");
      }
    }
    if (!droppedOldPeers.isEmpty()) {
      try {
        node.services().clientCore().getAlerts().register(droppedOldPeers);
        LOG.error(droppedOldPeers.getText());
      } catch (Throwable t) {
        // Startup MUST complete, don't let client layer problems kill it.
        LOG.error("Caught error telling user about dropped peers", t);
      }
    }
    return !someBroken;
  }

  /**
   * Convert serialized field sets into peer nodes, skipping entries that fail validation.
   *
   * @param peerEntries parsed field sets for peers, in file order
   * @param crypto cryptographic identity used to validate peer references
   * @param opennet opennet manager used when creating opennet peers
   * @param droppedOldPeers user alert collector for too-old peers
   * @return list of successfully created peer nodes, possibly empty
   */
  private List<PeerNode> createPeerNodesFromEntries(
      List<SimpleFieldSet> peerEntries,
      NodeCrypto crypto,
      OpennetManager opennet,
      DroppedOldPeersUserAlert droppedOldPeers) {
    List<PeerNode> created = new ArrayList<>();
    for (SimpleFieldSet fs : peerEntries) {
      try {
        created.add(createPeerNode(fs, crypto, opennet));
      } catch (FSParseException
          | PeerParseException
          | ReferenceSignatureVerificationException
          | PeerTooOldException
          | RuntimeException e2) {
        PeerTooOldException tooOld = unwrapPeerTooOld(e2);
        if (tooOld != null) {
          if (crypto.isOpennet()) {
            LOG.error("Dropping too-old opennet peer");
          } else {
            droppedOldPeers.add(tooOld, fs.get("myName"));
          }
        } else {
          handlePeerCreationException(e2, fs);
        }
      }
    }
    // Always return successfully parsed peers; callers decide whether some entries were broken.
    return created;
  }

  private static PeerTooOldException unwrapPeerTooOld(Throwable t) {
    if (t instanceof PeerTooOldException peerTooOldException) {
      return peerTooOldException;
    }
    if (t instanceof FSParseException fsParseException
        && fsParseException.getCause() instanceof PeerTooOldException peerTooOldException) {
      return peerTooOldException;
    }
    return null;
  }

  PeerNode createPeerNode(SimpleFieldSet fs, NodeCrypto crypto, OpennetManager opennet)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (crypto.isOpennet()) {
      return new OpennetPeerNode(fs, node, crypto, opennet, true, peerManager);
    }
    return new DarknetPeerNode(fs, node, crypto, true, null, null, peerManager);
  }

  /**
   * Apply created peers to either the opennet manager or the peer manager.
   *
   * @param createdNodes peers successfully created from the input file
   * @param opennet opennet manager used for old-opennet peers, may be {@code null}
   * @param oldOpennetPeers {@code true} to add to old-opennet storage instead of routing table
   */
  private void applyCreatedNodes(
      List<PeerNode> createdNodes, OpennetManager opennet, boolean oldOpennetPeers) {
    for (PeerNode pn : createdNodes) {
      if (oldOpennetPeers) {
        if (pn instanceof OpennetPeerNode opennetPeerNode) {
          if (opennet != null) {
            opennet.addOldOpennetNode(opennetPeerNode);
          } else {
            LOG.error("Opennet manager missing for old opennet peer: {}", pn);
          }
        } else {
          LOG.error("Darknet node in old opennet peers: {}", pn);
        }
      } else {
        peerManager.addPeer(pn, true, false);
      }
    }
  }

  /**
   * Log peer creation failures with both error and warning messages.
   *
   * @param e2 exception thrown while parsing or verifying a peer entry
   * @param fs serialized field set that caused the parse failure
   */
  private void handlePeerCreationException(Exception e2, SimpleFieldSet fs) {
    LOG.error("Peer parse error {} for {}", e2, fs, e2);
    LOG.warn("Cannot parse friend from peers file: {}", e2, e2);
  }

  /**
   * Read all peer field sets from a buffered reader.
   *
   * @param br reader positioned at the start of the peers file
   * @param out destination list for parsed field sets
   * @throws IOException if an I/O error occurs while reading from the stream
   */
  private void readPeerFieldSets(BufferedReader br, List<SimpleFieldSet> out) throws IOException {
    for (SimpleFieldSet sfs = readNextPeerFieldSet(br);
        sfs != null;
        sfs = readNextPeerFieldSet(br)) {
      out.add(sfs);
    }
  }

  /**
   * Read the next peer field set from the stream.
   *
   * @param br reader positioned at the next field set
   * @return parsed field set, or {@code null} when end-of-file is reached
   * @throws IOException if an I/O error occurs while reading from the stream
   */
  private SimpleFieldSet readNextPeerFieldSet(BufferedReader br) throws IOException {
    try {
      return new SimpleFieldSet(br, false, true);
    } catch (EOFException _) {
      return null; // end-of-file reached
    }
  }

  /**
   * Delete a file if it exists, ignoring I/O errors.
   *
   * @param file file to delete, possibly {@code null} if no temp file was created
   */
  private static void safeDeleteIfExists(File file) {
    try {
      java.nio.file.Files.deleteIfExists(file.toPath());
    } catch (IOException _) {
      // best-effort
    }
  }
}
