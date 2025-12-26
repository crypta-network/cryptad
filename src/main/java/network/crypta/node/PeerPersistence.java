package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

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
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.useralerts.DroppedOldPeersUserAlert;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles peer reference persistence for {@link PeerManager}.
 *
 * <p>Responsible for reading peer files, writing updated peer lists, rotating backups, and caching
 * serialized peers. The manager owns the scheduling and synchronization for disk I/O.
 */
class PeerPersistence {
  private static final Logger LOG = LoggerFactory.getLogger(PeerPersistence.class);
  private static final String READ_PREFIX = "Read ";
  private static final int BACKUPS_OPENNET = 1;
  private static final int BACKUPS_DARKNET = 10;
  private static final long MIN_WRITEPEERS_DELAY = MINUTES.toMillis(5);

  private final Node node;
  private final PeerManager peerManager;

  private final Object writePeersSync = new Object();
  private final Object writePeerFileSync = new Object();

  private volatile boolean shouldWritePeersDarknet = false;
  private volatile boolean shouldWritePeersOpennet = false;

  private String darkFilename;
  private String openFilename;
  private String oldOpennetPeersFilename;

  // Note: Potential improvement: use a dedicated stable hash (not hashCode()).
  // Note: Potential improvement: strip non-essential metadata; keep peer locations only.
  private String darknetPeersStringCache = null;
  private String opennetPeersStringCache = null;
  private String oldOpennetPeersStringCache = null;

  private final Runnable writePeersRunnable =
      () -> {
        try {
          writePeersNow();
        } finally {
          scheduleWritePeersNextRun();
        }
      };

  PeerPersistence(Node node, PeerManager peerManager) {
    this.node = node;
    this.peerManager = peerManager;
  }

  /** Schedule the periodic peer persistence job to run immediately. */
  void scheduleInitialWrite() {
    node.getTicker().queueTimedJob(writePeersRunnable, 0);
  }

  /** Flush peer files during shutdown to avoid waiting for the periodic write interval. */
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
   * @param filename The filename to read from. If this doesn't work, we try the .bak file.
   * @param crypto The cryptographic identity which these nodes are connected to.
   * @param opennet The opennet manager for the nodes. Only needed (for constructing the nodes) if
   *     isOpennet.
   * @param isOpennet Whether the file contains opennet peers.
   * @param oldOpennetPeers If true, don't add the nodes to the routing table, pass them to the
   *     opennet manager as "old peers" i.e. inactive nodes which may try to reconnect.
   */
  void tryReadPeers(
      String filename,
      NodeCrypto crypto,
      OpennetManager opennet,
      boolean isOpennet,
      boolean oldOpennetPeers) {
    synchronized (writePeersSync) {
      if (!oldOpennetPeers) {
        if (isOpennet) {
          openFilename = filename;
        } else {
          darkFilename = filename;
        }
      }
    }
    int maxBackups = isOpennet ? BACKUPS_OPENNET : BACKUPS_DARKNET;
    for (int i = 0; i <= maxBackups; i++) {
      File peersFile = getBackupFilename(filename, i);
      // Try to read the node list from disk
      if (peersFile.exists() && readPeers(peersFile, crypto, opennet, oldOpennetPeers)) {
        String msg;
        if (oldOpennetPeers) {
          int oldPeers = opennet == null ? 0 : opennet.countOldOpennetPeers();
          msg = READ_PREFIX + oldPeers + " old-opennet-peers from " + peersFile;
        } else if (isOpennet) {
          msg =
              READ_PREFIX
                  + peerManager.roster().getOpennetPeers().length
                  + " opennet peers from "
                  + peersFile;
        } else {
          msg =
              READ_PREFIX
                  + peerManager.roster().getDarknetPeers().length
                  + " darknet peers from "
                  + peersFile;
        }
        LOG.info(msg);
        return;
      }
    }
    if (!isOpennet) {
      LOG.info("No darknet peers file found.");
    }
    // The other cases are less important.
  }

  /** Marks a peer list write request so the next periodic run persists it. */
  void writePeers(boolean opennet) {
    if (opennet) markWriteOpennet();
    else markWriteDarknet();
  }

  /** Writes peers immediately on a high-priority executor thread. */
  void writePeersUrgent(boolean opennet) {
    if (opennet) writePeersOpennetUrgent();
    else writePeersDarknetUrgent();
  }

  private void scheduleWritePeersNextRun() {
    node.getTicker().queueTimedJob(writePeersRunnable, MIN_WRITEPEERS_DELAY);
  }

  private void writePeersNow() {
    // Non-urgent periodic write does not rotate backups.
    writePeersDarknetNow(false);
    writePeersOpennetNow(false);
  }

  private void writePeersDarknetNow(boolean rotateBackups) {
    if (shouldWritePeersDarknet) {
      shouldWritePeersDarknet = false;
      writePeersInnerDarknet(rotateBackups);
    }
  }

  private void writePeersOpennetNow(boolean rotateBackups) {
    if (shouldWritePeersOpennet) {
      shouldWritePeersOpennet = false;
      writePeersInnerOpennet(rotateBackups);
    }
  }

  private void writePeersOpennetUrgent() {
    node.getExecutor()
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

  private void writePeersDarknetUrgent() {
    node.getExecutor()
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

  private void markWriteDarknet() {
    shouldWritePeersDarknet = true;
  }

  private void markWriteOpennet() {
    shouldWritePeersOpennet = true;
  }

  private String getDarknetPeersString() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = peerManager.myPeers();
    for (PeerNode pn : peers) {
      if (pn instanceof DarknetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }
    return sb.toString();
  }

  private String getOpennetPeersString() {
    StringBuilder sb = new StringBuilder();
    PeerNode[] peers = peerManager.myPeers();
    for (PeerNode pn : peers) {
      if (pn instanceof OpennetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }
    return sb.toString();
  }

  private String getOldOpennetPeersString(OpennetManager om) {
    StringBuilder sb = new StringBuilder();
    for (PeerNode pn : om.getOldPeers()) {
      if (pn instanceof OpennetPeerNode) sb.append(pn.exportDiskFieldSet().toOrderedString());
    }
    return sb.toString();
  }

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

  private void writePeersInnerOpennet(boolean rotateBackups) {
    String newOpennetPeersString = null;
    String newOldOpennetPeersString = null;
    synchronized (writePeersSync) {
      OpennetManager om = node.getOpennet();
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
          && !newOldOpennetPeersString.equals(oldOpennetPeersStringCache)) {
        oldOpennetPeersStringCache = newOldOpennetPeersString;
        writePeersInner(
            oldOpennetPeersFilename, oldOpennetPeersStringCache, BACKUPS_OPENNET, rotateBackups);
      }
    }
  }

  /**
   * Write the peers file to disk.
   *
   * @param rotateBackups If true, rotate backups. If false, just clobber the latest file.
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

        if (rotateBackups) {
          rotateBackupFiles(filename, maxBackups, f);
        } else {
          FileUtil.moveTo(f, getBackupFilename(filename, 0));
        }
      } catch (FileNotFoundException e2) {
        LOG.error("Cannot write peers to disk: cannot create {} (error={})", f, e2, e2);
        safeDeleteIfExists(f);
      } catch (IOException e) {
        LOG.error("I/O error writing peers file: {}", e, e);
        safeDeleteIfExists(f);
        // don't overwrite old file!
      } finally {
        // Try-with-resources handles the stream cleanup
        safeDeleteIfExists(f);
      }
    }
  }

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

  private File getBackupFilename(String filename, int i) {
    if (i == 0) return new File(filename);
    if (i == 1) return new File(filename + ".bak");
    return new File(filename + ".bak." + i);
  }

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
        node.getClientCore().getAlerts().register(droppedOldPeers);
        LOG.error(droppedOldPeers.getText());
      } catch (Throwable t) {
        // Startup MUST complete, don't let client layer problems kill it.
        LOG.error("Caught error telling user about dropped peers", t);
      }
    }
    return !someBroken;
  }

  private List<PeerNode> createPeerNodesFromEntries(
      List<SimpleFieldSet> peerEntries,
      NodeCrypto crypto,
      OpennetManager opennet,
      DroppedOldPeersUserAlert droppedOldPeers) {
    List<PeerNode> created = new ArrayList<>();
    for (SimpleFieldSet fs : peerEntries) {
      try {
        created.add(PeerNode.create(fs, node, crypto, opennet, peerManager));
      } catch (FSParseException
          | PeerParseException
          | ReferenceSignatureVerificationException
          | RuntimeException e2) {
        handlePeerCreationException(e2, fs);
      } catch (PeerTooOldException e) {
        if (crypto.isOpennet()) {
          LOG.error("Dropping too-old opennet peer");
        } else {
          droppedOldPeers.add(e, fs.get("myName"));
        }
      }
    }
    // Always return successfully parsed peers; callers decide whether some entries were broken.
    return created;
  }

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

  private void handlePeerCreationException(Exception e2, SimpleFieldSet fs) {
    LOG.error("Peer parse error {} for {}", e2, fs, e2);
    LOG.warn("Cannot parse friend from peers file: {}", e2, e2);
  }

  private void readPeerFieldSets(BufferedReader br, List<SimpleFieldSet> out) throws IOException {
    for (SimpleFieldSet sfs = readNextPeerFieldSet(br);
        sfs != null;
        sfs = readNextPeerFieldSet(br)) {
      out.add(sfs);
    }
  }

  private SimpleFieldSet readNextPeerFieldSet(BufferedReader br) throws IOException {
    try {
      return new SimpleFieldSet(br, false, true);
    } catch (EOFException _) {
      return null; // end-of-file reached
    }
  }

  private static void safeDeleteIfExists(File file) {
    try {
      java.nio.file.Files.deleteIfExists(file.toPath());
    } catch (IOException _) {
      // best-effort
    }
  }
}
