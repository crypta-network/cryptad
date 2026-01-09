/*
 * ARK insertion helper for the node package.
 * See class-level Javadoc on NodeARKInserter for API and behavior details.
 */
package network.crypta.node;

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains the node's ARK (address record key) insertions.
 *
 * <p>This component exports the public node reference, broadcasts relevant diffs to connected
 * peers, and inserts/updates the ARK under the node's key when the detected public address or
 * peer-derived endpoints change. Insert operations run asynchronously on the node executor to avoid
 * blocking detection and networking threads.
 *
 * <p>Threading: methods may be called from various threads; long-running work is dispatched to the
 * node's executor. Callbacks from the client inserter may also arrive at worker threads.
 */
public class NodeARKInserter implements ClientPutCallback, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(NodeARKInserter.class);
  private static final String PHYSICAL_UDP = "physical.udp";

  /** Owning node used for scheduling and peer interactions. */
  private final Node node;

  private final NodeCrypto crypto;
  private final String darknetOpennetString;
  private final NodeIPPortDetector detector;
  private final boolean enabled;

  /**
   * Creates a new inserter for the given node.
   *
   * @param node the owning {@link Node}, used for scheduling and peer broadcasts
   * @param crypto node cryptography and identity utilities feeding ARK data
   * @param detector source of currently detected external peers/addresses
   * @param enableARKs when {@code true}, enables ARK insertion; when {@code false}, the inserter is
   *     inert
   */
  NodeARKInserter(Node node, NodeCrypto crypto, NodeIPPortDetector detector, boolean enableARKs) {
    this.node = node;
    this.crypto = crypto;
    this.detector = detector;
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (crypto.isOpennet()) darknetOpennetString = "Opennet";
    else darknetOpennetString = "Darknet";
    this.enabled = enableARKs;
  }

  private ClientPutter inserter;
  private boolean shouldInsert;
  private Peer[] lastInsertedPeers;
  private boolean canStart;

  void start() {
    if (!enabled) return;
    canStart = true;
    innerUpdate();
  }

  /**
   * Schedules a non-blocking ARK update check.
   *
   * <p>Runs {@link #innerUpdate()} on the node executor to avoid holding caller locks. No network
   * I/O happens on the caller thread.
   */
  public void update() {
    // Called by detector code. Dispatch off-thread to avoid stalling the caller and to reduce lock
    // contention.
    node.network().executor().execute(this::innerUpdate);
  }

  private void innerUpdate() {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (LOG.isDebugEnabled()) LOG.debug("NodeARKInserter.update()");
    if (!checkIPUpdated()) return;
    // Broadcast the current physical.udp entries to connected peers via a differential node
    // reference. Do not send an empty physical.udp set via a diff.
    SimpleFieldSet nfs = crypto.exportPublicFieldSet(false, false, true);
    String[] entries = nfs.getAll(PHYSICAL_UDP);
    if (entries != null) {
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.putOverwrite(PHYSICAL_UDP, entries);
      if (LOG.isDebugEnabled()) LOG.debug("{} ref physical.udp={}", darknetOpennetString, fs);
      node.network()
          .peers()
          .messenger()
          .locallyBroadcastDiffNodeRef(fs, !crypto.isOpennet(), crypto.isOpennet());
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("No physical.udp in {} ref", darknetOpennetString);
    }
    // Proceed with inserting the ARK
    if (LOG.isDebugEnabled())
      LOG.debug("Inserting {} ARK because peers list changed", darknetOpennetString);

    if (inserter != null) {
      // Already inserting; schedule a re-insert after the current one completes.
      synchronized (this) {
        shouldInsert = true;
      }

      return;
    }
    // Otherwise need to start an insert
    if (node.noConnectedPeers()) {
      // Cannot start until at least one peer is connected.
      synchronized (this) {
        shouldInsert = true;
      }
      return;
    }

    startInserter();
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean checkIPUpdated() {
    Peer[] p = detector.detectPrimaryPeers();
    if (p == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not inserting {} ARK because no IP address", darknetOpennetString);
      return false; // no point inserting
    }
    synchronized (this) {
      if (lastInsertedPeers != null) {
        if (p.length != lastInsertedPeers.length) return true;
        for (int i = 0; i < p.length; i++)
          if (!p[i].strictEquals(lastInsertedPeers[i])) return true;
      } else {
        // we've not inserted an ARK that we know about (ie since startup)
        return true;
      }
    }
    return false;
  }

  private void startInserter() {
    if (!canStart) {
      if (LOG.isDebugEnabled())
        LOG.debug("{} ARK inserter not ready to start", darknetOpennetString);
      return;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Start {} ARK inserter", darknetOpennetString);

    SimpleFieldSet fs = crypto.exportPublicFieldSet(false, false, true);

    // Remove fields that increase collision risk when generating ARKs.

    // Drop entire ark.* subset. Automatic migration between formats may be added later.
    fs.removeSubset("ark");
    fs.removeValue("location");
    fs.removeValue("sig");
    // fs.remove("version"); - keep version because of its significance in reconnection

    String s = fs.toString();

    byte[] buf = s.getBytes(StandardCharsets.UTF_8);

    RandomAccessBucket b = new SimpleReadOnlyArrayBucket(buf);

    long number = crypto.getMyARKNumber();
    InsertableClientSSK ark = crypto.getMyARK();
    FreenetURI uri = ark.getInsertURI().setKeyType("USK").setSuggestedEdition(number);

    if (LOG.isDebugEnabled())
      LOG.debug("Insert {} ARK uri={} contents={}", darknetOpennetString, uri, s);

    InsertContext ctx =
        node.services().clientCore().makeClient((short) 0, true, false).getInsertContext(true);
    inserter =
        new ClientPutter(
            new ClientPutterRequest(
                this,
                b,
                uri,
                null, // Modern ARKs fit in ~1 KiB so use pure SSKs (no MIME type) to improve
                // fetchability
                ctx,
                RequestStarter.INTERACTIVE_PRIORITY_CLASS,
                false),
            ClientPutterOptions.defaults());

    try {

      node.services().clientCore().getClientContext().start(inserter);

      synchronized (this) {
        if (fs.get(PHYSICAL_UDP) == null) {
          lastInsertedPeers = null;
        } else {
          Peer[] parsed = parsePeers(fs);
          // Keep prior value on parse failure to avoid repeated reinserts
          if (parsed != null) {
            lastInsertedPeers = parsed;
          }
        }
      }
    } catch (InsertException e) {
      onFailure(e, inserter);
    } catch (PersistenceDisabledException _) {
      // Inserter is non-persistent by design; this path should not occur.
    }
  }

  @SuppressWarnings("java:S1168")
  private Peer[] parsePeers(SimpleFieldSet fs) {
    try {
      String[] all = fs.getAll(PHYSICAL_UDP);
      Peer[] peers = new Peer[all.length];
      for (int i = 0; i < all.length; i++) peers[i] = new Peer(all[i], false);
      return peers;
    } catch (PeerParseException | UnknownHostException e1) {
      LOG.error(
          "Parse own {} ref failed (peerSpec={}): {}",
          darknetOpennetString,
          e1,
          fs.get(PHYSICAL_UDP),
          e1);
      // Signal failure so caller can preserve previous lastInsertedPeers
      return null;
    }
  }

  /**
   * Called when an ARK insert completes successfully.
   *
   * <p>Clears the current inserter and, if another insert was requested while the operation was in
   * progress, immediately starts the next insert.
   *
   * @param state the completed client putter; {@link BaseClientPutter#getURI()} is non-null
   */
  @Override
  public void onSuccess(BaseClientPutter state) {
    FreenetURI uri = state.getURI();
    if (LOG.isDebugEnabled()) LOG.debug("{} ARK insert succeeded: {}", darknetOpennetString, uri);
    synchronized (this) {
      inserter = null;
      if (!shouldInsert) return;
      shouldInsert = false;
    }
    startInserter();
  }

  /**
   * Called when an ARK insert fails.
   *
   * <p>Resets the last inserted peer snapshot, waits 5 seconds, and schedules a retry. The sleep
   * occurs on the callback thread.
   *
   * @param e the insert exception
   * @param state the client putter that failed
   */
  @Override
  public void onFailure(InsertException e, BaseClientPutter state) {
    if (LOG.isDebugEnabled()) LOG.debug("ARK insert error for {}: {}", darknetOpennetString, e, e);
    synchronized (this) {
      lastInsertedPeers = null;
    }
    // Back off briefly, then try again.
    try {
      Thread.sleep(5000);
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }

    startInserter();
  }

  /**
   * Called when the insert URI is generated.
   *
   * <p>Validates and persists the ARK edition number. If it increases, updates node files and
   * broadcasts a diff with the new {@code ark.number} to connected peers.
   *
   * @param uri the generated insert URI (USK-suggested edition)
   * @param state the client putter associated with the generation
   */
  @Override
  public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
    if (LOG.isDebugEnabled()) LOG.debug("Generated URI for {} ARK: {}", darknetOpennetString, uri);
    long l = uri.getSuggestedEdition();
    if (l < crypto.getMyARKNumber()) {
      LOG.error(
          "Inserted {} ARK edition lower than expected: {} expected {}",
          darknetOpennetString,
          l,
          crypto.getMyARKNumber());
    } else if (l > crypto.getMyARKNumber()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "{} ARK number moving from {} to {}", darknetOpennetString, crypto.getMyARKNumber(), l);
      crypto.setMyARKNumber(l);
      if (crypto.isOpennet()) node.writeOpennetFile();
      else node.writeNodeFile();
      // Broadcast the new ARK edition to connected peers via a differential node reference.
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.put("ark.number", crypto.getMyARKNumber());
      node.network()
          .peers()
          .messenger()
          .locallyBroadcastDiffNodeRef(fs, !crypto.isOpennet(), crypto.isOpennet());
    }
  }

  /**
   * Notifies the inserter that a peer connected.
   *
   * <p>If an insert is pending and not already in progress, triggers a start after rechecking the
   * detected IP endpoints.
   */
  public void onConnectedPeer() {
    if (!checkIPUpdated()) return;
    synchronized (this) {
      if (!shouldInsert) return;
    }
    // Already inserting.
    if (inserter != null) return;

    synchronized (this) {
      shouldInsert = false;
    }

    startInserter();
  }

  /**
   * Unused callback for this workflow.
   *
   * @param state the client putter; ignored
   */
  @Override
  public void onFetchable(BaseClientPutter state) {
    // Not required for ARK inserts.
  }

  /**
   * Indicates whether requests from this client are persisted across restarts.
   *
   * @return {@code false}; ARK inserts are non-persistent
   */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * Indicates whether requests from this client are treated as real-time.
   *
   * @return {@code false}; regular scheduling applies
   */
  @Override
  public boolean realTimeFlag() {
    return false;
  }

  /**
   * Receives generated metadata for the put operation.
   *
   * <p>Metadata is not expected for ARK inserts; frees the bucket and logs a warning.
   *
   * @param metadata unexpected metadata bucket; freed by this method
   * @param state the client putter that produced metadata
   */
  @Override
  public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
    LOG.warn("Unexpected onGeneratedMetadata() on {} from {}", this, state);
    metadata.free();
  }

  /**
   * Called when a persistent client resumes.
   *
   * <p>No action because this client is non-persistent.
   *
   * @param context the client context
   */
  @Override
  public void onResume(ClientContext context) {
    // Non-persistent client; nothing to resume.
  }

  /**
   * Returns the {@link RequestClient} identity used for requests.
   *
   * @return {@code this}
   */
  @Override
  public RequestClient getRequestClient() {
    return this;
  }
}
