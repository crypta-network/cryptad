/** */
package network.crypta.node;

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
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

public class NodeARKInserter implements ClientPutCallback, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(NodeARKInserter.class);

  /** */
  private final Node node;

  private final NodeCrypto crypto;
  private final String darknetOpennetString;
  private final NodeIPPortDetector detector;
  private final boolean enabled;

  /**
   * @param node
   * @param old If true, use the old ARK rather than the new ARK
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

  public void update() {
    // Called by detector code, which is critical and convoluted.
    // Run off-thread, break locks, avoid stalling caller.
    node.getExecutor().execute(() -> innerUpdate());
  }

  private void innerUpdate() {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (LOG.isDebugEnabled()) LOG.debug("update()");
    if (!checkIPUpdated()) return;
    // We'll broadcast the new physical.udp entry to our connected peers via a differential node
    // reference
    // We'll err on the side of caution and not update our peer to an empty physical.udp entry using
    // a differential node reference
    SimpleFieldSet nfs = crypto.exportPublicFieldSet(false, false, true);
    String[] entries = nfs.getAll("physical.udp");
    if (entries != null) {
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.putOverwrite("physical.udp", entries);
      if (LOG.isDebugEnabled())
        LOG.debug(darknetOpennetString + " ref's physical.udp is '" + fs + "'");
      node.getPeers().locallyBroadcastDiffNodeRef(fs, !crypto.isOpennet(), crypto.isOpennet());
    } else {
      if (LOG.isDebugEnabled()) LOG.debug(darknetOpennetString + " ref's physical.udp is null");
    }
    // Proceed with inserting the ARK
    if (LOG.isDebugEnabled())
      LOG.debug("Inserting " + darknetOpennetString + " ARK because peers list changed");

    if (inserter != null) {
      // Already inserting.
      // Re-insert after finished.
      synchronized (this) {
        shouldInsert = true;
      }

      return;
    }
    // Otherwise need to start an insert
    if (node.noConnectedPeers()) {
      // Can't start an insert yet
      synchronized (this) {
        shouldInsert = true;
      }
      return;
    }

    startInserter();
  }

  private boolean checkIPUpdated() {
    Peer[] p = detector.detectPrimaryPeers();
    if (p == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not inserting " + darknetOpennetString + " ARK because no IP address");
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
      if (LOG.isDebugEnabled()) LOG.debug(darknetOpennetString + " ARK inserter can't start yet");
      return;
    }

    if (LOG.isDebugEnabled()) LOG.debug("starting " + darknetOpennetString + " ARK inserter");

    SimpleFieldSet fs = crypto.exportPublicFieldSet(false, false, true);

    // Remove some unnecessary fields that only cause collisions.

    // Delete entire ark.* field for now. Changing this and automatically moving to the new may be
    // supported in future.
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
      LOG.debug("Inserting " + darknetOpennetString + " ARK: " + uri + "  contents:\n" + s);

    InsertContext ctx =
        node.getClientCore().makeClient((short) 0, true, false).getInsertContext(true);
    inserter =
        new ClientPutter(
            this,
            b,
            uri,
            null, // Modern ARKs easily fit inside 1KB so should be pure SSKs => no MIME type; this
            // improves fetchability considerably
            ctx,
            RequestStarter.INTERACTIVE_PRIORITY_CLASS,
            false,
            null,
            false,
            node.getClientCore().getClientContext(),
            null,
            -1);

    try {

      node.getClientCore().getClientContext().start(inserter);

      synchronized (this) {
        if (fs.get("physical.udp") == null) lastInsertedPeers = null;
        else {
          try {
            String[] all = fs.getAll("physical.udp");
            Peer[] peers = new Peer[all.length];
            for (int i = 0; i < all.length; i++) peers[i] = new Peer(all[i], false);
            lastInsertedPeers = peers;
          } catch (PeerParseException e1) {
            LOG.error(
                "Error parsing own "
                    + darknetOpennetString
                    + " ref: "
                    + e1
                    + " : "
                    + fs.get("physical.udp"),
                e1);
          } catch (UnknownHostException e1) {
            LOG.error(
                "Error parsing own "
                    + darknetOpennetString
                    + " ref: "
                    + e1
                    + " : "
                    + fs.get("physical.udp"),
                e1);
          }
        }
      }
    } catch (InsertException e) {
      onFailure(e, inserter);
    } catch (PersistenceDisabledException e) {
      // Impossible
    }
  }

  @Override
  public void onSuccess(BaseClientPutter state) {
    FreenetURI uri = state.getURI();
    if (LOG.isDebugEnabled()) LOG.debug(darknetOpennetString + " ARK insert succeeded: " + uri);
    synchronized (this) {
      inserter = null;
      if (!shouldInsert) return;
      shouldInsert = false;
    }
    startInserter();
  }

  @Override
  public void onFailure(InsertException e, BaseClientPutter state) {
    if (LOG.isDebugEnabled()) LOG.debug(darknetOpennetString + " ARK insert failed: " + e);
    synchronized (this) {
      lastInsertedPeers = null;
    }
    // :(
    // Better try again
    try {
      Thread.sleep(5000);
    } catch (InterruptedException e1) {
      // Ignore
    }

    startInserter();
  }

  @Override
  public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
    if (LOG.isDebugEnabled())
      LOG.debug("Generated URI for " + darknetOpennetString + " ARK: " + uri);
    long l = uri.getSuggestedEdition();
    if (l < crypto.getMyARKNumber()) {
      LOG.error(
          "Inserted "
              + darknetOpennetString
              + " ARK edition # lower than attempted: "
              + l
              + " expected "
              + crypto.getMyARKNumber());
    } else if (l > crypto.getMyARKNumber()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            darknetOpennetString
                + " ARK number moving from "
                + crypto.getMyARKNumber()
                + " to "
                + l);
      crypto.setMyARKNumber(l);
      if (crypto.isOpennet()) node.writeOpennetFile();
      else node.writeNodeFile();
      // We'll broadcast the new ARK edition to our connected peers via a differential node
      // reference
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.put("ark.number", crypto.getMyARKNumber());
      node.getPeers().locallyBroadcastDiffNodeRef(fs, !crypto.isOpennet(), crypto.isOpennet());
    }
  }

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

  @Override
  public void onFetchable(BaseClientPutter state) {
    // Ignore, we don't care
  }

  @Override
  public boolean persistent() {
    return false;
  }

  @Override
  public boolean realTimeFlag() {
    return false;
  }

  @Override
  public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
    LOG.error("Bogus onGeneratedMetadata() on " + this + " from " + state, new Exception("error"));
    metadata.free();
  }

  @Override
  public void onResume(ClientContext context) {
    // Not persistent.
  }

  @Override
  public RequestClient getRequestClient() {
    return this;
  }
}
