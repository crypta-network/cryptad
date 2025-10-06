package network.crypta.client.async;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleHealingQueue extends BaseClientPutter
    implements HealingQueue, PutCompletionCallback {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleHealingQueue.class);
  @Serial private static final long serialVersionUID = -2884613086588264043L;

  final int maxRunning;
  int counter;
  InsertContext ctx;
  private final HealingDecisionSupplier healingDecisionSupplier;
  final Map<Bucket, SingleBlockInserter> runningInserters;

  static {
  }

  static final RequestClient REQUEST_CLIENT = new RequestClientBuilder().build();

  public SimpleHealingQueue(
      InsertContext context,
      short prio,
      int maxRunning,
      HealingDecisionSupplier healingDecisionSupplier) {
    super(prio, REQUEST_CLIENT);
    this.ctx = context;
    this.healingDecisionSupplier = healingDecisionSupplier;
    this.runningInserters = new HashMap<>();
    this.maxRunning = maxRunning;
  }

  public boolean innerQueue(
      Bucket data, byte[] cryptoKey, byte cryptoAlgorithm, ClientContext context) {
    SingleBlockInserter sbi;
    int ctr;
    synchronized (this) {
      ctr = counter++;
      if (runningInserters.size() > maxRunning) return false;
      try {
        sbi =
            new SingleBlockInserter(
                this,
                data,
                (short) -1,
                FreenetURI.EMPTY_CHK_URI,
                ctx,
                realTimeFlag,
                this,
                false,
                CHKBlock.DATA_LENGTH,
                ctr,
                false,
                false,
                data,
                context,
                false,
                true,
                0,
                cryptoAlgorithm,
                cryptoKey);
      } catch (Throwable e) {
        LOG.error("Caught trying to insert healing block: " + e, e);
        return false;
      }
      if (isHealingThisBlockSimilarToForwarding(context, sbi)) {
        runningInserters.put(data, sbi);
      }
    }
    try {
      sbi.schedule(context);
      if (LOG.isDebugEnabled()) LOG.debug("Started healing insert " + ctr + " for " + data);
      return true;
    } catch (Throwable e) {
      LOG.error("Caught trying to insert healing block: " + e, e);
      return false;
    }
  }

  private boolean isHealingThisBlockSimilarToForwarding(
      ClientContext context, SingleBlockInserter sbi) {
    // ensure that we have a routing key
    sbi.tryEncode(context);
    double keyLocation = sbi.getKeyNoEncode().getNodeKey().toNormalizedDouble();
    return healingDecisionSupplier.shouldHeal(keyLocation);
  }

  @Override
  public void queue(Bucket data, byte[] cryptoKey, byte cryptoAlgorithm, ClientContext context) {
    if (!innerQueue(data, cryptoKey, cryptoAlgorithm, context)) data.free();
  }

  @Override
  public FreenetURI getURI() {
    return FreenetURI.EMPTY_CHK_URI;
  }

  @Override
  public boolean isFinished() {
    return false;
  }

  @Override
  protected void innerNotifyClients(ClientContext context) {
    // Do nothing
  }

  @Override
  public void onSuccess(ClientPutState state, ClientContext context) {
    SingleBlockInserter sbi = (SingleBlockInserter) state;
    Bucket data = (Bucket) sbi.getToken();
    synchronized (this) {
      runningInserters.remove(data);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Successfully inserted healing block: "
              + sbi.getURINoEncode()
              + " for "
              + data
              + " ("
              + sbi.token
              + ')');
    data.free();
  }

  @Override
  public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
    SingleBlockInserter sbi = (SingleBlockInserter) state;
    Bucket data = (Bucket) sbi.getToken();
    synchronized (this) {
      runningInserters.remove(data);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Failed to insert healing block: "
              + sbi.getURINoEncode()
              + " : "
              + e
              + " for "
              + data
              + " ("
              + sbi.token
              + ')',
          e);
    data.free();
  }

  @Override
  public void onEncode(BaseClientKey usk, ClientPutState state, ClientContext context) {
    // Ignore
  }

  @Override
  public void onTransition(
      ClientPutState oldState, ClientPutState newState, ClientContext context) {
    // Should never happen
    LOG.error(
        "impossible: onTransition on SimpleHealingQueue from " + oldState + " to " + newState,
        new Exception("debug"));
  }

  @Override
  public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
    // Should never happen
    LOG.error(
        "Got metadata on SimpleHealingQueue from " + state + ": " + m, new Exception("debug"));
  }

  @Override
  public void onBlockSetFinished(ClientPutState state, ClientContext context) {
    // Ignore
  }

  @Override
  public void onFetchable(ClientPutState state) {
    // Ignore
  }

  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {
    // Ignore
  }

  @Override
  protected void innerToNetwork(ClientContext context) {
    // Ignore
  }

  @Override
  public void cancel(ClientContext context) {
    super.cancel();
  }

  @Override
  public int getMinSuccessFetchBlocks() {
    return 0;
  }

  @Override
  public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
    LOG.error("onMetadata() in SimpleHealingQueue - impossible", new Exception("error"));
    meta.free();
  }

  @Override
  public void innerOnResume(ClientContext context) {
    // Do nothing. Not persisted.
  }

  @Override
  protected ClientBaseCallback getCallback() {
    return null;
  }
}
