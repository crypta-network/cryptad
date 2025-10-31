package network.crypta.node;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SendableGetRequestSender implements SendableRequestSender {
  private static final Logger LOG = LoggerFactory.getLogger(SendableGetRequestSender.class);

  @Override
  public boolean sendIsBlocking() {
    return false;
  }

  /**
   * Do the request, blocking. Called by RequestStarter. Also responsible for deleting it.
   *
   * @return True if a request was executed. False if caller should try to find another request, and
   *     remove this one from the queue.
   */
  @Override
  public boolean send(
      NodeClientCore core,
      final RequestScheduler sched,
      final ClientContext context,
      final ChosenBlock req) {
    Object keyNum = req.token;
    final ClientKey key = req.ckey;
    if (key == null) {
      LOG.error("Key is null in send(): keyNum = " + keyNum + " for " + req);
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Sending get for key " + keyNum + " : " + key);
    if (req.isCancelled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Cancelled: " + req);
      req.onFailure(new LowLevelGetException(LowLevelGetException.CANCELLED), context);
      return false;
    }
    try {
      final Key k = key.getNodeKey();
      core.asyncGet(
          k,
          false,
          new RequestCompletionListener() {

            @Override
            public void onSucceeded() {
              req.onFetchSuccess(context);
            }

            @Override
            public void onFailed(LowLevelGetException e) {
              req.onFailure(e, context);
            }
          },
          !req.ignoreStore,
          req.canWriteClientCache,
          req.realTimeFlag,
          req.localRequestOnly,
          req.ignoreStore);
    } catch (Throwable t) {
      LOG.error("Caught " + t, t);
      req.onFailure(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR), context);
      return true;
    }
    return true;
  }
}
