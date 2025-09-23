package network.crypta.client.async;

import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestSender;
import network.crypta.support.Logger;

/**
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class ChosenBlockImpl extends ChosenBlock {

  private static volatile boolean logMINOR;
  private static volatile boolean logDEBUG;

  static {
    Logger.registerClass(ChosenBlockImpl.class);
  }

  public final SendableRequest request;
  public final RequestScheduler sched;
  public final boolean persistent;

  public ChosenBlockImpl(
      SendableRequest req,
      SendableRequestItem token,
      Key key,
      ClientKey ckey,
      boolean localRequestOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean realTimeFlag,
      RequestScheduler sched,
      boolean persistent) {
    super(
        token,
        key,
        ckey,
        localRequestOnly,
        ignoreStore,
        canWriteClientCache,
        forkOnCacheable,
        realTimeFlag,
        sched);
    this.request = req;
    this.sched = sched;
    this.persistent = persistent;
    if (logDEBUG)
      Logger.minor(
          this,
          "Created "
              + this
              + " for "
              + (persistent ? "persistent" : "transient")
              + " block "
              + token
              + " for key "
              + key,
          new Exception("debug"));
  }

  @Override
  public boolean isCancelled() {
    return request.isCancelled();
  }

  @Override
  public boolean isPersistent() {
    return persistent;
  }

  @Override
  public void onFailure(final LowLevelPutException e, ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                ((SendableInsert) request).onFailure(e, token, context1);
              } finally {
                sched.removeRunningInsert((SendableInsert) (request), token.getKey());
                // Something might be waiting for a request to complete (e.g. if we have two
                // requests for the same key),
                // so wake the starter thread.
              }
              sched.wakeStarter();
              return false;
            });
  }

  @Override
  public void onInsertSuccess(final ClientKey key, ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                ((SendableInsert) request).onSuccess(token, key, context1);
              } finally {
                sched.removeRunningInsert((SendableInsert) (request), token.getKey());
              }
              // Something might be waiting for a request to complete (e.g. if we have two
              // requests for the same key),
              // so wake the starter thread.
              sched.wakeStarter();
              return false;
            });
  }

  @Override
  public void onFailure(final LowLevelGetException e, ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                ((SendableGet) request).onFailure(e, token, context1);
              } finally {
                sched.removeFetchingKey(key);
              }
              // Something might be waiting for a request to complete (e.g. if we have two
              // requests for the same key),
              // so wake the starter thread.
              sched.wakeStarter();
              return false;
            });
  }

  @Override
  public void onFetchSuccess(ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                sched.succeeded((SendableGet) request, false);
              } finally {
                sched.removeFetchingKey(key);
              }
              // Something might be waiting for a request to complete (e.g. if we have two
              // requests for the same key),
              // so wake the starter thread.
              sched.wakeStarter();
              return false;
            });
  }

  @Override
  public short getPriority() {
    return request.getPriorityClass();
  }

  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return request.getSender(context);
  }
}
