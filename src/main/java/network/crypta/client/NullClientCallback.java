package network.crypta.client;

import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** */
public class NullClientCallback implements ClientGetCallback, ClientPutCallback {
  private static final Logger LOG = LoggerFactory.getLogger(NullClientCallback.class);

  static {
  }

  private final RequestClient cb;

  public NullClientCallback(RequestClient cb) {
    this.cb = cb;
  }

  @Override
  public void onFailure(FetchException e, ClientGetter state) {
    if (LOG.isDebugEnabled())
      LOG.debug("NullClientCallback#onFailure e=" + e + ", state=" + state, e);
  }

  @Override
  public void onFailure(InsertException e, BaseClientPutter state) {
    if (LOG.isDebugEnabled())
      LOG.debug("NullClientCallback#onFailure e=" + e + ", state=" + state, e);
  }

  @Override
  public void onFetchable(BaseClientPutter state) {
    if (LOG.isDebugEnabled()) LOG.debug("NullClientCallback#onFetchable state=" + state);
  }

  @Override
  public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
    if (LOG.isDebugEnabled())
      LOG.debug("NullClientCallback#onGeneratedURI uri=" + uri + ", state=" + state);
  }

  @Override
  public void onSuccess(FetchResult result, ClientGetter state) {
    if (LOG.isDebugEnabled())
      LOG.debug("NullClientCallback#onSuccess result=" + result + ", state=" + state);
    result.data.free();
  }

  @Override
  public void onSuccess(BaseClientPutter state) {
    if (LOG.isDebugEnabled()) LOG.debug("NullClientCallback#onSuccess state=" + state);
  }

  @Override
  public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
    if (LOG.isDebugEnabled()) LOG.debug("NullClientCallback#onGeneratedMetadata state=" + state);
    metadata.free();
  }

  @Override
  public void onResume(ClientContext context) {
    // Do nothing.
  }

  @Override
  public RequestClient getRequestClient() {
    return cb;
  }
}
