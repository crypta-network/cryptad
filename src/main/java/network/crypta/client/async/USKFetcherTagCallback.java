package network.crypta.client.async;

public interface USKFetcherTagCallback extends USKFetcherCallback {

  void setTag(USKFetcherTag tag, ClientContext context);
}
