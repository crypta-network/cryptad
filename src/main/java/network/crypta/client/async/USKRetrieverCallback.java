package network.crypta.client.async;

import network.crypta.client.FetchResult;
import network.crypta.keys.USK;
import network.crypta.node.RequestStarter;

/** Interface implemented by USKRetriever clients. */
public interface USKRetrieverCallback {

  /**
   * Called when a new edition is found and downloaded.
   *
   * @param edition The USK edition number.
   * @param data The retrieved data.
   */
  void onFound(USK origUSK, long edition, FetchResult data);

  /**
   * Priority at which the polling should run normally. You have to return one of the constants from
   * {@link RequestStarter}.
   */
  short getPollingPriorityNormal();

  /**
   * Priority at which the polling should run when starting, or immediately after making some
   * progress. You have to return one of the constants from {@link RequestStarter}.
   */
  short getPollingPriorityProgress();
}
