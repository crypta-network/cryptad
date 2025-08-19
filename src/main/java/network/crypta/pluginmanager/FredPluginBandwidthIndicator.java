package network.crypta.pluginmanager;

public interface FredPluginBandwidthIndicator {

  /**
   * @return the reported upstream bit rate in bits per second. -1 if it's not available. Blocking.
   */
  int getUpstramMaxBitRate();

  /**
   * @return the reported downstream bit rate in bits per second. -1 if it's not available.
   *     Blocking.
   */
  int getDownstreamMaxBitRate();
}
