package network.crypta.pluginmanager;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;

/**
 * Interface that has to be implemented for plugins that want to be talkable via fcp or direct
 * (plugin to plugin)
 *
 * <p>see plugins.FCPHello for a simple sample.
 *
 * @author saces
 * @deprecated Use {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} instead
 */
@Deprecated
public interface FredPluginFCP {

  int ACCESS_DIRECT = 0;
  int ACCESS_FCP_RESTRICTED = 1;
  int ACCESS_FCP_FULL = 2;

  /**
   * @param replysender interface to send a reply
   * @param params parameters passed in, can be null
   * @param data a bucket of data passed in, can be null
   * @param access 0: direct call (plugin to plugin), 1: FCP restricted access, 2: FCP full access
   * @throws PluginNotFoundException If the plugin has already been removed.
   */
  void handle(PluginReplySender replysender, SimpleFieldSet params, Bucket data, int accesstype);
}
