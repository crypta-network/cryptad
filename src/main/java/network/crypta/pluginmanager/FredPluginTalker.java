package network.crypta.pluginmanager;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;

/**
 * Interface that has to be implemented for plugins that wants talk to other plugins that implements
 * FredPluginFCP
 *
 * @author saces
 * @deprecated Use {@link FredPluginFCPMessageHandler.ClientSideFCPMessageHandler} instead.
 */
@Deprecated
public interface FredPluginTalker {

  /**
   * @param pluginname - reply from
   * @param indentifier - identifer from your call
   * @param params parameters passed back
   * @param data a bucket of data passed back, can be null
   */
  void onReply(String pluginname, String indentifier, SimpleFieldSet params, Bucket data);
}
