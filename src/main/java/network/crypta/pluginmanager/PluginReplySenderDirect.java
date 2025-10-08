package network.crypta.pluginmanager;

import network.crypta.clients.fcp.FCPPluginConnection;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author saces
 * @author xor (xor@freenetproject.org)
 * @deprecated Use the {@link FCPPluginConnection} API instead.
 */
@Deprecated
public class PluginReplySenderDirect extends PluginReplySender {
  private static final Logger LOG = LoggerFactory.getLogger(PluginReplySenderDirect.class);

  private final Node node;
  private final FredPluginTalker target;

  /**
   * @see PluginReplySender#PluginReplySender(String, String, String)
   */
  public PluginReplySenderDirect(
      Node node2,
      FredPluginTalker target2,
      String pluginname2,
      String clientIdentifier,
      String clientSideIdentifier) {
    super(pluginname2, clientIdentifier, clientSideIdentifier);
    node = node2;
    target = target2;
  }

  @Override
  public void send(final SimpleFieldSet params, final Bucket bucket) {

    node.getExecutor()
        .execute(
            new Runnable() {

              @Override
              public void run() {

                try {
                  target.onReply(pluginname, clientSideIdentifier, params, bucket);
                } catch (Throwable t) {
                  LOG.error("Cought error while handling plugin reply: " + t.getMessage(), t);
                }
              }
            },
            "FCPPlugin reply runner for " + pluginname);
  }
}
