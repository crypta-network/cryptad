package network.crypta.pluginmanager;

import java.lang.ref.WeakReference;
import java.util.UUID;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FCPPluginConnection;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author saces, xor
 * @deprecated Use {@link FCPPluginConnection} instead.
 */
@Deprecated
public class PluginTalker {
  private static final Logger LOG = LoggerFactory.getLogger(PluginTalker.class);

  protected Node node;
  protected PluginReplySender replysender;

  protected int access;

  protected WeakReference<FredPluginFCP> pluginRef;
  protected String pluginName;

  public PluginTalker(
      FredPluginTalker fpt, Node node2, String pluginname2, String clientSideIdentifier)
      throws PluginNotFoundException {
    node = node2;
    pluginName = pluginname2;
    pluginRef = findPlugin(pluginname2);
    access = FredPluginFCP.ACCESS_DIRECT;

    // Normally, the clientIdentifier passed to the PluginReplySenderDirect() shall be an identifier
    // of the particular network connection to the client.
    // But this PluginTalker constructor typically gets called by PluginRespirator.getPluginTalker()
    // which is called directly by client plugins.
    // So there is no real FCP network connection, the client plugin runs in the same node as the
    // server plugin.
    // As we have no network connection to pull an ID from, we assume a new client for each call of
    // this constructor by computing a random clientIdentifier.
    final String clientIdentifier = UUID.randomUUID().toString();

    replysender =
        new PluginReplySenderDirect(
            node2, fpt, pluginname2, clientIdentifier, clientSideIdentifier);
  }

  public PluginTalker(
      Node node2,
      FCPConnectionHandler handler,
      String pluginname2,
      String clientSideIdentifier,
      boolean access2)
      throws PluginNotFoundException {
    node = node2;
    pluginName = pluginname2;
    pluginRef = findPlugin(pluginname2);
    access = access2 ? FredPluginFCP.ACCESS_FCP_FULL : FredPluginFCP.ACCESS_FCP_RESTRICTED;

    // The connection identifier UUID is unique for each network connection of a client, which is
    // exactly what the PluginReplySenderFCP() wants.
    final String clientIdentifier = handler.getConnectionIdentifierUUID().toString();

    replysender =
        new PluginReplySenderFCP(handler, pluginname2, clientIdentifier, clientSideIdentifier);
  }

  protected WeakReference<FredPluginFCP> findPlugin(String pluginname2)
      throws PluginNotFoundException {
    LOG.info("Searching fcp plugin: {}", pluginname2);
    FredPluginFCP plug = null;
    for (PluginInfoWrapper pluginInfoWrapper : node.getPluginManager().getPlugins()) {
      if (pluginInfoWrapper.getPluginClassName().equals(pluginname2)
          && !pluginInfoWrapper.isStopping()
          && pluginInfoWrapper.getPlugin() instanceof FredPluginFCP fcpPlugin) {
        plug = fcpPlugin;
        break;
      }
    }
    if (plug == null) {
      LOG.error("Could not find fcp plugin: {}", pluginname2);
      throw new PluginNotFoundException();
    }
    LOG.info("Found fcp plugin: {}", pluginname2);
    return new WeakReference<>(plug);
  }

  public void send(final SimpleFieldSet plugparams, final Bucket data2) {

    node.getExecutor()
        .execute(
            () -> sendSyncInternalOnly(plugparams, data2),
            "FCPPlugin talk runner for " + pluginName);
  }

  public void sendSyncInternalOnly(final SimpleFieldSet plugparams, final Bucket data2) {
    try {
      FredPluginFCP plug = pluginRef.get();
      if (plug == null) {
        // FIXME How to get this out to surrounding send(..)?
        // throw new PluginNotFoundException(How to get this out to surrounding send(..)?);
        LOG.warn("Connection to plugin '{}' lost.", pluginName);
        return;
      }
      plug.handle(replysender, plugparams, data2, access);
    } catch (VirtualMachineError vme) {
      throw vme; // OOM is included here
    } catch (Throwable t) {
      LOG.error(
          "Cought error while execute fcp plugin handler for '"
              + pluginName
              + "', report it to the plugin author: "
              + t.getMessage(),
          t);
    }
  }
}
