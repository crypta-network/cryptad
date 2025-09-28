package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.SimpleFieldSet;

/** remove a plugin */
public class RemovePlugin extends FCPMessage {

  static final String NAME = "RemovePlugin";

  private final String identifier;
  private final String plugname;
  private final int maxWaitTime;
  private final boolean purge;

  public RemovePlugin(SimpleFieldSet fs) throws MessageInvalidException {
    identifier = fs.get("Identifier");
    if (identifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must contain an Identifier field", null, false);
    plugname = fs.get("PluginName");
    if (plugname == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must contain a PluginName field", identifier, false);
    maxWaitTime = fs.getInt("MaxWaitTime", 0);
    purge = fs.getBoolean("Purge", false);
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public void run(final FCPConnectionHandler handler, final Node node)
      throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED, "LoadPlugin requires full access", identifier, false);
    }

    node.getExecutor()
        .execute(
            () -> {
              PluginInfoWrapper pi = findPluginInfo(node);
              if (pi == null) {
                handler.send(
                    new ProtocolErrorMessage(
                        ProtocolErrorMessage.NO_SUCH_PLUGIN,
                        false,
                        "Plugin '" + plugname + "' does not exist or is not a FCP plugin",
                        identifier,
                        false));
              } else {
                pi.stopPlugin(node.getPluginManager(), maxWaitTime, false);
                if (purge) {
                  node.getPluginManager().removeCachedCopy(pi.getFilename());
                }
                handler.send(new PluginRemovedMessage(plugname, identifier));
              }
            },
            "Remove Plugin");
  }

  private PluginInfoWrapper findPluginInfo(Node node) {
    PluginManager manager = node.getPluginManager();
    for (PluginInfoWrapper info : manager.getPlugins()) {
      if (plugname.equals(info.getPluginClassName())) {
        return info;
      }
      String filename = info.getFilename();
      if (filename != null) {
        String basename = new File(filename).getName();
        if (plugname.equals(basename)) {
          return info;
        }
        if (basename.endsWith(".jar")) {
          String withoutExt = basename.substring(0, basename.length() - 4);
          if (plugname.equals(withoutExt)) {
            return info;
          }
        }
      }
    }
    return null;
  }
}
