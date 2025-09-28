package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.SimpleFieldSet;

/** can find a plugin that implements FredPluginFCP */
public class GetPluginInfo extends FCPMessage {

  static final String NAME = "GetPluginInfo";

  private final String identifier;
  private final boolean detailed;
  private final String plugname;

  public GetPluginInfo(SimpleFieldSet fs) throws MessageInvalidException {
    identifier = fs.get("Identifier");
    if (identifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "GetPluginInfo must contain an Identifier field",
          null,
          false);
    plugname = fs.get("PluginName");
    if (plugname == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "GetPluginInfo must contain a PluginName field",
          identifier,
          false);
    detailed = fs.getBoolean("Detailed", false);
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
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (detailed && !handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "GetPluginInfo detailed requires full access",
          identifier,
          false);
    }

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
      handler.send(new PluginInfoMessage(pi, identifier, detailed));
    }
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
