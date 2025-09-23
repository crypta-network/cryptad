package network.crypta.clients.fcp;

import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.SimpleFieldSet;

public class ModifyConfig extends FCPMessage {

  static final String NAME = "ModifyConfig";

  final SimpleFieldSet fs;
  final String identifier;

  public ModifyConfig(SimpleFieldSet fs) {
    this.fs = fs;
    this.identifier = fs.get("Identifier");
    fs.removeValue("Identifier");
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
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ModifyConfig requires full access",
          identifier,
          false);
    }
    Config config = node.getConfig();

    boolean logMINOR = Logger.shouldLog(LogLevel.MINOR, this);

    for (SubConfig sc : config.getConfigs()) {
      String prefix = sc.getPrefix();
      for (Option<?> o : sc.getOptions()) {
        String configName = o.getName();
        if (logMINOR) Logger.minor(this, "Setting " + prefix + '.' + configName);

        // we ignore unreconized parameters
        String s = fs.get(prefix + '.' + configName);
        if (s != null) {
          if (!(o.getValueString().equals(s))) {
            if (logMINOR) Logger.minor(this, "Setting " + prefix + '.' + configName + " to " + s);
            try {
              o.setValue(s);
            } catch (Exception e) {
              // Bad values silently fail from an FCP perspective, but the FCP client can tell if a
              // change took by comparing ConfigData messages before and after
              Logger.error(this, "Caught " + e, e);
            }
          }
        }
      }
    }
    node.getClientCore().storeConfig();
    handler.send(
        new ConfigData(node, true, false, false, false, false, false, false, false, identifier));
  }
}
