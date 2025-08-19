package network.crypta.config;

/**
 * Thrown when the node must be restarted for a config setting to be applied. The thrower must
 * ensure that the value reaches the config file, even though it cannot be immediately used.
 */
@SuppressWarnings("serial")
public class NodeNeedRestartException extends ConfigException {
  public NodeNeedRestartException(String msg) {
    super(msg);
  }
}
