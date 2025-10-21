package network.crypta.config;

/**
 * Signals that a configuration change is accepted but requires a node restart to take effect.
 *
 * <p>Configuration setters such as {@link ConfigCallback#set(Object)} or {@link
 * ConfigConsumer#accept(Object)} throw this exception to indicate that the provided value has been
 * validated and recorded, but will not become active until the process restarts. When throwing this
 * exception, implementations should ensure the value is persisted so that it will be applied on the
 * next startup.
 */
public class NodeNeedRestartException extends ConfigException {
  /**
   * Creates a new exception with a human-readable reason.
   *
   * @param msg detail describing why a restart is required.
   */
  public NodeNeedRestartException(String msg) {
    super(msg);
  }
}
