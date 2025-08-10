package network.crypta.config;

/**
 * Usefull if you want to catch all exceptions the config framework can return;
 */
public abstract class ConfigException extends Exception {
	private static final long serialVersionUID = -1;
	
	public ConfigException(String msg) {
		super(msg);
	}
	public ConfigException(Throwable cause) {
		super(cause);
	}
}
