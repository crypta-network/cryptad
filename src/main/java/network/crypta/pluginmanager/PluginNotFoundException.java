package network.crypta.pluginmanager;

public class PluginNotFoundException extends Exception {
	private static final long serialVersionUID = -1;

	public PluginNotFoundException() {
		super();
	}

	public PluginNotFoundException(String arg0) {
		super(arg0);
	}

	public PluginNotFoundException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

	public PluginNotFoundException(Throwable arg0) {
		super(arg0);
	}

}
