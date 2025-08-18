package network.crypta.pluginmanager;

import java.io.Serial;

public class PluginTooOldException extends PluginNotFoundException {

	@Serial final private static long serialVersionUID = -3104024342634046289L;

	public PluginTooOldException(String string) {
		super(string);
	}

}
