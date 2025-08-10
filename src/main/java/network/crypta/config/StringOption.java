package network.crypta.config;

import network.crypta.support.api.StringCallback;

public class StringOption extends Option<String> {
	public StringOption(SubConfig conf, String optionName, String defaultValue, int sortOrder, 
			boolean expert, boolean forceWrite, String shortDesc, String longDesc, StringCallback cb) {
		super(conf, optionName, cb, sortOrder, expert, forceWrite, shortDesc, longDesc, Option.DataType.STRING);
		this.defaultValue = defaultValue;
		this.currentValue = defaultValue;
	}

	@Override
	protected String parseString(String val) throws InvalidConfigValueException {
		return val;
	}

	@Override
	protected String toString(String val) {
		return val;
	}
}
